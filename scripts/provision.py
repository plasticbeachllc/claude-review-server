#!/usr/bin/env python3
"""Provision a Hetzner server with the PR review agent — fully automated.

Reads configuration from .env, creates a server via the Hetzner API,
waits for cloud-init, injects auth tokens, sets up a Cloudflare Tunnel,
creates a GitHub org webhook, and starts the service.

Usage:
    python3 scripts/provision.py          # provision from .env
    just provision                        # same via Justfile
"""

import base64
import secrets
import subprocess
import sys
import time
from pathlib import Path

import requests
from hcloud import APIException, Client
from hcloud.images import Image
from hcloud.locations import Location
from hcloud.server_types import ServerType
from hcloud.ssh_keys import SSHKey

# ---------------------------------------------------------------------------
# Reuse the existing build system and shared utilities
# ---------------------------------------------------------------------------
sys.path.insert(0, str(Path(__file__).resolve().parent))
from _common import (  # noqa: E402
    CF_API,
    GH_API,
    SSH_OPTS,
    ProvisionError,
    cf_request,
    gh_paginate,
    load_config,
    ssh,
    wait_for_cloud_init,
    wait_for_ssh,
)
from build import BuildError, build  # noqa: E402
from destroy import (  # noqa: E402
    delete_dns_record,
    delete_server,
    delete_tunnel,
    delete_webhook,
)


# ---------------------------------------------------------------------------
# SSH key management
# ---------------------------------------------------------------------------
def find_local_pubkey() -> str:
    """Find the user's SSH public key. Returns the public key content."""
    candidates = [
        Path.home() / ".ssh" / "id_ed25519.pub",
        Path.home() / ".ssh" / "id_ecdsa.pub",
        Path.home() / ".ssh" / "id_rsa.pub",
    ]
    for path in candidates:
        if path.exists():
            return path.read_text().strip()
    raise ProvisionError(
        "No SSH public key found. Expected ~/.ssh/id_ed25519.pub, "
        "~/.ssh/id_ecdsa.pub, or ~/.ssh/id_rsa.pub"
    )


def ensure_ssh_key(client: Client, pubkey_content: str, name: str = "pr-review") -> SSHKey:
    """Find or create the SSH key on Hetzner (matched by fingerprint)."""
    try:
        key = client.ssh_keys.create(name=name, public_key=pubkey_content)
        print(f"  Created SSH key '{name}' on Hetzner")
        return key
    except APIException as e:
        if e.code == "uniqueness_error":
            for key in client.ssh_keys.get_all():
                if key.public_key.strip() == pubkey_content.strip():
                    print(f"  Reusing SSH key '{key.name}' on Hetzner")
                    return key
            # Name collision with a different key
            raise ProvisionError(
                f"SSH key named '{name}' already exists on Hetzner but doesn't match "
                f"your local public key. Delete it in the Hetzner console or use a "
                f"different SERVER_NAME."
            ) from e
        raise ProvisionError(f"Failed to create/find SSH key: {e}") from e


# ---------------------------------------------------------------------------
# Hetzner server
# ---------------------------------------------------------------------------
def create_server(client: Client, config: dict, ssh_key: SSHKey, cloud_init: str):
    """Create a Hetzner server with cloud-init user data."""
    name = config["SERVER_NAME"]

    # Fail-fast if server already exists
    existing = client.servers.get_by_name(name)
    if existing:
        raise ProvisionError(
            f"Server '{name}' already exists (id={existing.id}, ip={existing.public_net.ipv4.ip}). "
            f"Run `just destroy` first."
        )

    print(f"  Creating server '{name}' ({config['SERVER_TYPE']} in {config['SERVER_LOCATION']})...")
    response = client.servers.create(
        name=name,
        server_type=ServerType(name=config["SERVER_TYPE"]),
        image=Image(name=config["SERVER_IMAGE"]),
        location=Location(name=config["SERVER_LOCATION"]),
        ssh_keys=[ssh_key],
        user_data=cloud_init,
    )
    server = response.server
    print(f"  Server created: id={server.id}")

    # Wait for Hetzner to report it as running
    print("  Waiting for server status 'running'...", end="", flush=True)
    for _ in range(60):
        server = client.servers.get_by_id(server.id)
        if server.status == "running":
            print(" ok")
            return server
        print(".", end="", flush=True)
        time.sleep(5)
    raise ProvisionError("Server did not reach 'running' status in time")


# ---------------------------------------------------------------------------
# Auth injection
# ---------------------------------------------------------------------------
def inject_auth(ip: str, config: dict):
    """Inject GitHub and Claude auth tokens into the server.

    Uses upsert logic so re-running is safe (no duplicate tokens).
    """
    # Preflight: verify gh CLI is installed (cloud-init may not have finished)
    try:
        ssh(ip, "command -v gh", timeout=10, label="check gh installed")
    except ProvisionError:
        raise ProvisionError(
            f"GitHub CLI (gh) not found on server. "
            f"Check cloud-init logs: ssh root@{ip} cloud-init status --long"
        )

    # GitHub CLI auth — pipe token via stdin to avoid exposing it in process args
    print("  Authenticating GitHub CLI...")
    result = subprocess.run(
        ["ssh", *SSH_OPTS, f"root@{ip}",
         "sudo -u review gh auth login --with-token"],
        input=config["GH_TOKEN"], capture_output=True, text=True, timeout=30,
    )
    if result.returncode != 0:
        raise ProvisionError(
            f"GitHub CLI auth failed (rc={result.returncode})\n"
            f"stderr: {result.stderr.strip()}"
        )

    # Claude Code auth — upsert token in the service env file.
    # Token is read via stdin into a shell variable so it never appears in
    # process args (/proc/*/cmdline).  sed and echo run inside the same SSH
    # shell session on a single-tenant server.
    print("  Injecting Claude Code auth token...")
    result = subprocess.run(
        ["ssh", *SSH_OPTS, f"root@{ip}",
         "TOKEN=$(cat) && "
         "if grep -q '^CLAUDE_CODE_AUTH_TOKEN=' /opt/pr-review/.env; then "
         "  sed -i \"s|^CLAUDE_CODE_AUTH_TOKEN=.*|CLAUDE_CODE_AUTH_TOKEN=${TOKEN}|\" /opt/pr-review/.env; "
         "else "
         "  echo \"CLAUDE_CODE_AUTH_TOKEN=${TOKEN}\" >> /opt/pr-review/.env; "
         "fi"],
        input=config["CLAUDE_CODE_AUTH_TOKEN"],
        capture_output=True, text=True, timeout=30,
    )
    if result.returncode != 0:
        raise ProvisionError(
            f"Claude Code auth injection failed (rc={result.returncode})\n"
            f"stderr: {result.stderr.strip()}"
        )


# ---------------------------------------------------------------------------
# Cloudflare Tunnel
# ---------------------------------------------------------------------------
def setup_tunnel(config: dict, server_ip: str, created: dict | None = None) -> str:
    """Create a Cloudflare Tunnel, configure DNS, and install on the server.

    If a tunnel with the same name already exists, reuses it instead of
    creating a duplicate.  ``created`` is updated progressively so that
    ``_auto_cleanup`` can clean up resources even if this function fails
    mid-way (e.g. after DNS creation but before cloudflared install).
    """
    if created is None:
        created = {}
    token = config["CF_API_TOKEN"]
    account = config["CF_ACCOUNT_ID"]
    zone = config["CF_ZONE_ID"]
    hostname = config["TUNNEL_HOSTNAME"]
    tunnel_name = config.get("SERVER_NAME", "pr-review")

    # 1. Create tunnel (or reuse existing)
    existing = cf_request(
        "GET", f"/accounts/{account}/cfd_tunnel",
        token, params={"name": tunnel_name, "is_deleted": "false"},
    )
    existing_tunnels = existing.get("result", [])
    if existing_tunnels:
        tunnel_id = existing_tunnels[0]["id"]
        print(f"  Reusing existing Cloudflare Tunnel '{tunnel_name}' ({tunnel_id})")
    else:
        print(f"  Creating Cloudflare Tunnel '{tunnel_name}'...")
        tunnel_secret = base64.b64encode(secrets.token_bytes(32)).decode()
        data = cf_request(
            "POST", f"/accounts/{account}/cfd_tunnel",
            token, json={"name": tunnel_name, "tunnel_secret": tunnel_secret},
        )
        tunnel_id = data["result"]["id"]
        print(f"  Tunnel created: {tunnel_id}")
    created["tunnel"] = tunnel_name

    # 2. Configure ingress
    print("  Configuring tunnel ingress...")
    cf_request(
        "PUT", f"/accounts/{account}/cfd_tunnel/{tunnel_id}/configurations",
        token, json={
            "config": {
                "ingress": [
                    {"hostname": hostname, "service": "http://localhost:80"},
                    {"service": "http_status:404"},
                ],
            },
        },
    )

    # 3. Create DNS CNAME (skip if it already exists)
    print(f"  Creating DNS record {hostname} -> tunnel...")
    existing_dns = cf_request(
        "GET", f"/zones/{zone}/dns_records",
        token, params={"name": hostname, "type": "CNAME"},
    )
    if existing_dns.get("result"):
        record = existing_dns["result"][0]
        print(f"  DNS record already exists (id={record['id']}), updating...")
        cf_request(
            "PUT", f"/zones/{zone}/dns_records/{record['id']}",
            token, json={
                "type": "CNAME",
                "name": hostname,
                "content": f"{tunnel_id}.cfargotunnel.com",
                "proxied": True,
            },
        )
    else:
        cf_request(
            "POST", f"/zones/{zone}/dns_records",
            token, json={
                "type": "CNAME",
                "name": hostname,
                "content": f"{tunnel_id}.cfargotunnel.com",
                "proxied": True,
            },
        )
    created["dns"] = hostname

    # 4. Get connector token
    print("  Getting tunnel connector token...")
    data = cf_request("GET", f"/accounts/{account}/cfd_tunnel/{tunnel_id}/token", token)
    connector_token = data["result"]

    # 5. Install and start cloudflared on the server.
    # Uninstall first so re-provisioning doesn't fail on "already installed".
    # Read token into a shell variable via stdin so it never appears in
    # process args (/proc/*/cmdline).  The variable is only visible to
    # the shell process itself.
    print("  Installing cloudflared tunnel on server...")
    result = subprocess.run(
        ["ssh", *SSH_OPTS, f"root@{server_ip}",
         "cloudflared service uninstall 2>/dev/null || true;"
         " TUNNEL_TOKEN=$(cat) && cloudflared service install \"$TUNNEL_TOKEN\""],
        input=connector_token, capture_output=True, text=True, timeout=60,
    )
    if result.returncode != 0:
        raise ProvisionError(
            f"cloudflared install failed (rc={result.returncode})\n"
            f"stderr: {result.stderr.strip()}"
        )

    return hostname


# ---------------------------------------------------------------------------
# GitHub webhook
# ---------------------------------------------------------------------------
def read_webhook_secret(ip: str) -> str:
    """Read the auto-generated GITHUB_WEBHOOK_SECRET from the server.

    The secret is generated by cloud-init (``openssl rand -hex 32``) and
    stored bare in ``.env`` — no inline comments or quoting — so the
    simple ``grep | cut`` approach is reliable here.
    """
    raw = ssh(ip, "grep ^GITHUB_WEBHOOK_SECRET /opt/pr-review/.env | cut -d= -f2-",
              label="read GITHUB_WEBHOOK_SECRET")
    if not raw:
        raise ProvisionError("Could not read GITHUB_WEBHOOK_SECRET from server")
    return raw


def create_webhook(config: dict, webhook_secret: str, tunnel_hostname: str):
    """Create a GitHub org-level webhook.

    If a webhook with the same URL already exists, skips creation.
    """
    org = config["GITHUB_ORG"]
    url = f"https://{tunnel_hostname}/webhook"
    headers = {
        "Authorization": f"Bearer {config['GH_TOKEN']}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }

    # List all webhooks (follows pagination automatically).
    hooks = gh_paginate(
        f"{GH_API}/orgs/{org}/hooks",
        headers=headers, params={"per_page": 100},
    )
    for hook in hooks:
        if hook.get("config", {}).get("url") == url:
            print(f"  Webhook already exists (id={hook['id']}), skipping creation")
            return

    print(f"  Creating GitHub webhook for {org} -> {url}")
    resp = requests.post(
        f"{GH_API}/orgs/{org}/hooks",
        headers=headers,
        json={
            "name": "web",
            "config": {
                "url": url,
                "content_type": "json",
                "secret": webhook_secret,
            },
            "events": ["pull_request"],
            "active": True,
        },
        timeout=30,
    )
    if resp.status_code not in (201, 200):
        raise ProvisionError(
            f"GitHub webhook creation failed ({resp.status_code}): {resp.text}"
        )
    hook_id = resp.json().get("id")
    print(f"  Webhook created: id={hook_id}")


def _auto_cleanup(created: dict, config: dict):
    """Best-effort cleanup of partially created resources on failure."""
    if not created:
        return
    print("\nCleaning up partially created resources...", file=sys.stderr)

    # Reverse order: webhook -> DNS -> tunnel -> server
    cleanup_steps = []
    if "webhook" in created:
        cleanup_steps.append(("webhook", delete_webhook))
    if "dns" in created:
        cleanup_steps.append(("DNS record", delete_dns_record))
    if "tunnel" in created:
        cleanup_steps.append(("tunnel", delete_tunnel))
    if "server" in created:
        cleanup_steps.append(("server", delete_server))

    for label, fn in cleanup_steps:
        try:
            fn(config)
            print(f"  Cleaned up {label}", file=sys.stderr)
        except Exception as e:
            print(f"  Warning: failed to clean up {label}: {e}", file=sys.stderr)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    root = Path(__file__).resolve().parent.parent
    created = {}  # Track created resources for error reporting
    config = {}   # Initialized before try so _auto_cleanup always has a valid ref

    try:
        # 1. Config
        print("[1/8] Loading configuration...")
        config = load_config(root)

        # 2. Build cloud-init
        print("[2/8] Building cloud-init.yaml...")
        cloud_init = build(root)

        # 3. SSH key
        print("[3/8] Setting up SSH key...")
        pubkey = find_local_pubkey()
        client = Client(token=config["HCLOUD_TOKEN"])
        ssh_key = ensure_ssh_key(client, pubkey, name=config["SERVER_NAME"])

        # 4. Create server
        print("[4/8] Creating Hetzner server...")
        server = create_server(client, config, ssh_key, cloud_init)
        ip = server.public_net.ipv4.ip
        created["server"] = config["SERVER_NAME"]
        print(f"  Server IP: {ip}")

        # 5. Wait for boot
        print("[5/8] Waiting for server to be ready...")
        wait_for_ssh(ip)
        wait_for_cloud_init(ip)

        # 6. Inject auth
        print("[6/8] Injecting auth tokens...")
        inject_auth(ip, config)

        # 7. Cloudflare Tunnel (setup_tunnel updates `created` progressively)
        print("[7/8] Setting up Cloudflare Tunnel...")
        hostname = setup_tunnel(config, ip, created=created)

        # 8. GitHub webhook + start service
        print("[8/8] Creating webhook and starting service...")
        webhook_secret = read_webhook_secret(ip)
        create_webhook(config, webhook_secret, hostname)
        created["webhook"] = hostname
        ssh(ip, "systemctl restart pr-review")

        # Verify the service actually started (retry to allow systemd to settle)
        print("  Verifying service started...", end="", flush=True)
        svc_status = "unknown"
        for _ in range(6):
            time.sleep(2)
            svc_status = ssh(
                ip, "systemctl is-active pr-review 2>/dev/null || echo inactive",
                timeout=10,
            )
            if svc_status == "active":
                break
            print(".", end="", flush=True)
        if svc_status != "active":
            print()
            raise ProvisionError(
                f"Service pr-review is '{svc_status}' after restart. "
                f"Check logs: ssh root@{ip} journalctl -u pr-review --no-pager -n 50"
            )
        print(" ok")

        # Summary
        print()
        print("=" * 60)
        print("  PROVISIONING COMPLETE")
        print()
        print(f"  Server:   {config['SERVER_NAME']} ({ip})")
        print(f"  Webhook:  https://{hostname}/webhook")
        print(f"  SSH:      ssh root@{ip}")
        print(f"  Logs:     ssh root@{ip} journalctl -u pr-review -f")
        print(f"  Health:   ssh root@{ip} curl -s localhost:8081/health")
        print("=" * 60)

    except (ProvisionError, BuildError, APIException) as e:
        print(f"\nERROR: {e}", file=sys.stderr)
        _auto_cleanup(created, config)
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nInterrupted.")
        _auto_cleanup(created, config)
        sys.exit(1)


if __name__ == "__main__":
    main()
