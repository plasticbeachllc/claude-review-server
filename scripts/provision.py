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
import json
import secrets
import shlex
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
# Reuse the existing build system
# ---------------------------------------------------------------------------
sys.path.insert(0, str(Path(__file__).resolve().parent))
from _common import CF_API, GH_API, ProvisionError, cf_request, load_config  # noqa: E402
from build import BuildError, build  # noqa: E402

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
SSH_OPTS = [
    "-o", "StrictHostKeyChecking=accept-new",
    "-o", "ConnectTimeout=10",
    "-o", "BatchMode=yes",
]


# ---------------------------------------------------------------------------
# SSH helpers
# ---------------------------------------------------------------------------
def ssh(ip: str, cmd: str, timeout: int = 120, *, label: str = "") -> str:
    """Run a command on the server via SSH. Returns stdout.

    Use ``label`` to replace the raw command in error messages (avoids
    leaking tokens when a sensitive command fails).
    """
    result = subprocess.run(
        ["ssh", *SSH_OPTS, f"root@{ip}", cmd],
        capture_output=True, text=True, timeout=timeout,
    )
    if result.returncode != 0:
        display = label or cmd
        raise ProvisionError(
            f"SSH command failed (rc={result.returncode}): {display}\n"
            f"stderr: {result.stderr.strip()}"
        )
    return result.stdout.strip()


def wait_for_ssh(ip: str, timeout: int = 300):
    """Poll until SSH is reachable."""
    print(f"  Waiting for SSH on {ip}...", end="", flush=True)
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            ssh(ip, "echo ready", timeout=10)
            print(" ok")
            return
        except (ProvisionError, subprocess.TimeoutExpired):
            print(".", end="", flush=True)
            time.sleep(5)
    raise ProvisionError(f"SSH not reachable after {timeout}s")


def wait_for_cloud_init(ip: str, timeout: int = 600):
    """Wait for cloud-init to finish on the server."""
    print("  Waiting for cloud-init to finish...", end="", flush=True)
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            out = ssh(ip, "cloud-init status --format json 2>/dev/null || echo '{}'", timeout=30)
            data = json.loads(out) if out else {}
            status = data.get("status", "")
            if status == "done":
                print(" done")
                return
            if status == "error":
                detail = data.get("detail", "unknown")
                raise ProvisionError(f"cloud-init failed: {detail}")
        except ProvisionError:
            raise  # cloud-init failures must propagate immediately
        except (subprocess.TimeoutExpired, json.JSONDecodeError):
            pass
        print(".", end="", flush=True)
        time.sleep(10)
    raise ProvisionError(f"cloud-init did not finish within {timeout}s")


# ---------------------------------------------------------------------------
# SSH key management
# ---------------------------------------------------------------------------
def find_local_pubkey() -> tuple[str, str]:
    """Find the user's SSH public key. Returns (name, public_key_content)."""
    candidates = [
        Path.home() / ".ssh" / "id_ed25519.pub",
        Path.home() / ".ssh" / "id_rsa.pub",
    ]
    for path in candidates:
        if path.exists():
            content = path.read_text().strip()
            return (path.stem, content)
    raise ProvisionError(
        "No SSH public key found. Expected ~/.ssh/id_ed25519.pub or ~/.ssh/id_rsa.pub"
    )


def ensure_ssh_key(client: Client, pubkey_content: str) -> SSHKey:
    """Find or create the SSH key on Hetzner (matched by fingerprint)."""
    name = "pr-review"
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
        image=Image(name="ubuntu-24.04"),
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
    """Inject GitHub and Claude auth tokens into the server."""
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

    # Claude Code auth — append token to the service env file
    print("  Injecting Claude Code auth token...")
    claude_env_line = shlex.quote("CLAUDE_CODE_AUTH_TOKEN=" + config["CLAUDE_CODE_AUTH_TOKEN"])
    ssh(ip, f"printf '%s\\n' {claude_env_line} >> /opt/pr-review/.env",
        label="append CLAUDE_CODE_AUTH_TOKEN to /opt/pr-review/.env")


# ---------------------------------------------------------------------------
# Cloudflare Tunnel
# ---------------------------------------------------------------------------
def setup_tunnel(config: dict, server_ip: str) -> str:
    """Create a Cloudflare Tunnel, configure DNS, and install on the server.

    If a tunnel with the same name already exists, reuses it instead of
    creating a duplicate.
    """
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

    # 4. Get connector token
    print("  Getting tunnel connector token...")
    data = cf_request("GET", f"/accounts/{account}/cfd_tunnel/{tunnel_id}/token", token)
    connector_token = data["result"]

    # 5. Install and start cloudflared on the server
    print("  Installing cloudflared tunnel on server...")
    ssh(server_ip, f"cloudflared service install {shlex.quote(connector_token)}",
        timeout=60, label="cloudflared service install <TOKEN>")

    return hostname


# ---------------------------------------------------------------------------
# GitHub webhook
# ---------------------------------------------------------------------------
def read_webhook_secret(ip: str) -> str:
    """Read the auto-generated GITHUB_WEBHOOK_SECRET from the server."""
    raw = ssh(ip, "grep ^GITHUB_WEBHOOK_SECRET /opt/pr-review/.env | cut -d= -f2-")
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

    # Check for existing webhook with the same URL
    resp = requests.get(
        f"{GH_API}/orgs/{org}/hooks",
        headers=headers, params={"per_page": 100}, timeout=30,
    )
    if resp.status_code == 200:
        for hook in resp.json():
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


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    root = Path(__file__).resolve().parent.parent
    created = {}  # Track created resources for error reporting

    try:
        # 1. Config
        print("[1/8] Loading configuration...")
        config = load_config(root)

        # 2. Build cloud-init
        print("[2/8] Building cloud-init.yaml...")
        cloud_init = build(root)

        # 3. SSH key
        print("[3/8] Setting up SSH key...")
        _, pubkey = find_local_pubkey()
        client = Client(token=config["HCLOUD_TOKEN"])
        ssh_key = ensure_ssh_key(client, pubkey)

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

        # 7. Cloudflare Tunnel
        print("[7/8] Setting up Cloudflare Tunnel...")
        hostname = setup_tunnel(config, ip)
        created["tunnel"] = hostname

        # 8. GitHub webhook + start service
        print("[8/8] Creating webhook and starting service...")
        webhook_secret = read_webhook_secret(ip)
        create_webhook(config, webhook_secret, hostname)
        created["webhook"] = hostname
        ssh(ip, "systemctl start pr-review")

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

    except (ProvisionError, BuildError) as e:
        print(f"\nERROR: {e}", file=sys.stderr)
        if created:
            print("\nPartially created resources:", file=sys.stderr)
            for kind, name in created.items():
                print(f"  {kind}: {name}", file=sys.stderr)
            print("Run `just destroy` to clean up.", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nInterrupted.")
        if created:
            print(f"Partial resources created: {created}", file=sys.stderr)
            print("Run `just destroy` to clean up.", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
