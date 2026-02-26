#!/usr/bin/env python3
"""Destroy a provisioned PR review server and clean up associated resources.

Removes (in reverse order): GitHub webhook, DNS record, Cloudflare Tunnel,
Hetzner server. Each step is best-effort — failures are warned but don't
block cleanup of remaining resources.

Usage:
    python3 scripts/destroy.py
    just destroy
"""

import sys
from pathlib import Path

import requests
from hcloud import Client

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _common import GH_API, ProvisionError, cf_request, gh_paginate, load_config  # noqa: E402


def delete_webhook(config: dict):
    """Find and delete the GitHub org webhook matching our tunnel hostname."""
    org = config["GITHUB_ORG"]
    hostname = config["TUNNEL_HOSTNAME"]
    target_url = f"https://{hostname}/webhook"
    headers = {
        "Authorization": f"Bearer {config['GH_TOKEN']}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }

    # List all hooks (follows pagination automatically)
    hooks = gh_paginate(
        f"{GH_API}/orgs/{org}/hooks",
        headers=headers, params={"per_page": 100},
    )

    for hook in hooks:
        hook_url = hook.get("config", {}).get("url", "")
        if hook_url == target_url:
            del_resp = requests.delete(
                f"{GH_API}/orgs/{org}/hooks/{hook['id']}",
                headers=headers, timeout=30,
            )
            if del_resp.status_code == 204:
                print(f"  Deleted webhook {hook['id']}")
            else:
                print(f"  Warning: webhook delete returned {del_resp.status_code}")
            return

    print("  No matching webhook found (already deleted?)")


def delete_dns_record(config: dict):
    """Find and delete the CNAME record for our tunnel hostname."""
    token = config["CF_API_TOKEN"]
    zone = config["CF_ZONE_ID"]
    hostname = config["TUNNEL_HOSTNAME"]

    # List DNS records matching our hostname
    data = cf_request(
        "GET", f"/zones/{zone}/dns_records",
        token, params={"name": hostname, "type": "CNAME"},
    )
    records = data.get("result", [])
    if not records:
        print("  No matching DNS record found (already deleted?)")
        return

    if len(records) > 1:
        print(f"  Warning: found {len(records)} CNAME records for {hostname}, deleting all")
    for record in records:
        cf_request("DELETE", f"/zones/{zone}/dns_records/{record['id']}", token)
        print(f"  Deleted DNS record {record['id']} ({hostname})")


def delete_tunnel(config: dict):
    """Find and delete the Cloudflare Tunnel by name."""
    token = config["CF_API_TOKEN"]
    account = config["CF_ACCOUNT_ID"]
    tunnel_name = config.get("SERVER_NAME", "pr-review")

    # List tunnels and find ours
    data = cf_request(
        "GET", f"/accounts/{account}/cfd_tunnel",
        token, params={"name": tunnel_name, "is_deleted": "false"},
    )
    tunnels = data.get("result", [])
    if not tunnels:
        print("  No matching tunnel found (already deleted?)")
        return

    for tunnel in tunnels:
        # cascade=true cleans up active connections before deleting
        cf_request(
            "DELETE", f"/accounts/{account}/cfd_tunnel/{tunnel['id']}",
            token, params={"cascade": "true"},
        )
        print(f"  Deleted tunnel {tunnel['id']} ({tunnel_name})")


def delete_server(config: dict):
    """Delete the Hetzner server by name."""
    client = Client(token=config["HCLOUD_TOKEN"])
    name = config["SERVER_NAME"]
    server = client.servers.get_by_name(name)
    if not server:
        print("  No matching server found (already deleted?)")
        return

    client.servers.delete(server)
    print(f"  Deleted server '{name}' (id={server.id})")


def main():
    root = Path(__file__).resolve().parent.parent
    errors = []

    # Accept --yes flag to skip interactive confirmation (used by `just destroy`)
    skip_confirm = "--yes" in sys.argv

    try:
        config = load_config(root)
    except ProvisionError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)

    name = config.get("SERVER_NAME", "pr-review")

    if not skip_confirm:
        print(f"This will delete server '{name}' and all associated resources.")
        try:
            answer = input("Type 'yes' to confirm: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nAborted.")
            sys.exit(1)
        if answer != "yes":
            print("Aborted.")
            sys.exit(1)

    print(f"Destroying '{name}' and associated resources...\n")

    steps = [
        ("GitHub webhook", delete_webhook),
        ("DNS record", delete_dns_record),
        ("Cloudflare Tunnel", delete_tunnel),
        ("Hetzner server", delete_server),
    ]

    for label, fn in steps:
        print(f"[{label}]")
        try:
            fn(config)
        except Exception as e:
            print(f"  Warning: {e}")
            errors.append((label, str(e)))

    print()
    if errors:
        print("Completed with errors — the following may need manual cleanup:")
        for label, detail in errors:
            print(f"  • {label}: {detail}")
        print(f"\nHint: check the Hetzner console, Cloudflare dashboard, and GitHub org settings.")
        sys.exit(1)
    else:
        print("All resources destroyed.")


if __name__ == "__main__":
    main()
