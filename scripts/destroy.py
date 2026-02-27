#!/usr/bin/env python3
"""Destroy a provisioned PR review server and clean up associated resources.

Removes (in reverse order): DNS record, Cloudflare Tunnel, Hetzner server.
The GitHub App and its webhook are preserved so ``just provision`` can be
re-run without ``just create-app``.  Each step is best-effort — failures
are warned but don't block cleanup of remaining resources.

Usage:
    python3 scripts/destroy.py
    just destroy
"""

import sys
from pathlib import Path

from hcloud import Client

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _common import ProvisionError, cf_request, load_config  # noqa: E402


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
    """Delete the Hetzner server by name.

    Waits for the Hetzner API to confirm deletion is complete before
    returning, so callers aren't surprised by a still-running server.
    """
    client = Client(token=config["HCLOUD_TOKEN"])
    name = config["SERVER_NAME"]
    server = client.servers.get_by_name(name)
    if not server:
        print("  No matching server found (already deleted?)")
        return

    response = client.servers.delete(server)
    if response is not None:
        # hcloud-python returns a BoundAction; wait for it to finish
        response.wait_until_finished()
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
