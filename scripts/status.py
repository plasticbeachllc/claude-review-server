#!/usr/bin/env python3
"""Check the status of a provisioned PR review server.

Reports server status from Hetzner and optionally checks the service health
via SSH.

Usage:
    python3 scripts/status.py
    just status
"""

import sys
from pathlib import Path

from hcloud import Client

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _common import ProvisionError, load_config, ssh  # noqa: E402


def main():
    root = Path(__file__).resolve().parent.parent

    try:
        config = load_config(root)
    except ProvisionError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)

    name = config["SERVER_NAME"]
    client = Client(token=config["HCLOUD_TOKEN"])
    server = client.servers.get_by_name(name)

    if not server:
        print(f"Server '{name}' not found on Hetzner (not provisioned).")
        return

    ip = server.public_net.ipv4.ip
    print(f"Server:   {name} (id={server.id})")
    print(f"Status:   {server.status}")
    print(f"IP:       {ip}")
    print(f"Type:     {server.server_type.name}")
    print(f"Location: {server.datacenter.name}")
    print(f"Created:  {server.created.isoformat()}")

    if server.status != "running":
        return

    # Check service health via SSH
    print()
    try:
        svc = ssh(ip, "systemctl is-active pr-review 2>/dev/null || echo inactive", timeout=10)
        print(f"Service:  {svc}")
    except Exception:
        print("Service:  (SSH unreachable)")
        return

    try:
        health = ssh(ip, "curl -sf localhost:8081/health 2>/dev/null || echo 'unreachable'", timeout=10)
        print(f"Health:   {health}")
    except Exception:
        print("Health:   (check failed)")

    hostname = config.get("TUNNEL_HOSTNAME", "")
    if hostname:
        print(f"Webhook:  https://{hostname}/webhook")
    print(f"SSH:      ssh root@{ip}")
    print(f"Logs:     ssh root@{ip} journalctl -u pr-review -f")


if __name__ == "__main__":
    main()
