"""Shared utilities for provisioning scripts."""

import json
import subprocess
import time
from pathlib import Path

import requests

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
CF_API = "https://api.cloudflare.com/client/v4"
GH_API = "https://api.github.com"

REQUIRED_KEYS = [
    "HCLOUD_TOKEN",
    "GH_TOKEN",
    "CLAUDE_CODE_AUTH_TOKEN",
    "CF_API_TOKEN",
    "CF_ACCOUNT_ID",
    "CF_ZONE_ID",
    "TUNNEL_HOSTNAME",
    "GITHUB_ORG",
]
DEFAULTS = {
    "SERVER_NAME": "pr-review",
    "SERVER_TYPE": "cx11",
    "SERVER_LOCATION": "fsn1",
    "SERVER_IMAGE": "ubuntu-24.04",
}

# SSH options for connecting to provisioned servers.
# StrictHostKeyChecking=accept-new trusts the key on first connection and
# rejects if it changes later.  The Hetzner API does not expose server host
# keys, so there is no way to pre-seed known_hosts.  Since we connect to a
# server we just created, the MITM window is minimal and this is standard
# practice for cloud provisioning.
SSH_OPTS = [
    "-o", "StrictHostKeyChecking=accept-new",
    "-o", "ConnectTimeout=10",
    "-o", "BatchMode=yes",
]


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------
class ProvisionError(Exception):
    """Raised when a provisioning step fails."""


class CloudInitError(ProvisionError):
    """Raised specifically when cloud-init reports an error status."""


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
def load_config(root: Path) -> dict:
    """Load .env file and validate required keys."""
    env_path = root / ".env"
    if not env_path.exists():
        raise ProvisionError(f".env not found at {env_path} — cp .env.example .env")

    config = {}
    for line in env_path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        value = value.strip()
        # Strip surrounding quotes (single or double) — common .env convention
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ('"', "'"):
            value = value[1:-1]
        config[key.strip()] = value

    # Apply defaults
    for key, default in DEFAULTS.items():
        config.setdefault(key, default)

    # Validate
    missing = [k for k in REQUIRED_KEYS if not config.get(k)]
    if missing:
        raise ProvisionError(f"Missing required .env keys: {', '.join(missing)}")

    return config


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
                raise CloudInitError(f"cloud-init failed: {detail}")
        except CloudInitError:
            raise  # cloud-init errors must propagate immediately
        except (ProvisionError, subprocess.TimeoutExpired, json.JSONDecodeError):
            pass  # transient SSH failures or parse errors — keep polling
        print(".", end="", flush=True)
        time.sleep(10)
    raise ProvisionError(f"cloud-init did not finish within {timeout}s")


# ---------------------------------------------------------------------------
# Cloudflare API helper
# ---------------------------------------------------------------------------
def cf_request(method: str, path: str, token: str, **kwargs) -> dict:
    """Make an authenticated Cloudflare API request."""
    resp = requests.request(
        method, f"{CF_API}{path}",
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        timeout=30, **kwargs,
    )
    data = resp.json()
    if not data.get("success"):
        errors = data.get("errors", [])
        raise ProvisionError(f"Cloudflare API error: {errors}")
    return data
