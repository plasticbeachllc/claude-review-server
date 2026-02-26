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
#
# StrictHostKeyChecking=no accepts any host key without prompting.  Combined
# with UserKnownHostsFile=/dev/null (so every connection looks "new" and no
# stale keys accumulate), this avoids host key conflicts on destroy-then-
# reprovision cycles where Hetzner may reuse IPs with new host keys.
#
# This is appropriate for single-tenant ephemeral infrastructure managed by
# these scripts.  The Hetzner API does not expose server host keys, so there
# is no way to pre-seed known_hosts; since we connect to a server we just
# created, the MITM window is minimal and this is standard practice for
# cloud provisioning.
SSH_OPTS = [
    "-o", "StrictHostKeyChecking=no",
    "-o", "UserKnownHostsFile=/dev/null",
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
        else:
            # Strip inline comments for unquoted values (e.g. KEY=value # comment).
            # Only " #" is treated as a comment start — bare "#" inside values
            # is preserved (handles e.g. URLs with fragments).
            comment_idx = value.find(" #")
            if comment_idx != -1:
                value = value[:comment_idx].rstrip()
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
                detail = data.get("extended_status", data.get("status", "unknown"))
                # Fetch verbose output for debugging
                try:
                    long_out = ssh(ip, "cloud-init status --long 2>/dev/null || true", timeout=10)
                except Exception:
                    long_out = ""
                msg = f"cloud-init failed: {detail}"
                if long_out:
                    msg += f"\n{long_out}"
                raise CloudInitError(msg)
        except CloudInitError:
            raise  # cloud-init errors must propagate immediately
        except (ProvisionError, subprocess.TimeoutExpired, json.JSONDecodeError):
            pass  # transient SSH failures or parse errors — keep polling
        print(".", end="", flush=True)
        remaining = deadline - time.time()
        if remaining <= 0:
            break
        time.sleep(min(10, remaining))
    raise ProvisionError(f"cloud-init did not finish within {timeout}s")


# ---------------------------------------------------------------------------
# GitHub API helpers
# ---------------------------------------------------------------------------
def gh_paginate(url: str, headers: dict, params: dict | None = None,
                timeout: int = 30) -> list:
    """Fetch all pages of a GitHub API list endpoint.

    Follows ``Link: rel="next"`` headers automatically so callers never
    silently miss results.  ``params`` are only sent on the first request;
    subsequent pages use the URL from the Link header which already contains
    query parameters.
    """
    all_items: list = []
    while url:
        resp = requests.get(url, headers=headers, params=params, timeout=timeout)
        if resp.status_code != 200:
            raise ProvisionError(
                f"GitHub API error ({resp.status_code}): {resp.text}"
            )
        all_items.extend(resp.json())
        # Follow pagination — params are baked into the Link URL for page 2+
        url = None
        params = None
        link = resp.headers.get("Link", "")
        for part in link.split(","):
            if 'rel="next"' in part:
                url = part.split(";")[0].strip().strip("<>")
                break
    return all_items


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
    # 204 No Content has no body — return a synthetic success response.
    if resp.status_code == 204:
        return {"success": True, "result": None}
    try:
        data = resp.json()
    except (ValueError, requests.exceptions.JSONDecodeError):
        raise ProvisionError(
            f"Cloudflare returned non-JSON response (HTTP {resp.status_code})"
        )
    if not data.get("success"):
        errors = data.get("errors", [])
        raise ProvisionError(f"Cloudflare API error: {errors}")
    return data
