"""Shared utilities for provisioning scripts."""

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
    "SERVER_TYPE": "cx22",
    "SERVER_LOCATION": "fsn1",
}


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------
class ProvisionError(Exception):
    """Raised when a provisioning step fails."""


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
