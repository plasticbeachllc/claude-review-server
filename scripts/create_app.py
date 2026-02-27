#!/usr/bin/env python3
"""Create a GitHub App via the manifest flow and install it on your org.

This is a one-time setup step.  Run ``just create-app`` before your first
``just provision``.

The script:
  1. Starts a temporary local HTTP server
  2. Opens your browser to GitHub with the app manifest
  3. You approve the app on GitHub
  4. GitHub redirects back; the script captures the app credentials
  5. You install the app on your org (browser opens automatically)
  6. The script discovers the installation ID

Credentials are saved to ``.env`` and ``github-app.pem``.

Usage:
    python3 scripts/create_app.py
    just create-app
"""

import html
import json
import secrets
import socket
import sys
import textwrap
import threading
import time
import webbrowser
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import requests

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _jwt import generate_jwt  # noqa: E402

GH_API = "https://api.github.com"
PEM_FILENAME = "github-app.pem"


# ---------------------------------------------------------------------------
# .env helpers
# ---------------------------------------------------------------------------
def _read_env(path: Path) -> dict[str, str]:
    """Read a .env file into a dict (comments and blanks skipped)."""
    config: dict[str, str] = {}
    if not path.exists():
        return config
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        config[key.strip()] = value.strip()
    return config


def _upsert_env(path: Path, updates: dict[str, str]):
    """Add or update keys in a .env file, preserving comments and order."""
    lines: list[str] = []
    existing_keys: set[str] = set()

    if path.exists():
        for line in path.read_text().splitlines():
            stripped = line.strip()
            if stripped and not stripped.startswith("#") and "=" in stripped:
                key = stripped.partition("=")[0].strip()
                if key in updates:
                    lines.append(f"{key}={updates[key]}")
                    existing_keys.add(key)
                    continue
            lines.append(line)

    # Append any new keys that weren't already in the file
    for key, value in updates.items():
        if key not in existing_keys:
            lines.append(f"{key}={value}")

    path.write_text("\n".join(lines) + "\n")


# ---------------------------------------------------------------------------
# Manifest flow HTTP handler
# ---------------------------------------------------------------------------
class _ManifestHandler(BaseHTTPRequestHandler):
    """Handles the GitHub App manifest creation redirect flow.

    Results are stored on the *server* instance (not class variables) so
    that the main thread can read them without relying on class-level
    mutation from the server thread.
    """

    def do_GET(self):
        parsed = urlparse(self.path)

        if parsed.path == "/":
            # Serve the auto-submitting form page
            self._serve_form()
        elif parsed.path == "/callback":
            # GitHub redirects here with ?code=...
            params = parse_qs(parsed.query)
            codes = params.get("code", [])
            if codes:
                self.server.callback_code = codes[0]  # type: ignore[attr-defined]
                self.server.callback_event.set()  # type: ignore[attr-defined]
                self._respond(200, "App created! You can close this tab.")
            else:
                self.server.callback_error = "No code in callback"  # type: ignore[attr-defined]
                self.server.callback_event.set()  # type: ignore[attr-defined]
                self._respond(400, "Error: no code parameter received.")
        else:
            self.send_response(404)
            self.end_headers()

    def _serve_form(self):
        """Serve an HTML page that auto-submits the manifest to GitHub."""
        server = self.server
        manifest_escaped = html.escape(json.dumps(server.manifest))  # type: ignore[attr-defined]
        org_escaped = html.escape(server.org)  # type: ignore[attr-defined]
        page = textwrap.dedent(f"""\
            <!DOCTYPE html>
            <html>
            <head><title>Create GitHub App</title></head>
            <body>
            <h2>Creating GitHub App for {org_escaped}...</h2>
            <p>If you are not redirected automatically,
               click the button below.</p>
            <form id="manifest-form" method="post"
                  action="https://github.com/organizations/{org_escaped}/settings/apps/new">
              <input type="hidden" name="manifest" value="{manifest_escaped}">
              <button type="submit">Create GitHub App</button>
            </form>
            <script>document.getElementById('manifest-form').submit();</script>
            </body>
            </html>
        """)
        self._respond(200, page, content_type="text/html")

    def _respond(self, status: int, body: str, content_type: str = "text/html"):
        encoded = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, fmt, *args):
        pass  # Suppress default stderr logging


def _find_free_port() -> int:
    """Find an available TCP port on localhost."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


# ---------------------------------------------------------------------------
# Main flow
# ---------------------------------------------------------------------------
def create_app(root: Path) -> dict:
    """Run the GitHub App manifest flow. Returns the app credentials."""
    env_path = root / ".env"
    config = _read_env(env_path)

    # Validate required keys for app creation
    org = config.get("GITHUB_ORG")
    hostname = config.get("TUNNEL_HOSTNAME")
    if not org:
        print("ERROR: GITHUB_ORG not set in .env", file=sys.stderr)
        sys.exit(1)
    if not hostname:
        print("ERROR: TUNNEL_HOSTNAME not set in .env", file=sys.stderr)
        sys.exit(1)

    # Check if app already exists
    if config.get("GH_APP_ID"):
        print(
            f"ERROR: GH_APP_ID={config['GH_APP_ID']} already set in .env.\n"
            f"If you want to create a new app, remove GH_APP_ID from .env first.",
            file=sys.stderr,
        )
        sys.exit(1)

    port = _find_free_port()
    webhook_url = f"https://{hostname}/webhook"

    # Random suffix avoids name collisions if re-creating the app.
    # GitHub App names must be globally unique.
    suffix = secrets.token_hex(3)
    manifest = {
        "name": f"pr-review-{org}-{suffix}",
        "url": "https://github.com/plasticbeachllc/claude-review-server",
        "hook_attributes": {
            # No "secret" key here — GitHub generates the webhook secret
            # automatically during the manifest flow and returns it in the
            # POST /app-manifests/{code}/conversions response.
            "url": webhook_url,
            "active": True,
        },
        "redirect_url": f"http://localhost:{port}/callback",
        "default_permissions": {
            "contents": "read",
            "pull_requests": "write",
        },
        "default_events": ["pull_request"],
        "public": False,
    }

    # Start local server
    server = HTTPServer(("127.0.0.1", port), _ManifestHandler)
    server.manifest = manifest  # type: ignore[attr-defined]
    server.org = org  # type: ignore[attr-defined]

    print(f"[1/4] Starting local server on http://localhost:{port}")
    print(f"  Opening browser to create GitHub App for org '{org}'...")
    print(f"  Webhook URL: {webhook_url}")
    print()

    # Store callback results on the server instance (read by main thread)
    server.callback_code = None  # type: ignore[attr-defined]
    server.callback_error = None  # type: ignore[attr-defined]
    server.callback_event = threading.Event()  # type: ignore[attr-defined]

    # Serve in a background thread
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()

    url = f"http://localhost:{port}/"
    if not webbrowser.open(url):
        print(f"\n  No browser found. Open this URL manually:\n  {url}")

    # Wait for the callback (up to 5 minutes)
    print("  Waiting for you to approve the app on GitHub...", end="", flush=True)
    server.callback_event.wait(timeout=300)  # type: ignore[attr-defined]

    server.shutdown()

    if server.callback_error:  # type: ignore[attr-defined]
        print(f"\nERROR: {server.callback_error}", file=sys.stderr)
        sys.exit(1)
    if not server.callback_code:  # type: ignore[attr-defined]
        print("\nERROR: Timed out waiting for GitHub redirect", file=sys.stderr)
        sys.exit(1)

    code = server.callback_code  # type: ignore[attr-defined]
    print(" ok")

    # Exchange code for credentials
    print("\n[2/4] Exchanging code for app credentials...")
    resp = requests.post(
        f"{GH_API}/app-manifests/{code}/conversions",
        headers={
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        },
        timeout=30,
    )
    if resp.status_code != 201:
        print(
            f"ERROR: GitHub API returned {resp.status_code}: {resp.text}",
            file=sys.stderr,
        )
        sys.exit(1)

    data = resp.json()
    try:
        app_id = str(data["id"])
        app_slug = data.get("slug", f"pr-review-{org}")
        pem = data["pem"]
        webhook_secret = data["webhook_secret"]
    except KeyError as e:
        print(
            f"ERROR: Unexpected response from GitHub (missing {e}): "
            f"{json.dumps(data)[:500]}",
            file=sys.stderr,
        )
        sys.exit(1)

    # Save PEM file
    pem_path = root / PEM_FILENAME
    pem_path.write_text(pem)
    pem_path.chmod(0o600)
    print(f"  Saved private key to {PEM_FILENAME}")

    # Update .env
    _upsert_env(env_path, {
        "GH_APP_ID": app_id,
        "GH_APP_PRIVATE_KEY_FILE": str(pem_path.resolve()),
        "GITHUB_WEBHOOK_SECRET": webhook_secret,
    })
    print(f"  Updated .env: GH_APP_ID={app_id}")
    print(f"  Webhook secret saved to .env")

    # Install the app on the org
    print(f"\n[3/4] Install the app on your org")
    install_url = f"https://github.com/apps/{app_slug}/installations/new"
    print(f"  Opening: {install_url}")
    print(f"  Select your org '{org}' and click Install.")
    print()
    if not webbrowser.open(install_url):
        print(f"\n  No browser found. Open this URL manually:\n  {install_url}")

    # Poll for the installation
    print("  Waiting for installation...", end="", flush=True)
    deadline = time.time() + 300
    installation_id = None

    while time.time() < deadline:
        time.sleep(3)
        print(".", end="", flush=True)
        try:
            jwt = generate_jwt(app_id, str(pem_path))
            resp = requests.get(
                f"{GH_API}/app/installations",
                headers={
                    "Authorization": f"Bearer {jwt}",
                    "Accept": "application/vnd.github+json",
                    "X-GitHub-Api-Version": "2022-11-28",
                },
                timeout=30,
            )
            if resp.status_code == 200:
                installations = resp.json()
                for inst in installations:
                    account = inst.get("account", {})
                    if account.get("login", "").lower() == org.lower():
                        installation_id = str(inst["id"])
                        break
                if installation_id:
                    break
        except Exception as exc:
            print(f"\n  (poll error, will retry: {exc})", file=sys.stderr, end="")
            # Continue polling — transient auth / network errors are expected
            # while the PEM is fresh and installation is in progress.

    if not installation_id:
        print("\nERROR: Timed out waiting for app installation.", file=sys.stderr)
        print(
            f"Install the app manually at {install_url}, then add "
            f"GH_INSTALLATION_ID=<id> to .env",
            file=sys.stderr,
        )
        sys.exit(1)

    print(" ok")

    _upsert_env(env_path, {"GH_INSTALLATION_ID": installation_id})

    print(f"\n[4/4] Setup complete!")
    print()
    print("=" * 60)
    print(f"  App ID:          {app_id}")
    print(f"  Installation ID: {installation_id}")
    print(f"  Private key:     {PEM_FILENAME}")
    print(f"  Webhook URL:     {webhook_url}")
    print()
    print(f"  Next step: just provision")
    print("=" * 60)

    return {
        "app_id": app_id,
        "installation_id": installation_id,
        "webhook_secret": webhook_secret,
    }


def main():
    root = Path(__file__).resolve().parent.parent
    create_app(root)


if __name__ == "__main__":
    main()
