"""GitHub App JWT generation using openssl CLI (no Python crypto deps)."""

import base64
import json
import os
import subprocess
import time


def _b64url(data: bytes) -> str:
    """Base64url-encode *data* without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def generate_jwt(app_id: str, private_key_path: str) -> str:
    """Generate an RS256 JWT for GitHub App authentication.

    Uses ``openssl dgst -sha256 -sign`` for RSA signing so that neither
    PyJWT nor the ``cryptography`` package is required.  Both macOS
    LibreSSL and Linux OpenSSL support this command.

    The JWT is valid for 10 minutes (the GitHub maximum) with 60 seconds
    of backward clock-skew tolerance on the ``iat`` claim.
    """
    if not os.path.isfile(private_key_path):
        raise RuntimeError(f"Private key not found: {private_key_path}")

    now = int(time.time())
    header = _b64url(json.dumps({"alg": "RS256", "typ": "JWT"}).encode())
    payload = _b64url(json.dumps({
        "iat": now - 60,
        "exp": now + 10 * 60,
        "iss": app_id,
    }).encode())

    signing_input = f"{header}.{payload}"

    try:
        result = subprocess.run(
            ["openssl", "dgst", "-sha256", "-sign", private_key_path],
            input=signing_input.encode(),
            capture_output=True,
            timeout=10,
        )
    except FileNotFoundError:
        raise RuntimeError(
            "openssl not found — install it (e.g. apt install openssl)"
        ) from None
    if result.returncode != 0:
        raise RuntimeError(
            f"openssl signing failed (rc={result.returncode}): "
            f"{result.stderr.decode().strip()}"
        )

    if not result.stdout:
        raise RuntimeError(
            "openssl produced no output — check key file permissions"
        )

    signature = _b64url(result.stdout)
    return f"{signing_input}.{signature}"
