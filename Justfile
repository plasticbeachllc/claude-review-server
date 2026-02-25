# PR Review Agent — build & deploy commands

# Build cloud-init.yaml from template + source files
build:
    python3 scripts/build.py
    @echo "✓ cloud-init.yaml is ready"

# Validate the built cloud-init.yaml (requires cloud-init installed)
validate: build
    #!/usr/bin/env bash
    if ! command -v cloud-init &>/dev/null; then
        echo "Note: cloud-init not installed, skipping validation"
        exit 0
    fi
    cloud-init schema --config-file cloud-init.yaml

# Deploy agent files to a running server (requires root SSH access)
deploy host:
    scp src/agent.py src/prompt.md {{host}}:/opt/pr-review/
    ssh {{host}} 'chown review:review /opt/pr-review/agent.py /opt/pr-review/prompt.md && systemctl restart pr-review'
    @echo "✓ Deployed and restarted on {{host}}"

# Set up Origin CA TLS (for custom domain users — see README)
# Usage: just setup-tls root@server origin.pem origin-key.pem
setup-tls host cert key:
    ssh {{host}} 'mkdir -p /etc/caddy/certs && chown caddy:caddy /etc/caddy/certs && chmod 700 /etc/caddy/certs'
    scp {{cert}} {{host}}:/etc/caddy/certs/origin.pem
    scp {{key}} {{host}}:/etc/caddy/certs/origin-key.pem
    scp infra/Caddyfile.origin-ca {{host}}:/etc/caddy/Caddyfile
    ssh {{host}} 'chown caddy:caddy /etc/caddy/certs/origin.pem /etc/caddy/certs/origin-key.pem && chmod 644 /etc/caddy/certs/origin.pem && chmod 600 /etc/caddy/certs/origin-key.pem && ufw allow 443/tcp && caddy validate --config /etc/caddy/Caddyfile && systemctl restart caddy && systemctl is-active --quiet caddy'
    @echo "✓ TLS configured — Caddy now serving on :443"

# Provision a new server (build + create + configure — fully automated)
provision:
    uv run python scripts/provision.py

# Destroy the server and clean up tunnel/webhook/DNS (pass --yes to confirm)
destroy confirm="":
    @[ "{{ confirm }}" = "--yes" ] || (echo "This will delete the server and all associated resources."; echo "Run: just destroy --yes"; exit 1)
    uv run python scripts/destroy.py

# Check server status and health
status:
    uv run python scripts/status.py

# Run tests
test:
    uv run pytest tests/ -v

# Clean build artifacts
clean:
    rm -f cloud-init.yaml
