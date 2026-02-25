# PR Review Agent — build & deploy commands

# Build cloud-init.yaml from template + source files
build:
    python3 build.py
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
    scp agent.py prompt.md {{host}}:/opt/pr-review/
    ssh {{host}} 'chown review:review /opt/pr-review/agent.py /opt/pr-review/prompt.md && systemctl restart pr-review'
    @echo "✓ Deployed and restarted on {{host}}"

# Set up Origin CA TLS (for custom domain users — see README)
# Usage: just setup-tls root@server origin.pem origin-key.pem
setup-tls host cert key:
    ssh {{host}} 'mkdir -p /etc/caddy/certs'
    scp {{cert}} {{host}}:/etc/caddy/certs/origin.pem
    scp {{key}} {{host}}:/etc/caddy/certs/origin-key.pem
    scp Caddyfile.origin-ca {{host}}:/etc/caddy/Caddyfile
    ssh {{host}} 'chown caddy:caddy /etc/caddy/certs/origin.pem /etc/caddy/certs/origin-key.pem && chmod 644 /etc/caddy/certs/origin.pem && chmod 600 /etc/caddy/certs/origin-key.pem && ufw allow 443/tcp && systemctl restart caddy'
    @echo "✓ TLS configured — Caddy now serving on :443"

# Run tests
test:
    uv run pytest tests/ -v

# Clean build artifacts
clean:
    rm -f cloud-init.yaml
