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

# Run tests
test:
    uv run pytest tests/ -v

# Clean build artifacts
clean:
    rm -f cloud-init.yaml
