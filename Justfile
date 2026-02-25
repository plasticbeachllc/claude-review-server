# PR Review Agent — build & deploy commands

# Build cloud-init.yaml from template + source files
build:
    python3 build.py
    @echo "✓ cloud-init.yaml is ready"

# Validate the built cloud-init.yaml (requires cloud-init installed)
validate: build
    cloud-init schema --config-file cloud-init.yaml || echo "Note: install cloud-init for full validation"

# Deploy agent files to a running server (requires SSH access)
deploy host:
    scp agent.py prompt.md check-auth.sh {{host}}:/opt/pr-review/
    ssh {{host}} 'chown review:review /opt/pr-review/agent.py /opt/pr-review/prompt.md /opt/pr-review/check-auth.sh && systemctl restart pr-review'
    @echo "✓ Deployed and restarted on {{host}}"

# Run tests
test:
    uv run pytest tests/ -v

# Clean build artifacts
clean:
    rm -f cloud-init.yaml
