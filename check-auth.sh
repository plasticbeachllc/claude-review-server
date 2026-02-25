#!/usr/bin/env bash
set -euo pipefail

set -a
source /opt/pr-review/.env
set +a

ALERT_REPO="${ALERT_REPO:-}"
ISSUE_TITLE="🔑 PR Review Agent: Claude auth expired"

check_claude() {
    timeout 30 claude -p "Reply with OK" --output-format text 2>/dev/null \
        | grep -qi "ok"
}

check_gh() {
    gh auth status &>/dev/null
}

alert() {
    local tool="$1"
    echo "AUTH FAILURE: $tool auth is invalid"

    # Don't alert if no repo configured
    if [[ -z "$ALERT_REPO" ]]; then
        echo "ALERT_REPO not set, cannot create issue"
        exit 1
    fi

    # Don't spam — check for existing open issue
    existing=$(gh issue list --repo "$ALERT_REPO" \
        --search "$ISSUE_TITLE" --state open --json number --jq 'length' 2>/dev/null || echo "0")

    if [[ "$existing" != "0" ]]; then
        echo "Alert issue already open, skipping"
        exit 1
    fi

    gh issue create --repo "$ALERT_REPO" \
        --title "$ISSUE_TITLE" \
        --body "$(cat <<EOF
## Auth Expired

The PR review agent on \`$(hostname)\` detected that **${tool}** authentication
has expired and needs to be renewed.

### How to fix

SSH into the server and run:

\`\`\`bash
# If Claude auth expired:
sudo -u review claude

# If GitHub auth expired:
sudo -u review gh auth login
\`\`\`

Then verify:
\`\`\`bash
sudo -u review /opt/pr-review/check-auth.sh
\`\`\`

This issue was created automatically. Close it once resolved.

---
*Server: $(hostname) | Time: $(date -u '+%Y-%m-%d %H:%M UTC')*
EOF
)" \
        --label "ops" 2>/dev/null || echo "Failed to create alert issue"

    exit 1
}

echo "Checking GitHub CLI auth..."
check_gh || alert "GitHub CLI (gh)"

echo "Checking Claude CLI auth..."
check_claude || alert "Claude CLI"

echo "All auth checks passed."
