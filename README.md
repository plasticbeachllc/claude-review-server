# Automated PR Reviews with Claude Code

A self-hosted agent that automatically reviews pull requests using your Claude Code subscription. When a PR is opened or updated in your GitHub org, the agent posts a concise, actionable review comment within a couple of minutes.

## What it does

- Listens for GitHub webhook events on PR open and push
- Fetches the diff via the GitHub CLI
- Sends it to Claude Code for review
- Posts the review as a PR comment
- Collapses old reviews when a PR is force-pushed
- Skips draft PRs
- Smart diff truncation — drops lockfiles and generated code first when diffs are large

## Architecture

```
GitHub webhook → Cloudflare (TLS) → Caddy (reverse proxy) → Python agent → Claude Code CLI → gh pr comment
```

## Project structure

```
agent.py                 # Webhook listener + review logic
prompt.md                # Review prompt template (customize this!)
check-auth.sh            # Auth health check (runs every 30 min via systemd)
cloud-init.tmpl.yaml     # Cloud-init template with {{FILE:...}} markers
build.py                 # Assembles cloud-init.yaml from template + source files
Justfile                 # Build, test, and deploy commands
pyproject.toml           # Python project config (dev deps via uv)
.env.example             # Copy to .env, fill in your values
```

## Prerequisites

- **Hetzner Cloud account** (or any VPS — adjust cloud-init as needed)
- **Cloudflare account** with your domain's DNS managed there
- **GitHub org** with permission to create org-level webhooks
- **Claude Code subscription** (Pro or Max) for `claude setup-token`
- **SSH key** added to your Hetzner account
- [**just**](https://github.com/casey/just) command runner
- [**uv**](https://docs.astral.sh/uv/) (for running tests)

## Cost

~$4/month for a CX11 server. Claude usage comes from your existing subscription.

---

## Quick start

### 1. Clone and configure

```bash
git clone <this-repo>
cd claude-review-server
cp .env.example .env
# Edit .env with your webhook secret and other settings
```

### 2. Customize the review prompt (optional)

Edit `prompt.md` to change what Claude focuses on during reviews.

### 3. Build cloud-init.yaml

```bash
just build
```

This assembles `cloud-init.yaml` from the template and your source files. The built file is gitignored — it's a build artifact.

### 4. Create the Cloudflare Origin CA certificate

1. In Cloudflare dashboard → your domain → **SSL/TLS → Origin Server**
2. Click **Create Certificate**, set hostname to your subdomain (e.g. `pr-review.yourdomain.com`)
3. Copy both the certificate and private key (the key is only shown once)
4. Under **SSL/TLS → Overview**, set encryption mode to **Full (Strict)**

### 5. Create the Hetzner server

1. Go to [Hetzner Cloud Console](https://console.hetzner.cloud/) → **Create Server**
2. Select Ubuntu 24.04, CX11, your SSH key
3. Under **Cloud config**, paste the contents of your built `cloud-init.yaml`
4. Create the server and note the IPv4 address

Wait 3–5 minutes for cloud-init to finish (watch the CPU graph in Hetzner console).

### 6. Point your domain at the server

In Cloudflare DNS, add an A record:

| Type | Name         | Content         | Proxy   |
|------|--------------|-----------------|---------|
| A    | `pr-review`  | `<server IPv4>` | Proxied |

### 7. Configure the server

SSH in and complete setup:

```bash
ssh root@<server-ip>

# Install the Cloudflare Origin CA cert
nano /etc/caddy/certs/origin.pem      # paste certificate
nano /etc/caddy/certs/origin-key.pem  # paste private key
chmod 644 /etc/caddy/certs/origin.pem
chmod 600 /etc/caddy/certs/origin-key.pem
chown caddy:caddy /etc/caddy/certs/origin-key.pem
systemctl restart caddy

# Authenticate GitHub CLI
sudo -u review gh auth login

# Add Claude Code token (generate with: claude setup-token)
sudo -u review claude

# Set your alert repo in .env
nano /opt/pr-review/.env
# Set ALERT_REPO=your-org/your-repo

# Start the agent
systemctl start pr-review
systemctl start pr-review-auth-check.timer

# Verify
curl http://localhost:8080/health
# → {"status":"healthy"}
```

### 8. Create the GitHub webhook

1. GitHub org → **Settings → Webhooks → Add webhook**
2. **Payload URL:** `https://pr-review.yourdomain.com/webhook`
3. **Content type:** `application/json`
4. **Secret:** `grep WEBHOOK_SECRET /opt/pr-review/.env | cut -d= -f2`
5. **Events:** Pull requests only
6. Check **Recent Deliveries** for a `200` response

### 9. Test it

Open a PR on any repo in your org. You should see a review comment within 1–2 minutes.

---

## Commands

```bash
just build              # Assemble cloud-init.yaml from template + sources
just test               # Run tests (via uv)
just deploy user@host   # SCP source files to server and restart
just clean              # Remove built cloud-init.yaml
```

## Updating a running server

After editing `agent.py`, `prompt.md`, or `check-auth.sh`:

```bash
just deploy root@<server-ip>
```

This copies the files and restarts the service. No need to rebuild cloud-init.yaml unless you're provisioning a new server.

## Customization

### Review prompt

Edit `prompt.md`. The template uses Python format strings: `{pr_number}`, `{repo}`, `{pr_title}`, `{pr_body}`, `{truncation_note}`, `{diff}`.

### Diff size limit

The `max_chars` parameter in `smart_truncate_diff` defaults to 40,000 characters. Increase for more coverage at the cost of slower reviews.

### Concurrent reviews

Set `MAX_WORKERS` in `.env` (default: 4).

### Low-priority file patterns

Edit `LOW_PRIORITY_PATTERNS` in `agent.py` to control which files get dropped first when diffs are truncated. Defaults: lockfiles, generated code, snapshots, SVGs, vendored code.

---

## Troubleshooting

**Webhook returns 404** — The agent only responds to `POST /webhook` and `GET /health`.

**Agent won't start** — Check `journalctl -u pr-review --no-pager -n 30`. Common cause: missing `GITHUB_WEBHOOK_SECRET` in `.env`.

**Claude auth errors** — Regenerate with `claude setup-token`, update `.env`, `systemctl restart pr-review`.

**Caddy won't start** — Check cert permissions: `origin.pem` should be 644, `origin-key.pem` should be 600 owned by `caddy:caddy`.

**Reviews aren't posting** — Verify gh access: `sudo -u review gh pr list --repo your-org/some-repo`.

## Maintenance

| Task | Frequency | How |
|------|-----------|-----|
| Renew Claude token | Yearly | `claude setup-token`, update `.env`, restart |
| Renew Origin CA cert | 15 years | Regenerate in Cloudflare, replace cert files |
| Update Claude Code | As needed | Bump version in `cloud-init.tmpl.yaml`, `just build` |
| System packages | Monthly | `apt update && apt upgrade` |
