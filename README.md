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
GitHub webhook → Cloudflare Tunnel (TLS) → cloudflared → Caddy (reverse proxy) → Python agent → Claude Code CLI → gh pr comment
```

## Project structure

```
agent.py                 # Webhook listener + review logic
prompt.md                # Review prompt template (customize this!)
cloud-init.tmpl.yaml     # Cloud-init template with {{FILE:...}} markers
build.py                 # Assembles cloud-init.yaml from template + source files
Caddyfile.origin-ca      # Caddy TLS config for custom domain setup
Justfile                 # Build, test, and deploy commands
pyproject.toml           # Python project config (dev deps via uv)
.env.example             # Copy to .env, fill in your values
```

## Prerequisites

- **Hetzner Cloud account** (or any VPS — adjust cloud-init as needed)
- **Cloudflare account** (free tier works — used for tunnel or DNS)
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

### 4. Create the Hetzner server

1. Go to [Hetzner Cloud Console](https://console.hetzner.cloud/) → **Create Server**
2. Select Ubuntu 24.04, CX11, your SSH key
3. Under **Cloud config**, paste the contents of your built `cloud-init.yaml`
4. Create the server and note the IPv4 address

Wait 3–5 minutes for cloud-init to finish (watch the CPU graph in Hetzner console).

### 5. Set up a Cloudflare Tunnel

This gives you a public HTTPS URL without opening any inbound ports or managing certificates.

1. In Cloudflare dashboard → **Zero Trust → Networks → Tunnels**
2. Click **Create a tunnel**, choose **Cloudflared**, name it (e.g. `pr-review`)
3. Copy the install/run command — it includes your tunnel token
4. SSH into your server and run the install command:

```bash
ssh root@<server-ip>

# Add Cloudflare's GPG key and APT repo
curl -fsSL https://pkg.cloudflare.com/cloudflare-main.gpg | tee /usr/share/keyrings/cloudflare-main.gpg >/dev/null
echo "deb [signed-by=/usr/share/keyrings/cloudflare-main.gpg] https://pkg.cloudflare.com/cloudflared $(lsb_release -cs) main" | tee /etc/apt/sources.list.d/cloudflared.list
apt-get update && apt-get install -y cloudflared

# Install the tunnel as a service using the token Cloudflare gave you
cloudflared service install <YOUR_TUNNEL_TOKEN>
```

5. Back in the Cloudflare dashboard, add a **Public Hostname** for the tunnel:
   - **Subdomain:** `pr-review` (or whatever you like)
   - **Domain:** pick any domain on your Cloudflare account, or use the generated `*.cfargotunnel.com` URL
   - **Service:** `http://localhost:80` (Caddy handles the rest)
6. Note the resulting public URL (e.g. `https://pr-review.yourdomain.com`)

### 6. Configure the server

```bash
ssh root@<server-ip>

# Authenticate GitHub CLI
sudo -u review gh auth login

# Authenticate Claude Code (token is stored in ~review/.claude/)
sudo -u review claude

# Start the agent
systemctl start pr-review

# Verify locally
curl http://localhost:8080/health
# → {"status":"healthy"}

# Verify end-to-end through the tunnel
curl https://<your-tunnel-hostname>/health
# → {"status":"healthy"}
```

### 7. Create the GitHub webhook

1. GitHub org → **Settings → Webhooks → Add webhook**
2. **Payload URL:** `https://<your-tunnel-hostname>/webhook`
3. **Content type:** `application/json`
4. **Secret:** `grep WEBHOOK_SECRET /opt/pr-review/.env | cut -d= -f2`
5. **Events:** Pull requests only
6. Check **Recent Deliveries** for a `200` response

### 8. Test it

Open a PR on any repo in your org. You should see a review comment within 1–2 minutes.

---

## Alternative: Custom domain with Origin CA

If you already have a domain on Cloudflare and prefer to use an Origin CA certificate instead of a tunnel, replace step 5 above with:

### 5a. Create the Cloudflare Origin CA certificate

1. In Cloudflare dashboard → your domain → **SSL/TLS → Origin Server**
2. Click **Create Certificate**, set hostname to your subdomain (e.g. `pr-review.yourdomain.com`)
3. Copy both the certificate and private key (the key is only shown once)
4. Under **SSL/TLS → Overview**, set encryption mode to **Full (Strict)**

### 5b. Point your domain at the server

In Cloudflare DNS, add an A record:

| Type | Name         | Content         | Proxy   |
|------|--------------|-----------------|---------|
| A    | `pr-review`  | `<server IPv4>` | Proxied |

### 5c. Configure the server for TLS

Save the certificate and private key from step 5a to local files, then run:

```bash
just setup-tls root@<server-ip> origin.pem origin-key.pem
```

This deploys the TLS Caddyfile, installs the certs with correct permissions, opens port 443, and restarts Caddy.

Then continue with step 6 (configure the server) as normal.

---

## Commands

```bash
just build                                    # Assemble cloud-init.yaml from template + sources
just test                                     # Run tests (via uv)
just deploy user@host                         # SCP source files to server and restart
just setup-tls host cert key                  # Configure Origin CA TLS (custom domain only)
just clean                                    # Remove built cloud-init.yaml
```

## Updating a running server

After editing `agent.py` or `prompt.md`:

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

**Claude auth errors** — Re-run `sudo -u review claude` to re-authenticate (token is stored in `~review/.claude/`), then `systemctl restart pr-review`.

**Caddy won't start** — Check cert permissions: `origin.pem` should be 644, `origin-key.pem` should be 600 owned by `caddy:caddy`.

**Tunnel not connecting** — Check `systemctl status cloudflared` and verify the tunnel is active in the Cloudflare Zero Trust dashboard.

**Reviews aren't posting** — Verify gh access: `sudo -u review gh pr list --repo your-org/some-repo`.

## Maintenance

| Task | Frequency | How |
|------|-----------|-----|
| Renew Claude token | Yearly | `claude setup-token`, update `.env`, restart |
| Renew Origin CA cert | 15 years | Regenerate in Cloudflare, replace cert files (custom domain only) |
| Update Claude Code | As needed | Bump version in `cloud-init.tmpl.yaml`, `just build` |
| System packages | Monthly | `apt update && apt upgrade` |
