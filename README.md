# Claude Review Server

A self-hosted agent that automatically reviews pull requests using your Claude Code subscription. When a PR is opened or updated in your GitHub org, the agent posts a concise, actionable review comment.

```
GitHub webhook → Cloudflare Tunnel → Caddy → Python agent → Claude Code → PR comment
```

---

## What you get

When someone opens or updates a PR in your org, the agent reads edited files and posts a review.

When someone force-pushes, old reviews are automatically collapsed so the conversation stays clean.

---

## Why this exists

|  | Claude Review Server | GitHub Copilot code review | Typical SaaS reviewers |
|--|--|--|--|
| **Cost** | ~$4/mo server + your existing Claude sub | $19/user/mo or higher | $15–50/user/mo |
| **Privacy** | Code stays on your server | Sent to GitHub/Microsoft | Sent to third party |
| **Customizable** | Edit one Markdown file to change the review focus | Limited configuration | Varies |
| **Self-hosted** | Full control | No | Rarely |

---

## Quick start

### One-command deploy

Fill `.env` with your infrastructure secrets, create a GitHub App, and provision — Hetzner VM, Cloudflare Tunnel, and webhook included.

```bash
git clone https://github.com/plasticbeachllc/claude-review-server.git
cd claude-review-server
cp .env.example .env
# Fill in .env (see below)

just create-app    # One-time: creates GitHub App + webhook, installs on your org
just provision     # Provisions server, injects credentials, starts service
```

That's all. Open a PR in your org to see it works.

### Contents of `.env`

| Variable | Where to get it |
|----------|----------------|
| `HCLOUD_TOKEN` | [Hetzner Cloud Console](https://console.hetzner.cloud/) → API tokens |
| `CLAUDE_CODE_AUTH_TOKEN` | Run `claude setup-token` locally |
| `CF_API_TOKEN` | [Cloudflare dashboard](https://dash.cloudflare.com/profile/api-tokens) → Create token (Zone:DNS:Edit + Account:Cloudflare Tunnel:Edit) |
| `CF_ACCOUNT_ID` | Cloudflare dashboard → any domain → Overview sidebar |
| `CF_ZONE_ID` | Same page as account ID |
| `TUNNEL_HOSTNAME` | The public hostname you want (e.g. `pr-review.yourdomain.com`) |
| `GITHUB_ORG` | Your GitHub org name |

`GH_APP_ID`, `GH_APP_PRIVATE_KEY_FILE`, `GH_INSTALLATION_ID`, and `GITHUB_WEBHOOK_SECRET` are auto-populated by `just create-app`.

### Managing the server

```bash
just status                    # Health check + server info
just deploy root@<server-ip>   # Push code changes, restart service
just destroy yes               # Tear everything down
```

---

## How it works

1. **GitHub sends a webhook** when a PR is opened or updated
2. **Signature verification** — the agent validates the HMAC-SHA256 signature; forged requests are rejected
3. **Draft filtering** — draft PRs are skipped
4. **Diff retrieval** — fetches edited files using the GitHub CLI
5. **Smart truncation** — if truncation is necssary to fit context, lockfiles and generated code are dropped first
6. **Claude reviews** — Customizable prompt drives review mechanics
7. **Comment posted** — the review appears as a PR comment within 1–2 minutes
8. **Force-push handling** — prior reviews are collapsed under a `<details>` tag; ongoing reviews are restarted

### Smart diff truncation

Large PRs are truncated for context limitations. The system drops files in this order:

1. Lockfiles (`package-lock.json`, `yarn.lock`, `Cargo.lock`, ...)
2. Generated/minified code (`.min.js`, `.pb.go`, ...)
3. Snapshots, SVGs, vendored code
4. Remaining files by size (largest first)

A note is added to the review listing which files were omitted.

---

## Customization

### Change what Claude reviews

Edit `src/prompt.md`. This is the prompt template sent to Claude for each review. 

Available template variables: `{pr_number}`, `{repo}`, `{pr_title}`, `{pr_body}`, `{truncation_note}`, `{diff}`.

### Configuration

| Setting | Where | Default |
|---------|-------|---------|
| Review prompt | `src/prompt.md` | Correctness + security + performance |
| Concurrent reviews | `MAX_WORKERS` in `.env` | 4 |
| Diff size limit | `max_chars` in `smart_truncate_diff()` | 40,000 chars |
| Low-priority file patterns | `LOW_PRIORITY_PATTERNS` in `src/agent.py` | Lockfiles, generated, vendor, SVGs |

---

## Project structure

```
src/
  agent.py               # Webhook listener + review logic
  prompt.md              # Review prompt template — edit this!
scripts/
  create_app.py          # GitHub App creation (manifest flow)
  provision.py           # One-command server provisioning
  destroy.py             # Clean teardown of all resources
  status.py              # Health + status checks
  build.py               # Assembles cloud-init.yaml from template
  _jwt.py                # GitHub App JWT generation
  _common.py             # Shared utilities
infra/
  cloud-init.tmpl.yaml   # Server provisioning template
  Caddyfile.origin-ca    # TLS config for custom domain setup
tests/
  test_agent.py          # Unit tests
  test_provision.py      # Provisioning tests
Justfile                 # All commands: build, test, deploy, provision, destroy
.env.example             # Configuration template
```

---

## Alternative: manual setup

If you'd rather provision the server yourself (or use a different cloud provider), you can set things up step by step.

<details>
<summary>Manual setup instructions</summary>

### 1. Build cloud-init.yaml

```bash
just build
```

### 2. Create a server

Use any VPS with Ubuntu 24.04. Paste the contents of `cloud-init.yaml` as the cloud-init user data.

Wait 3–5 minutes for provisioning to complete.

### 3. Set up a Cloudflare Tunnel

1. Cloudflare dashboard → **Zero Trust → Networks → Tunnels → Create a tunnel**
2. Choose **Cloudflared**, name it (e.g. `pr-review`)
3. SSH into your server and install cloudflared:

```bash
ssh root@<server-ip>
curl -fsSL https://pkg.cloudflare.com/cloudflare-main.gpg \
  | tee /usr/share/keyrings/cloudflare-main.gpg >/dev/null
echo "deb [signed-by=/usr/share/keyrings/cloudflare-main.gpg] \
  https://pkg.cloudflare.com/cloudflared $(lsb_release -cs) main" \
  | tee /etc/apt/sources.list.d/cloudflared.list
apt-get update && apt-get install -y cloudflared
cloudflared service install <YOUR_TUNNEL_TOKEN>
```

4. In the Cloudflare dashboard, add a public hostname:
   - **Service:** `http://localhost:80`
   - **Subdomain/Domain:** whatever you want (e.g. `pr-review.yourdomain.com`)

### 4. Configure the server

```bash
ssh root@<server-ip>

# Copy GitHub App private key
scp github-app.pem root@<server-ip>:/opt/pr-review/github-app.pem

# Add credentials to /opt/pr-review/.env:
#   GH_APP_ID=<from .env>
#   GH_INSTALLATION_ID=<from .env>
#   GH_APP_PRIVATE_KEY_FILE=/opt/pr-review/github-app.pem
#   GITHUB_WEBHOOK_SECRET=<from .env>
#   CLAUDE_CODE_AUTH_TOKEN=<from .env>

# Fix permissions
chown review:review /opt/pr-review/github-app.pem
chmod 600 /opt/pr-review/github-app.pem

# Start the agent
systemctl start pr-review

# Verify
curl http://localhost:8080/health
# → {"status":"healthy"}
```

### 5. Create the GitHub App

If you didn't use `just create-app`, create the app manually:

1. GitHub org → **Settings → Developer settings → GitHub Apps → New GitHub App**
2. Set permissions: `Contents: Read`, `Pull requests: Read & write`
3. Subscribe to **Pull request** events
4. Set webhook URL to `https://<your-hostname>/webhook`
5. Install the app on your org
6. Add `GH_APP_ID`, `GH_INSTALLATION_ID`, `GITHUB_WEBHOOK_SECRET` to your `.env`
7. Save the private key as `github-app.pem`

### 6. Test it

Open a PR. You should see a review comment within 1–2 minutes.

</details>

<details>
<summary>Custom domain with Origin CA (instead of Tunnel)</summary>

If you prefer a direct connection with Cloudflare Origin CA certificates:

1. Cloudflare → your domain → **SSL/TLS → Origin Server → Create Certificate**
2. Set hostname to your subdomain, copy the cert and key
3. Set SSL mode to **Full (Strict)**
4. Add a proxied A record pointing to your server IP
5. Deploy the certs:

```bash
just setup-tls root@<server-ip> origin.pem origin-key.pem
```

</details>

---

## Commands

| Command | What it does |
|---------|-------------|
| `just create-app` | Create GitHub App + webhook, install on org (one-time) |
| `just provision` | Create server + tunnel (fully automated) |
| `just status` | Check server health and status |
| `just deploy root@host` | Push code changes to a running server |
| `just build` | Assemble cloud-init.yaml from template |
| `just test` | Run unit tests |
| `just setup-tls host cert key` | Configure Origin CA TLS |
| `just destroy yes` | Tear down server + tunnel + DNS (App preserved) |
| `just clean` | Remove built cloud-init.yaml |

---

## Troubleshooting

| Problem | Fix |
|---------|-----|
| Webhook returns 404 | The agent only responds to `POST /webhook` and `GET /health` |
| Agent won't start | `journalctl -u pr-review --no-pager -n 30` — usually a missing env var |
| Claude auth errors | `sudo -u review claude` to re-authenticate, then `systemctl restart pr-review` |
| Reviews aren't posting | Check App credentials in `/opt/pr-review/.env` and PEM file permissions |
| Tunnel not connecting | `systemctl status cloudflared` and check Cloudflare Zero Trust dashboard |

---

## Prerequisites

- [**just**](https://github.com/casey/just) command runner
- [**uv**](https://docs.astral.sh/uv/) (for running scripts and tests)
- A **Claude Code subscription** (Pro or Max)
- A **Hetzner Cloud** account (or any VPS — adjust cloud-init as needed)
- A **Cloudflare** account (free tier works)
- A **GitHub org** with permission to create and install GitHub Apps

---

## Security

- **No inbound ports** — Cloudflare Tunnel connects outbound; no ports are opened on the server
- **HMAC signature verification** — every webhook payload is cryptographically verified
- **Isolated service user** — the agent runs as an unprivileged `review` user, not root
- **Systemd hardening** — `ProtectSystem=strict`, `PrivateTmp=yes`, restricted capabilities
- **Token isolation** — auth tokens are stored with proper permissions in `~review/.claude/`

---

## License

MIT — see [LICENSE](LICENSE).
