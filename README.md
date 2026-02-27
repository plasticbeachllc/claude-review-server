# Claude Review Server

**Automatic, intelligent PR reviews on every push — powered by your Claude Code subscription.**

Open a pull request, get a thoughtful code review in under two minutes. No SaaS, no per-seat pricing, no sending your code to a third party. Just Claude, running on a $4/month server you control.

```
GitHub webhook → Cloudflare Tunnel → Caddy → Python agent → Claude Code → PR comment
```

---

## What you get

When someone opens or updates a PR in your org, the agent reads the diff and posts a review like this:

> ## Review
>
> 1. **SQL injection risk** — `query.build()` on line 42 interpolates user input directly. Use parameterized queries instead.
> 2. **Missing error handling** — the `/api/submit` endpoint doesn't catch `TimeoutError`, which will crash the worker.
> 3. **Nice refactor** — extracting the validation logic into `validate_input()` makes this much easier to test.
>
> ---
> *Automated review by Claude Code*

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

Fill in your tokens, run one command, and the server provisions itself — Hetzner VM, Cloudflare Tunnel, GitHub webhook, everything.

```bash
git clone https://github.com/plasticbeachllc/claude-review-server.git
cd claude-review-server
cp .env.example .env
# Fill in .env (see below)

just provision
```

That's it. Open a PR in your org to see it work.

### What goes in `.env`

| Variable | Where to get it |
|----------|----------------|
| `HCLOUD_TOKEN` | [Hetzner Cloud Console](https://console.hetzner.cloud/) → API tokens |
| `GH_TOKEN` | GitHub → Settings → Developer settings → Personal access tokens (needs `admin:org_hook` scope) |
| `CLAUDE_CODE_AUTH_TOKEN` | Run `claude setup-token` locally |
| `CF_API_TOKEN` | [Cloudflare dashboard](https://dash.cloudflare.com/profile/api-tokens) → Create token (Zone:DNS:Edit + Account:Cloudflare Tunnel:Edit) |
| `CF_ACCOUNT_ID` | Cloudflare dashboard → any domain → Overview sidebar |
| `CF_ZONE_ID` | Same page as account ID |
| `TUNNEL_HOSTNAME` | The public hostname you want (e.g. `pr-review.yourdomain.com`) |
| `GITHUB_ORG` | Your GitHub org name |

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
4. **Diff retrieval** — fetches the full diff via `gh pr diff`
5. **Smart truncation** — if the diff exceeds 40K chars, lockfiles and generated code are dropped first so Claude reviews what matters most
6. **Claude reviews** — the diff is sent to Claude Code CLI with a customizable prompt
7. **Comment posted** — the review appears as a PR comment within 1–2 minutes
8. **Force-push handling** — previous reviews are collapsed under a `<details>` tag

### Smart diff truncation

Large PRs don't break the system. The agent intelligently drops files in this order:

1. Lockfiles (`package-lock.json`, `yarn.lock`, `Cargo.lock`, ...)
2. Generated/minified code (`.min.js`, `.pb.go`, ...)
3. Snapshots, SVGs, vendored code
4. Remaining files by size (largest first)

A note is added to the review listing which files were omitted.

---

## Customization

### Change what Claude reviews

Edit `src/prompt.md`. This is the prompt template sent to Claude with every review. The default focuses on correctness, security, performance, and actionable suggestions — but you can tune it for your team's priorities.

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
  agent.py               # Webhook listener + review logic (~340 lines)
  prompt.md              # Review prompt template — edit this!
scripts/
  provision.py           # One-command server provisioning
  destroy.py             # Clean teardown of all resources
  status.py              # Health + status checks
  build.py               # Assembles cloud-init.yaml from template
infra/
  cloud-init.tmpl.yaml   # Server provisioning template
  Caddyfile.origin-ca    # TLS config for custom domain setup
tests/
  test_agent.py          # Unit tests
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

# Authenticate GitHub CLI
sudo -u review gh auth login

# Authenticate Claude Code
sudo -u review claude

# Start the agent
systemctl start pr-review

# Verify
curl http://localhost:8080/health
# → {"status":"healthy"}
```

### 5. Create the GitHub webhook

1. GitHub org → **Settings → Webhooks → Add webhook**
2. **Payload URL:** `https://<your-hostname>/webhook`
3. **Content type:** `application/json`
4. **Secret:** your `GITHUB_WEBHOOK_SECRET` from `.env`
5. **Events:** Pull requests only

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
| `just provision` | Create server + tunnel + webhook (fully automated) |
| `just status` | Check server health and status |
| `just deploy root@host` | Push code changes to a running server |
| `just build` | Assemble cloud-init.yaml from template |
| `just test` | Run unit tests |
| `just setup-tls host cert key` | Configure Origin CA TLS |
| `just destroy yes` | Tear down server + tunnel + webhook + DNS |
| `just clean` | Remove built cloud-init.yaml |

---

## Troubleshooting

| Problem | Fix |
|---------|-----|
| Webhook returns 404 | The agent only responds to `POST /webhook` and `GET /health` |
| Agent won't start | `journalctl -u pr-review --no-pager -n 30` — usually a missing env var |
| Claude auth errors | `sudo -u review claude` to re-authenticate, then `systemctl restart pr-review` |
| Reviews aren't posting | Verify gh access: `sudo -u review gh pr list --repo your-org/some-repo` |
| Tunnel not connecting | `systemctl status cloudflared` and check Cloudflare Zero Trust dashboard |

---

## Prerequisites

- [**just**](https://github.com/casey/just) command runner
- [**uv**](https://docs.astral.sh/uv/) (for running scripts and tests)
- A **Claude Code subscription** (Pro or Max)
- A **Hetzner Cloud** account (or any VPS — adjust cloud-init as needed)
- A **Cloudflare** account (free tier works)
- A **GitHub org** with permission to create org-level webhooks

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
