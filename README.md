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

## Prerequisites

Install these on your local machine before starting:

- [**just**](https://github.com/casey/just) — command runner (`brew install just` / `cargo install just`)
- [**uv**](https://docs.astral.sh/uv/) — Python package manager (`curl -LsSf https://astral.sh/uv/install.sh | sh`)
- **Python 3.10+** (`python3 --version` to check)
- An **SSH key** — see [SSH key setup](#ssh-key-setup) below

You also need accounts with:

- [**Hetzner Cloud**](https://console.hetzner.cloud/) (server hosting, ~$4/mo)
- [**Cloudflare**](https://dash.cloudflare.com/) (tunnel + DNS, free tier works)
- [**GitHub**](https://github.com/) org with admin access (to create and install a GitHub App)
- A **Claude Code subscription** (Pro or Max)

### SSH key setup

The provisioning script needs your SSH public key to upload to Hetzner. Without any configuration it auto-discovers keys in this order:

1. `~/.ssh/id_ed25519.pub`, `~/.ssh/id_ecdsa.pub`, or `~/.ssh/id_rsa.pub` (standard files)
2. The default SSH agent (`SSH_AUTH_SOCK`)
3. Any `IdentityAgent` configured in `~/.ssh/config` (1Password, Secretive, etc.)

If you have multiple keys or want explicit control, set `SSH_KEY` in `.env`:

```env
# Point to a specific .pub file:
SSH_KEY=~/.ssh/my_hetzner_key.pub

# Or match a 1Password / agent key by its comment:
SSH_KEY=Hetzner - GitHub Webhooks
```

**If you have a standard SSH key** — you're all set, no action needed. Verify with:

```bash
ls ~/.ssh/id_*.pub
```

To use a specific key instead of the default, set `SSH_KEY` to its path:

```env
SSH_KEY=~/.ssh/id_ed25519.pub
```

**If you don't have an SSH key yet** — generate one:

```bash
ssh-keygen -t ed25519 -C "your-email@example.com"
```

Accept the default path (`~/.ssh/id_ed25519`). A passphrase is optional.

**If you use 1Password SSH agent** — it works automatically. The provisioning script reads the `IdentityAgent` directive from your `~/.ssh/config` and queries the 1Password agent socket directly. No `.pub` files needed.

If you have multiple keys in 1Password, set `SSH_KEY` to the key's comment (the name shown in 1Password) to select the right one:

```env
SSH_KEY=Hetzner - GitHub Webhooks
```

To see which keys are available, run:

```bash
SSH_AUTH_SOCK="$HOME/Library/Group Containers/2BUA8C4S2C.com.1password/t/agent.sock" ssh-add -L
```

The comment is the third field on each line (e.g. `ssh-ed25519 AAAA... Hetzner - GitHub Webhooks`). If this says "The agent has no identities", enable the SSH agent in 1Password → Settings → Developer → SSH Agent.

---

## Runbook

### Step 1: Clone and configure `.env`

```bash
git clone https://github.com/plasticbeachllc/claude-review-server.git
cd claude-review-server
cp .env.example .env
```

Open `.env` in your editor. You need to fill in **7 values manually** — the rest are either defaults or auto-populated later. Here is exactly where to find each one:

#### `HCLOUD_TOKEN`

1. Go to [Hetzner Cloud Console](https://console.hetzner.cloud/)
2. Select your project (or create one)
3. Left sidebar → **Security** → **API Tokens**
4. Click **Generate API Token**, name it anything, select **Read & Write**
5. Copy the token — it's only shown once

#### `CLAUDE_CODE_OAUTH_TOKEN`

1. Open a terminal and run:
   ```bash
   claude setup-token
   ```
2. Follow the prompts — this outputs a token string
3. Copy the full token string into `.env`

#### `CF_API_TOKEN`

1. Go to [Cloudflare API Tokens](https://dash.cloudflare.com/profile/api-tokens)
2. Click **Create Token**
3. Use **Create Custom Token** (not a template)
4. Add two permissions:
   - **Zone** → **DNS** → **Edit**
   - **Account** → **Cloudflare Tunnel** → **Edit**
5. Under Zone Resources, select **Include** → **Specific zone** → pick your domain
6. Click **Continue to summary** → **Create Token**
7. Copy the token — it's only shown once

#### `CF_ACCOUNT_ID`

1. Go to [Cloudflare Dashboard](https://dash.cloudflare.com/)
2. Click on any domain you own
3. The **Account ID** is in the right sidebar under **API**
4. Copy it

#### `CF_ZONE_ID`

1. Same page as Account ID (your domain's Overview page)
2. The **Zone ID** is in the right sidebar under **API**, directly below Account ID
3. Copy it

#### `TUNNEL_HOSTNAME`

Choose the public hostname for your review agent. This must be a subdomain of the domain you selected in the Cloudflare token setup.

Example: if your domain is `example.com`, set this to `pr-review.example.com`.

#### `GITHUB_ORG`

Your GitHub organization name exactly as it appears in the URL. For `github.com/my-org`, set this to `my-org`.

#### What your `.env` should look like after this step

```env
# ── Runtime ──────────────────────────────────────
REVIEW_WORKDIR=/opt/pr-review/workspace          # leave as-is
MAX_WORKERS=4                                     # leave as-is
PORT=8080                                         # leave as-is

# ── Hetzner Cloud ────────────────────────────────
HCLOUD_TOKEN=aBcDeFgHiJkLmNoPqRsTuVwXyZ...       # ← you filled this in
SERVER_NAME=pr-review                             # leave as-is
SERVER_TYPE=cax11                                 # leave as-is
SERVER_LOCATION=nbg1                              # leave as-is
SERVER_IMAGE=ubuntu-24.04                         # leave as-is

# ── GitHub App (auto-populated by just create-app) ──
GH_APP_ID=                                        # ← auto-populated in Step 2
GH_APP_PRIVATE_KEY_FILE=github-app.pem            # ← auto-populated in Step 2
GH_INSTALLATION_ID=                               # ← auto-populated in Step 2
GITHUB_WEBHOOK_SECRET=                            # ← auto-populated in Step 2

# ── Claude Code ──────────────────────────────────
CLAUDE_CODE_OAUTH_TOKEN=eyJhb...                   # ← you filled this in

# ── Cloudflare ───────────────────────────────────
CF_API_TOKEN=aBcDeFgHiJkLmNoPqRsTuVwXyZ...       # ← you filled this in
CF_ACCOUNT_ID=abc123def456...                     # ← you filled this in
CF_ZONE_ID=789ghi012jkl...                        # ← you filled this in
TUNNEL_HOSTNAME=pr-review.example.com             # ← you filled this in

# ── GitHub ───────────────────────────────────────
GITHUB_ORG=my-org                                 # ← you filled this in
```

### Step 2: Create the GitHub App

```bash
just create-app
```

This is a one-time setup that:

1. Opens your browser to GitHub
2. You click **Create GitHub App** to approve
3. GitHub redirects back — the script captures the app credentials
4. Your browser opens again to install the app on your org — click **Install**
5. The script detects the installation and saves everything

When it finishes, your `.env` will have `GH_APP_ID`, `GH_INSTALLATION_ID`, and `GITHUB_WEBHOOK_SECRET` filled in, and a `github-app.pem` file will appear in your project root.

**Do not** manually edit these four values — they are managed by the script.

### Step 3: Run tests

```bash
just test
```

All tests should pass. If any fail, fix your `.env` and retry.

### Step 4: Provision the server

```bash
just provision
```

This takes 3–5 minutes and runs 8 automated stages:

1. Validates your `.env`
2. Builds `cloud-init.yaml` (embeds agent code into server config)
3. Finds or uploads your SSH key to Hetzner
4. Creates the Hetzner VM
5. Waits for the server to boot and finish setup
6. Injects your secrets (PEM, tokens) into the server securely
7. Creates a Cloudflare Tunnel + DNS record
8. Starts the review service

When it finishes, you'll see:

```
══════════════════════════════════════════════════════════════
  PROVISIONING COMPLETE

  Server:   pr-review (123.45.67.89)
  Webhook:  https://pr-review.example.com/webhook
  SSH:      ssh root@123.45.67.89
  Logs:     ssh root@123.45.67.89 journalctl -u pr-review -f
  Health:   ssh root@123.45.67.89 curl -s localhost:8081/health
══════════════════════════════════════════════════════════════
```

### Step 5: Verify it works

```bash
just status
```

This checks the server is running and the tunnel is reachable. Exit code 0 means healthy.

Then open a PR on any repo in your org. Within 1–3 minutes, a review comment should appear.

---

## Updating

### Push code changes (hot deploy)

After editing `src/agent.py` or `src/prompt.md` locally:

```bash
just deploy root@<server-ip>
```

This copies the files to the server, restarts the service, and takes effect immediately. No re-provisioning needed.

### Check server health

```bash
just status
```

### View logs

```bash
ssh root@<server-ip> journalctl -u pr-review -f
```

---

## Destroying

```bash
just destroy yes
```

This tears down all infrastructure in reverse order:

1. Deletes the DNS record from Cloudflare
2. Deletes the Cloudflare Tunnel
3. Deletes the Hetzner server

The GitHub App and SSH key are preserved. You can re-run `just provision` at any time to recreate the server without repeating `just create-app`.

### Verify teardown

- [Hetzner Console](https://console.hetzner.cloud/) → server should be gone
- [Cloudflare Dashboard](https://dash.cloudflare.com/) → tunnel and DNS record should be gone
- `just status` → should exit with code 3 (not found)

### Reprovision from scratch

```bash
just destroy yes && just provision
```

---

## How it works

1. **GitHub sends a webhook** when a PR is opened or updated
2. **Signature verification** — the agent validates the HMAC-SHA256 signature; forged requests are rejected
3. **Draft filtering** — draft PRs are skipped
4. **Diff retrieval** — fetches edited files using the GitHub CLI
5. **Full file context** — fetches complete contents of changed files via the GitHub API for richer review context
6. **Smart truncation** — if truncation is necessary to fit context, lockfiles and generated code are dropped first
7. **Claude reviews** — customizable prompt drives review mechanics
8. **Comment posted** — the review appears as a PR comment within 1–2 minutes
9. **Force-push handling** — prior reviews are collapsed under a `<details>` tag; ongoing reviews are restarted

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

Available template variables: `{pr_number}`, `{repo}`, `{pr_title}`, `{pr_body}`, `{truncation_note}`, `{file_contents}`, `{diff}`.

After editing, deploy with `just deploy root@<server-ip>`.

### Configuration

| Setting | Where | Default |
|---------|-------|---------|
| Review prompt | `src/prompt.md` | Correctness + security + performance |
| Concurrent reviews | `MAX_WORKERS` in `.env` | 4 |
| Diff size limit | `max_chars` in `smart_truncate_diff()` | 40,000 chars |
| File contents limit | `MAX_FILE_CHARS` in `.env` | 80,000 chars |
| Debounce delay | `DEBOUNCE_SECONDS` in `.env` | 10 seconds |
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
  test_status.py         # Status command tests
  conftest.py            # Pytest fixtures
Justfile                 # All commands: build, test, deploy, provision, destroy
.env.example             # Configuration template
```

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
#   CLAUDE_CODE_OAUTH_TOKEN=<from .env>

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

## Troubleshooting

| Problem | Fix |
|---------|-----|
| Webhook returns 404 | The agent only responds to `POST /webhook` and `GET /health` |
| Agent won't start | `journalctl -u pr-review --no-pager -n 30` — usually a missing env var |
| Claude auth errors | `sudo -u review claude` to re-authenticate, then `systemctl restart pr-review` |
| Reviews aren't posting | Check App credentials in `/opt/pr-review/.env` and PEM file permissions |
| Tunnel not connecting | `systemctl status cloudflared` and check Cloudflare Zero Trust dashboard |

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
