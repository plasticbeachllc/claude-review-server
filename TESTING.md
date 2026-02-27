# Manual Testing Plan — Pre-Release

Run through these phases in order before public release. Each checkbox is a pass/fail gate.

## Phase 0: Prerequisites

- [ ] `just`, `uv`, and `python3` (>=3.10) installed locally
- [ ] Hetzner Cloud account with API token
- [ ] Cloudflare account with: API token (Zone:DNS:Edit + Account:Cloudflare Tunnel:Edit), Account ID, Zone ID
- [ ] GitHub account (org or personal) with admin access
- [ ] Claude Code auth token (`claude setup-token`)
- [ ] SSH key pair in `~/.ssh/`

## Phase 1: Local Build & Test

- [ ] `cp .env.example .env` and fill in all values
- [ ] `just test` — all tests pass
- [ ] `just build` — produces `cloud-init.yaml` without errors
- [ ] `just validate` — cloud-init schema validates (if cloud-init CLI installed locally)
- [ ] Inspect `cloud-init.yaml`: no `{{FILE:...}}` markers remain, agent code is embedded

## Phase 2: Automated Provisioning

- [ ] `just provision` — completes all 8 stages without error
- [ ] Output shows server IP, webhook URL, SSH command, health endpoint
- [ ] SSH into server works: `ssh root@<ip>`
- [ ] On server: `systemctl is-active pr-review` returns `active`
- [ ] On server: `systemctl is-active caddy` returns `active`
- [ ] On server: `systemctl is-active cloudflared` returns `active`
- [ ] On server: `curl -s localhost:8080/health` returns `{"status":"healthy"}`
- [ ] On server: `curl -s localhost:8081/health` returns `{"status":"healthy"}` (Caddy internal health port)
- [ ] On server: `sudo -u review gh auth status` shows authenticated
- [ ] On server: `/opt/pr-review/.env` contains `CLAUDE_CODE_OAUTH_TOKEN=...`
- [ ] On server: `/opt/pr-review/.env` has `chmod 600` and owned by `review:review`

## Phase 3: External Connectivity

- [ ] `just status` — shows server running and healthy, tunnel reachable (exit code 0)
- [ ] `curl https://<tunnel-hostname>/health` returns `{"status":"healthy"}`
- [ ] `curl -X POST https://<tunnel-hostname>/webhook` returns 403 (no signature)

## Phase 4: End-to-End PR Review

- [ ] Open a new PR on any repo where the app is installed
- [ ] Check GitHub webhook Recent Deliveries — should show 200 response
- [ ] Within 1–3 minutes, a review comment appears on the PR
- [ ] Comment has `<!-- claude-review -->` marker (view raw source)
- [ ] Comment header says "Review"

## Phase 5: Force-Push / Synchronize

- [ ] Amend and force-push to the same PR branch
- [ ] GitHub webhook delivers a `synchronize` event — 200 response
- [ ] Previous review comment gets collapsed under `<details>` tag
- [ ] New review comment appears with "Updated Review" header
- [ ] New review reflects the updated diff

## Phase 6: Edge Cases

- [ ] Open a **draft** PR — agent should skip it (check logs: `journalctl -u pr-review -f`)
- [ ] Open a PR with a very large diff (>40k chars) — truncation note appears in review, lockfiles/generated code dropped first
- [ ] Send a webhook with an invalid signature — 403 response, warning in logs
- [ ] Send a non-pull_request event (e.g. push) — 200 response, no review posted

## Phase 7: Hot Deploy

- [ ] Edit `src/prompt.md` locally (e.g. add "Be extra thorough")
- [ ] `just deploy root@<ip>` — deploys and restarts
- [ ] On server: `systemctl is-active pr-review` returns `active`
- [ ] Open a new PR — review reflects the updated prompt

## Phase 8: Service Resilience

- [ ] On server: `systemctl restart pr-review` — service comes back up
- [ ] On server: `kill -TERM <agent-pid>` — process exits cleanly (check `journalctl` for "shutting down" log)
- [ ] On server: `systemctl stop pr-review && systemctl start pr-review` — service restarts cleanly
- [ ] `just status` — reports healthy after restart

## Phase 9: Idempotency

- [ ] Run `just provision` again — should fail with "Server already exists" (not create duplicates)
- [ ] Destroy and reprovision: `just destroy yes && just provision` — full cycle works, webhook/tunnel/DNS cleaned and recreated

## Phase 10: Teardown

- [ ] `just destroy yes` — deletes webhook, DNS record, tunnel, server
- [ ] Verify in Hetzner console: server gone
- [ ] Verify in Cloudflare dashboard: tunnel gone, DNS record gone
- [ ] Verify in GitHub account settings: webhook gone
- [ ] `just status` — exits with code 3 (not found)

## Phase 11: Manual Setup Path (Optional)

For users who don't want fully automated provisioning:

- [ ] Create server manually via Hetzner console with built `cloud-init.yaml`
- [ ] Wait for cloud-init to finish (3–5 min)
- [ ] Set up Cloudflare Tunnel manually per README instructions
- [ ] Authenticate `gh` and `claude` manually per README step 6
- [ ] Create webhook manually per README step 7
- [ ] Start service and verify health
