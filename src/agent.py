#!/usr/bin/env python3
"""GitHub PR Review Agent — webhook listener + Claude CLI reviewer."""

import hashlib
import hmac
import json
import logging
import os
import re
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path

# ── Structured JSON logging ──────────────────────────────
class JSONFormatter(logging.Formatter):
    def format(self, record):
        entry = {
            "ts": self.formatTime(record),
            "level": record.levelname,
            "msg": record.getMessage(),
        }
        if record.exc_info and record.exc_info[0]:
            entry["exc"] = self.formatException(record.exc_info)
        return json.dumps(entry)

handler = logging.StreamHandler(sys.stdout)
handler.setFormatter(JSONFormatter())
logging.root.handlers = [handler]
logging.root.setLevel(logging.INFO)
log = logging.getLogger("pr-review")

# ── Configuration ────────────────────────────────────────
try:
    WEBHOOK_SECRET = os.environ["GITHUB_WEBHOOK_SECRET"]
except KeyError:
    sys.exit("GITHUB_WEBHOOK_SECRET not set — add it to /opt/pr-review/.env")
WORKDIR = Path(os.environ.get("REVIEW_WORKDIR", "/opt/pr-review/workspace"))
MAX_WORKERS = int(os.environ.get("MAX_WORKERS", "4"))
REVIEW_MARKER = "<!-- claude-review -->"
SCRIPT_DIR = Path(__file__).resolve().parent
_prompt_template: str | None = None
_prompt_lock = threading.Lock()


def get_prompt_template() -> str:
    """Lazy-load the prompt template on first use (thread-safe)."""
    global _prompt_template
    if _prompt_template is None:
        with _prompt_lock:
            if _prompt_template is None:  # double-checked locking
                _prompt_template = (SCRIPT_DIR / "prompt.md").read_text()
    return _prompt_template

# Files to drop first when truncating large diffs
LOW_PRIORITY_PATTERNS = [
    r"(package-lock|yarn\.lock|pnpm-lock|Cargo\.lock|go\.sum|composer\.lock)",
    r"\.(generated|min)\.(js|css|ts)$",
    r"__snapshots__/",
    r"\.svg$",
    r"vendor/",
    r"\.pb\.go$",
]

executor = ThreadPoolExecutor(max_workers=MAX_WORKERS)

# Regex for extracting the filename from "diff --git a/path b/path"
DIFF_HEADER_RE = re.compile(r"^diff --git a/(.*) b/(.*)$")

# ── Helpers ─────────────────────────────────────────────

def verify_signature(payload: bytes, signature: str) -> bool:
    """Verify GitHub HMAC-SHA256 webhook signature."""
    if not signature.startswith("sha256="):
        return False
    expected = "sha256=" + hmac.new(
        WEBHOOK_SECRET.encode(), payload, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, signature)


def is_low_priority(filename: str) -> bool:
    """Check if a file matches low-priority patterns (lockfiles, generated, vendor, etc.)."""
    return any(re.search(p, filename) for p in LOW_PRIORITY_PATTERNS)


def smart_truncate_diff(diff: str, max_chars: int = 40_000) -> tuple[str, str]:
    """Truncate diff by dropping low-priority files first, then large files."""
    if len(diff) <= max_chars:
        return diff, ""

    # Split diff into per-file chunks
    file_diffs = []
    current = []
    current_name = ""
    for line in diff.splitlines(keepends=True):
        if line.startswith("diff --git"):
            if current:
                file_diffs.append((current_name, "".join(current)))
            current = [line]
            # Extract filename from "diff --git a/path b/path"
            m = DIFF_HEADER_RE.match(line.rstrip())
            current_name = m.group(2) if m else "unknown"
        else:
            current.append(line)
    if current:
        file_diffs.append((current_name, "".join(current)))

    # Sort: high-priority files first (is_low_priority=False sorts before True),
    # then by size ascending within each group (keep smaller files, drop bigger ones)
    file_diffs.sort(key=lambda x: (is_low_priority(x[0]), len(x[1])))

    kept = []
    dropped = []
    total = 0
    for name, content in file_diffs:
        if total + len(content) <= max_chars:
            kept.append(content)
            total += len(content)
        else:
            dropped.append(name)

    note = ""
    if dropped:
        note = (
            f"\n\n(Diff truncated for review. {len(dropped)} file(s) omitted: "
            f"{', '.join(dropped[:10])}"
            f"{'...' if len(dropped) > 10 else ''})"
        )
    return "".join(kept), note


def already_reviewed(repo: str, pr_number: int) -> bool:
    """Check if we already posted a review comment on this PR."""
    result = subprocess.run(
        ["gh", "pr", "view", str(pr_number), "--repo", repo,
         "--json", "comments", "--jq",
         '[.comments[].body | select(contains("<!-- claude-review -->"))] '
         '| length'],
        capture_output=True, text=True, timeout=30,
    )
    try:
        return int(result.stdout.strip()) > 0
    except (ValueError, AttributeError):
        return False


def collapse_old_reviews(repo: str, pr_number: int):
    """Edit previous review comments to collapse them under a <details> tag."""
    result = subprocess.run(
        ["gh", "api",
         f"/repos/{repo}/issues/{pr_number}/comments",
         "--paginate", "--jq",
         '.[] | select(.body | contains("<!-- claude-review -->")) '
         '| select(.body | contains("<details>") | not) '
         '| {id: .id, body: .body}'],
        capture_output=True, text=True, timeout=30,
    )
    if result.returncode != 0 or not result.stdout.strip():
        return

    for line in result.stdout.strip().splitlines():
        try:
            comment = json.loads(line)
            comment_id = comment.get("id")
            old_body = comment.get("body")
        except (json.JSONDecodeError, AttributeError):
            continue

        if not comment_id or not old_body:
            continue

        # Wrap in collapsed details
        collapsed = (
            f"{REVIEW_MARKER}\n"
            f"<details>\n<summary>Previous review (superseded)</summary>\n\n"
            f"{old_body.replace(REVIEW_MARKER, '').strip()}\n\n"
            f"</details>"
        )
        subprocess.run(
            ["gh", "api", "--method", "PATCH",
             f"/repos/{repo}/issues/comments/{comment_id}",
             "-f", f"body={collapsed}"],
            capture_output=True, timeout=30,
        )


def review_pr(repo: str, pr_number: int, pr_title: str, action: str):
    """Fetch diff, invoke Claude, post review comment."""
    log.info(f"Reviewing {repo}#{pr_number}: {pr_title} ({action})")
    try:
        if action == "opened" and already_reviewed(repo, pr_number):
            log.info(f"Already reviewed {repo}#{pr_number}, skipping")
            return

        # Collapse old reviews on force-push
        if action == "synchronize":
            collapse_old_reviews(repo, pr_number)

        diff_result = subprocess.run(
            ["gh", "pr", "diff", str(pr_number), "--repo", repo],
            capture_output=True, text=True, timeout=60,
        )
        if diff_result.returncode != 0:
            log.error(f"gh pr diff failed: {diff_result.stderr}")
            return

        body_result = subprocess.run(
            ["gh", "pr", "view", str(pr_number), "--repo", repo,
             "--json", "body", "--jq", ".body"],
            capture_output=True, text=True, timeout=30,
        )
        pr_body = body_result.stdout.strip() if body_result.returncode == 0 else ""

        diff, truncation_note = smart_truncate_diff(diff_result.stdout)

        if not diff.strip():
            log.warning(f"Empty diff for {repo}#{pr_number}")
            return

        # Escape braces in untrusted content so .format() doesn't choke
        # on diffs/bodies containing {variable_name} patterns.
        def esc(s: str) -> str:
            return s.replace("{", "{{").replace("}", "}}")

        prompt = get_prompt_template().format(
            pr_number=pr_number,
            repo=repo,
            pr_title=esc(pr_title),
            pr_body=esc(pr_body) or "(none)",
            truncation_note=truncation_note,
            diff=esc(diff),
        )

        result = subprocess.run(
            ["claude", "-p", prompt, "--output-format", "text"],
            capture_output=True, text=True, timeout=300,
            cwd=str(WORKDIR),
        )
        if result.returncode != 0:
            log.error(f"claude failed (exit {result.returncode}): {result.stderr}")
            return

        review_text = result.stdout.strip()
        if not review_text:
            log.warning("Empty review output")
            return

        header = "🔄 Updated Review" if action == "synchronize" else "📝 Review"
        comment = (
            f"{REVIEW_MARKER}\n"
            f"## {header}\n\n"
            f"{review_text}\n\n"
            f"---\n"
            f"*Automated review by Claude Code*"
        )

        post_result = subprocess.run(
            ["gh", "pr", "comment", str(pr_number), "--repo", repo,
             "--body", comment],
            capture_output=True, text=True, timeout=30,
        )
        if post_result.returncode != 0:
            log.error(f"Failed to post comment: {post_result.stderr}")
            return

        log.info(f"Posted review for {repo}#{pr_number}")

    except subprocess.TimeoutExpired:
        log.error(f"Timeout reviewing {repo}#{pr_number}")
    except Exception as e:
        log.error(f"Error reviewing {repo}#{pr_number}: {e}", exc_info=True)


# ── HTTP handler ────────────────────────────────────────

class WebhookHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path != "/webhook":
            self.send_response(404)
            self.end_headers()
            return

        try:
            length = int(self.headers.get("Content-Length", 0))
        except (ValueError, TypeError):
            self.send_response(400)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"error":"invalid Content-Length"}')
            return
        if length > 5_000_000:  # 5 MB sanity limit
            log.warning(f"Payload too large ({length} bytes) from {self.client_address[0]}")
            self.send_response(413)
            self.end_headers()
            return

        payload = self.rfile.read(length)
        signature = self.headers.get("X-Hub-Signature-256", "")

        if not verify_signature(payload, signature):
            log.warning(f"Invalid signature from {self.client_address[0]}")
            self.send_response(403)
            self.end_headers()
            return

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"ok":true}')

        event = self.headers.get("X-GitHub-Event", "")
        if event != "pull_request":
            return

        data = json.loads(payload)
        action = data.get("action")
        if action not in ("opened", "synchronize"):
            return

        pr = data["pull_request"]
        if pr.get("draft", False):
            log.info(f"Skipping draft PR #{pr['number']}")
            return

        executor.submit(
            review_pr,
            data["repository"]["full_name"],
            pr["number"],
            pr["title"],
            action,
        )

    def do_GET(self):
        if self.path == "/health":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"status":"healthy"}')
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, fmt, *args):
        log.info(f"{self.client_address[0]} {fmt % args}")


if __name__ == "__main__":
    WORKDIR.mkdir(parents=True, exist_ok=True)
    port = int(os.environ.get("PORT", "8080"))
    server = HTTPServer(("127.0.0.1", port), WebhookHandler)
    log.info(f"PR Review Agent listening on 127.0.0.1:{port} "
             f"(workers={MAX_WORKERS})")
    server.serve_forever()
