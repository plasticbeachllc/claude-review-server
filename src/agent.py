#!/usr/bin/env python3
"""GitHub PR Review Agent — webhook listener + Claude CLI reviewer."""

import hashlib
import hmac
import json
import logging
import os
import re
import signal
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
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
WEBHOOK_SECRET = os.environ["GITHUB_WEBHOOK_SECRET"]  # tests must set before import
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


# ── Per-PR review state (generation tracking + process handle) ───
@dataclass
class _PRReviewState:
    generation: int = 0
    process: subprocess.Popen | None = None

_review_state: dict[str, _PRReviewState] = {}
_review_state_lock = threading.Lock()
_shutting_down = threading.Event()

# Regex for extracting the filename from "diff --git a/path b/path"
DIFF_HEADER_RE = re.compile(r"^diff --git a/(.*) b/(.*)$")

# ── Generation tracking ────────────────────────────────

def _bump_generation(pr_key: str) -> int:
    """Increment the generation counter for a PR; kill any in-flight Claude process."""
    with _review_state_lock:
        state = _review_state.get(pr_key)
        if state is None:
            state = _PRReviewState(generation=1)
            _review_state[pr_key] = state
            return 1

        state.generation += 1
        gen = state.generation
        proc = state.process
        state.process = None

    # Kill outside the lock to avoid holding it during process teardown.
    if proc is not None:
        log.info(f"Killing superseded review for {pr_key} (gen {gen - 1})")
        try:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
        except OSError:
            pass  # already dead

    return gen


def _is_current(pr_key: str, generation: int) -> bool:
    """Return True if *generation* is still the latest for this PR."""
    if _shutting_down.is_set():
        return False
    with _review_state_lock:
        state = _review_state.get(pr_key)
        return state is not None and state.generation == generation


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


def review_pr(
    repo: str,
    pr_number: int,
    pr_title: str,
    action: str,
    pr_key: str,
    generation: int,
):
    """Fetch diff, invoke Claude, post review comment.

    Bails out early if a newer generation supersedes this one (i.e. a new
    push arrived while we were working).
    """
    log.info(f"Reviewing {pr_key}: {pr_title} ({action}) [gen={generation}]")
    try:
        if action == "opened" and already_reviewed(repo, pr_number):
            log.info(f"Already reviewed {pr_key}, skipping")
            return

        # Collapse old reviews on force-push
        if action == "synchronize":
            collapse_old_reviews(repo, pr_number)

        # ── Check before diff fetch ──
        if not _is_current(pr_key, generation):
            log.info(f"Superseded before diff fetch {pr_key} gen={generation}")
            return

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
            log.warning(f"Empty diff for {pr_key}")
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

        # ── Check before Claude invocation (the expensive step) ──
        if not _is_current(pr_key, generation):
            log.info(f"Superseded before Claude call {pr_key} gen={generation}")
            return

        # Use Popen so the webhook handler can kill us mid-flight.
        proc = subprocess.Popen(
            ["claude", "-p", prompt, "--output-format", "text"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            cwd=str(WORKDIR),
        )

        # Register process so _bump_generation can kill it.
        with _review_state_lock:
            state = _review_state.get(pr_key)
            if state is not None and state.generation == generation:
                state.process = proc
            else:
                # Already superseded between the check above and now.
                proc.kill()
                proc.wait()
                return

        try:
            stdout, stderr = proc.communicate(timeout=300)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
            log.error(f"Claude timed out for {pr_key}")
            return
        finally:
            # Unregister process handle.
            with _review_state_lock:
                state = _review_state.get(pr_key)
                if state is not None and state.process is proc:
                    state.process = None

        if proc.returncode != 0:
            # returncode < 0 means killed by signal (i.e. we cancelled it).
            if proc.returncode < 0:
                log.info(f"Claude killed (signal {-proc.returncode}) for {pr_key}")
                return
            log.error(f"claude failed (exit {proc.returncode}): {stderr}")
            return

        review_text = stdout.strip()
        if not review_text:
            log.warning("Empty review output")
            return

        # ── Final check before posting ──
        if not _is_current(pr_key, generation):
            log.info(f"Superseded before posting {pr_key} gen={generation}")
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

        log.info(f"Posted review for {pr_key} [gen={generation}]")

    except subprocess.TimeoutExpired:
        log.error(f"Timeout reviewing {pr_key}")
    except Exception as e:
        log.error(f"Error reviewing {pr_key}: {e}", exc_info=True)


# ── HTTP handler ────────────────────────────────────────

class WebhookHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path != "/webhook":
            self.send_response(404)
            self.end_headers()
            return

        length = int(self.headers.get("Content-Length", 0))
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

        repo = data["repository"]["full_name"]
        pr_number = pr["number"]
        pr_key = f"{repo}#{pr_number}"
        generation = _bump_generation(pr_key)

        executor.submit(
            review_pr, repo, pr_number, pr["title"], action,
            pr_key, generation,
        )

    def do_GET(self):
        if self.path == "/health":
            self.send_response(200)
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

    def _shutdown(signum, _frame):
        name = signal.Signals(signum).name
        log.info(f"Received {name}, shutting down…")

        def _do_shutdown():
            _shutting_down.set()
            # Kill any in-flight Claude processes.
            with _review_state_lock:
                for state in _review_state.values():
                    if state.process is not None:
                        try:
                            state.process.kill()
                        except OSError:
                            pass
            server.shutdown()
            executor.shutdown(wait=True, cancel_futures=False)

        # Run in a thread to avoid blocking the signal handler.
        threading.Thread(target=_do_shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)

    log.info(f"PR Review Agent listening on 127.0.0.1:{port} "
             f"(workers={MAX_WORKERS})")
    server.serve_forever()
