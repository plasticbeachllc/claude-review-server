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
from urllib.parse import quote

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
MAX_FILE_CHARS = int(os.environ.get("MAX_FILE_CHARS", "80000"))
DEBOUNCE_SECONDS = int(os.environ.get("DEBOUNCE_SECONDS", "10"))
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
    r"(package-lock|yarn\.lock|pnpm-lock|Cargo\.lock|go\.sum|composer\.lock|"
    r"uv\.lock|poetry\.lock|Pipfile\.lock|Gemfile\.lock|bun\.lockb)",
    r"\.(generated|min)\.(js|css|ts)$",
    r"__snapshots__/",
    r"\.svg$",
    r"vendor/",
    r"\.pb\.go$",
]

executor = ThreadPoolExecutor(max_workers=MAX_WORKERS)
PORT = int(os.environ.get("PORT", "8080"))
MAX_COMMENT_CHARS = 65_000  # GitHub comment limit is 65536


# ── Per-PR review state (generation tracking + process handle) ───
@dataclass
class _PRReviewState:
    generation: int = 0
    process: subprocess.Popen | None = None
    timer: threading.Timer | None = None

_review_state: dict[str, _PRReviewState] = {}
_review_state_lock = threading.Lock()
_shutting_down = threading.Event()

# Regex for extracting the filename from "diff --git a/path b/path"
DIFF_HEADER_RE = re.compile(r"^diff --git a/(.*) b/(.*)$")

# ── Generation tracking ────────────────────────────────

def _bump_generation(pr_key: str) -> int:
    """Increment the generation counter for a PR.

    Cancels any pending debounce timer and sends SIGTERM to any running
    Claude process.  We intentionally do NOT call proc.wait() here —
    the communicate() call in review_pr is the single authoritative wait.
    """
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
        timer = state.timer
        state.timer = None

    # Cancel pending debounce timer.
    if timer is not None:
        timer.cancel()

    # Signal process to exit; communicate() in review_pr handles the wait.
    if proc is not None:
        log.info(f"Killing superseded review for {pr_key} (gen {gen - 1})")
        try:
            proc.terminate()
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


def _schedule_review(
    pr_key: str, delay: float,
    repo: str, pr_number: int, title: str, action: str, generation: int,
):
    """Start a timer that submits review_pr after *delay* seconds.

    The timer is registered in _review_state so that _bump_generation can
    cancel it if a new push arrives before the timer fires.
    """
    def _submit():
        if _is_current(pr_key, generation):
            executor.submit(
                review_pr, repo, pr_number, title, action,
                pr_key, generation,
            )

    timer = threading.Timer(delay, _submit)
    with _review_state_lock:
        state = _review_state.get(pr_key)
        if state is not None and state.generation == generation:
            state.timer = timer
    timer.start()


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


def extract_diff_filenames(diff: str) -> list[str]:
    """Extract unique filenames from a unified diff, excluding deleted files."""
    filenames: list[str] = []
    lines = diff.splitlines()
    i = 0
    while i < len(lines):
        m = DIFF_HEADER_RE.match(lines[i])
        if m:
            filename = m.group(2)
            # Check next few lines for "deleted file mode" or "+++ /dev/null"
            is_deleted = False
            for j in range(i + 1, min(i + 6, len(lines))):
                if lines[j].startswith("diff --git"):
                    break
                if "deleted file mode" in lines[j] or lines[j] == "+++ /dev/null":
                    is_deleted = True
                    break
            if not is_deleted and filename not in filenames:
                filenames.append(filename)
        i += 1
    return filenames


def format_file_contents(
    files: list[tuple[str, str]], max_chars: int = 80_000,
) -> tuple[str, str]:
    """Format file contents with priority-based truncation.

    Returns (formatted_contents, truncation_note).

    Note: the is_low_priority sort is intentionally kept even though
    fetch_file_contents already filters low-priority files. This makes
    format_file_contents safe for standalone use with arbitrary inputs.
    """
    if not files:
        return "", ""

    # Sort: high-priority first, then smaller files first (defensive —
    # callers may pass unfiltered file lists)
    sorted_files = sorted(files, key=lambda x: (is_low_priority(x[0]), len(x[1])))

    kept: list[str] = []
    dropped: list[str] = []
    total = 0
    for name, content in sorted_files:
        entry = f"### {name}\n~~~\n{content}\n~~~\n"
        if total + len(entry) <= max_chars:
            kept.append(entry)
            total += len(entry)
        else:
            dropped.append(name)

    note = ""
    if dropped:
        note = (
            f"({len(dropped)} file(s) contents omitted: "
            f"{', '.join(dropped[:10])}"
            f"{'...' if len(dropped) > 10 else ''})"
        )

    return "".join(kept), note


def fetch_file_contents(
    repo: str, head_sha: str, filenames: list[str],
) -> list[tuple[str, str]]:
    """Fetch full file contents from the PR head ref via GitHub API.

    Skips low-priority, binary, and oversized (>50 KB) files.
    Fetches at most 15 files to limit API calls.
    """
    if not re.fullmatch(r"[\w.-]+/[\w.-]+", repo):
        log.warning(f"Invalid repo format: {repo!r}")
        return []
    if not re.fullmatch(r"[0-9a-f]{40}", head_sha):
        log.warning(f"Invalid head SHA format: {head_sha!r}")
        return []

    targets = [f for f in filenames if not is_low_priority(f)][:15]
    files: list[tuple[str, str]] = []

    for filename in targets:
        encoded_path = quote(filename, safe="/")
        # capture_output without text=True is intentional: we need raw
        # bytes to detect binary content (null-byte check) before
        # decoding as UTF-8.
        result = subprocess.run(
            ["gh", "api",
             f"repos/{repo}/contents/{encoded_path}?ref={head_sha}",
             "-H", "Accept: application/vnd.github.raw+json"],
            capture_output=True, timeout=30,
        )
        if result.returncode != 0:
            log.debug(f"Failed to fetch {filename} (rc={result.returncode})")
            continue
        # Decode as UTF-8; null bytes are a strong binary signal
        content = result.stdout.decode("utf-8", errors="replace")
        if not content:
            log.debug(f"Skipping empty file: {filename}")
            continue
        if "\x00" in content[:8192]:
            log.debug(f"Skipping binary file: {filename}")
            continue
        if len(content) > 50_000:
            log.debug(f"Skipping oversized file ({len(content)} chars): {filename}")
            continue
        files.append((filename, content))

    return files


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
    # Use @json on each object to guarantee one JSON object per line,
    # even when comment bodies contain literal newlines.
    result = subprocess.run(
        ["gh", "api",
         f"/repos/{repo}/issues/{pr_number}/comments",
         "--paginate", "--jq",
         '.[] | select(.body | contains("<!-- claude-review -->")) '
         '| select(.body | contains("<details>") | not) '
         '| {id: .id, body: .body} | @json'],
        capture_output=True, text=True, timeout=30,
    )
    if result.returncode != 0 or not result.stdout.strip():
        return

    for line in result.stdout.strip().splitlines():
        try:
            # @json double-encodes: the outer json.loads unwraps the string
            # envelope, the inner one parses the actual object.  We use @json
            # because `gh api --jq` pretty-prints objects by default (spanning
            # multiple lines), which breaks splitlines() iteration.
            comment = json.loads(json.loads(line))
            comment_id = comment.get("id")
            old_body = comment.get("body")
        except (json.JSONDecodeError, AttributeError, TypeError):
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

        # ── Check before any work (avoids wasted API calls) ──
        if not _is_current(pr_key, generation):
            log.info(f"Superseded before start {pr_key} gen={generation}")
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

        # Fetch PR metadata (body + head SHA) in one call
        pr_info_result = subprocess.run(
            ["gh", "pr", "view", str(pr_number), "--repo", repo,
             "--json", "body,headRefOid"],
            capture_output=True, text=True, timeout=30,
        )
        pr_body = ""
        head_sha = ""
        if pr_info_result.returncode == 0:
            try:
                pr_info = json.loads(pr_info_result.stdout)
                pr_body = pr_info.get("body", "").strip()
                head_sha = pr_info.get("headRefOid", "")
            except (json.JSONDecodeError, AttributeError):
                pass

        diff, truncation_note = smart_truncate_diff(diff_result.stdout)

        if not diff.strip():
            log.warning(f"Empty diff for {pr_key}")
            return

        # Fetch full contents of changed files for richer context
        file_section = ""
        if head_sha:
            filenames = extract_diff_filenames(diff_result.stdout)
            fetchable = [f for f in filenames if not is_low_priority(f)]
            raw_files = fetch_file_contents(repo, head_sha, fetchable)
            file_contents_str, file_note = format_file_contents(
                raw_files, max_chars=MAX_FILE_CHARS,
            )
            # Surface the 15-file fetch cap if it was hit
            notes = []
            capped = len(fetchable) - 15
            if capped > 0:
                names = ", ".join(fetchable[15:25])
                suffix = "..." if capped > 10 else ""
                notes.append(
                    f"({capped} file(s) exceeded 15-file fetch limit: "
                    f"{names}{suffix})"
                )
            if file_note:
                notes.append(file_note)

            if file_contents_str:
                parts = ["Full contents of changed files for context:"]
                parts.extend(notes)
                parts.append(file_contents_str)
                file_section = "\n\n".join(parts)

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
            file_contents=esc(file_section),
            diff=esc(diff),
        )
        # Collapse runs of blank lines left by empty placeholders
        prompt = re.sub(r"\n{3,}", "\n\n", prompt)

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
        footer = "\n\n---\n*Automated review by Claude Code*"

        # Truncate if review would exceed GitHub's comment size limit
        overhead = len(f"{REVIEW_MARKER}\n## {header}\n\n") + len(footer)
        max_review = MAX_COMMENT_CHARS - overhead
        if len(review_text) > max_review:
            truncation_msg = "\n\n*(Review truncated — exceeded GitHub comment size limit)*"
            review_text = review_text[:max_review - len(truncation_msg)] + truncation_msg
            log.warning(f"Truncated review for {pr_key} to fit comment limit")

        comment = (
            f"{REVIEW_MARKER}\n"
            f"## {header}\n\n"
            f"{review_text}"
            f"{footer}"
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
    finally:
        # Prune state entry to prevent unbounded memory growth.
        with _review_state_lock:
            state = _review_state.get(pr_key)
            if (state is not None
                    and state.generation == generation
                    and state.process is None
                    and state.timer is None):
                del _review_state[pr_key]


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
            body = b'{"error":"invalid Content-Length"}'
            self.send_response(400)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if length > 5_000_000:  # 5 MB sanity limit
            log.warning(f"Payload too large ({length} bytes) from {self.client_address[0]}")
            body = b'{"error":"payload too large"}'
            self.send_response(413)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        payload = self.rfile.read(length)
        signature = self.headers.get("X-Hub-Signature-256", "")

        if not verify_signature(payload, signature):
            log.warning(f"Invalid signature from {self.client_address[0]}")
            body = b'{"error":"invalid signature"}'
            self.send_response(403)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        body = b'{"ok":true}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

        event = self.headers.get("X-GitHub-Event", "")
        if event != "pull_request":
            return

        try:
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

            delay = 0 if action == "opened" else DEBOUNCE_SECONDS
            _schedule_review(
                pr_key, delay,
                repo, pr_number, pr["title"], action, generation,
            )
        except (json.JSONDecodeError, KeyError, TypeError) as e:
            log.error(f"Malformed webhook payload: {e}")

    def do_GET(self):
        if self.path == "/health":
            body = b'{"status":"healthy"}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, fmt, *args):
        log.info(f"{self.client_address[0]} {fmt % args}")


_shutdown_thread: threading.Thread | None = None  # set by _shutdown()

if __name__ == "__main__":
    WORKDIR.mkdir(parents=True, exist_ok=True)
    server = HTTPServer(("127.0.0.1", PORT), WebhookHandler)

    def _do_shutdown():
        """Perform blocking shutdown work off the signal handler thread."""
        if _shutting_down.is_set():
            return  # guard against double-signal
        _shutting_down.set()
        # Collect processes and timers under the lock, act outside it.
        with _review_state_lock:
            timers = [s.timer for s in _review_state.values()
                      if s.timer is not None]
            procs = [s.process for s in _review_state.values()
                     if s.process is not None]
        for timer in timers:
            timer.cancel()
        for proc in procs:
            try:
                proc.terminate()  # graceful SIGTERM; communicate() handles wait
            except OSError:
                pass
        server.shutdown()
        executor.shutdown(wait=True, cancel_futures=False)

    def _shutdown(signum, _frame):
        global _shutdown_thread
        log.info(f"Received {signal.Signals(signum).name}, shutting down...")
        _shutdown_thread = threading.Thread(target=_do_shutdown)
        _shutdown_thread.start()

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)

    log.info(f"PR Review Agent listening on 127.0.0.1:{PORT} "
             f"(workers={MAX_WORKERS})")
    server.serve_forever()

    # Join the shutdown thread so in-flight reviews finish before exit.
    if _shutdown_thread is not None:
        _shutdown_thread.join()
