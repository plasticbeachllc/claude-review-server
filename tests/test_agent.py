"""Tests for agent.py core functions."""

import hashlib
import hmac
import json
import os
import subprocess
from http.server import HTTPServer
from threading import Thread
from unittest.mock import patch

import pytest

# Set required env var before importing agent
os.environ.setdefault("GITHUB_WEBHOOK_SECRET", "test-secret-key")

from agent import (
    REVIEW_MARKER,
    WebhookHandler,
    already_reviewed,
    collapse_old_reviews,
    is_low_priority,
    review_pr,
    smart_truncate_diff,
    verify_signature,
)


# ── verify_signature ─────────────────────────────────────


class TestVerifySignature:
    SECRET = "test-secret-key"

    def _sign(self, payload: bytes) -> str:
        return "sha256=" + hmac.new(
            self.SECRET.encode(), payload, hashlib.sha256
        ).hexdigest()

    def test_valid_signature(self):
        payload = b'{"action":"opened"}'
        sig = self._sign(payload)
        assert verify_signature(payload, sig) is True

    def test_invalid_signature(self):
        payload = b'{"action":"opened"}'
        assert verify_signature(payload, "sha256=badhex") is False

    def test_missing_prefix(self):
        payload = b'{"action":"opened"}'
        raw = hmac.new(
            self.SECRET.encode(), payload, hashlib.sha256
        ).hexdigest()
        assert verify_signature(payload, raw) is False

    def test_empty_signature(self):
        assert verify_signature(b"hello", "") is False

    def test_tampered_payload(self):
        payload = b'{"action":"opened"}'
        sig = self._sign(payload)
        assert verify_signature(b'{"action":"closed"}', sig) is False


# ── is_low_priority ──────────────────────────────────────


class TestIsLowPriority:
    @pytest.mark.parametrize(
        "filename",
        [
            "package-lock.json",
            "yarn.lock",
            "pnpm-lock.yaml",
            "Cargo.lock",
            "go.sum",
            "composer.lock",
            "dist/bundle.min.js",
            "styles/app.min.css",
            "src/__snapshots__/App.test.tsx.snap",
            "icons/logo.svg",
            "vendor/github.com/lib/pq/conn.go",
            "proto/api.pb.go",
        ],
    )
    def test_low_priority_files(self, filename):
        assert is_low_priority(filename) is True

    @pytest.mark.parametrize(
        "filename",
        [
            "src/main.py",
            "lib/auth.ts",
            "README.md",
            "Dockerfile",
            "agent.py",
            "tests/test_handler.py",
            ".github/workflows/ci.yml",
        ],
    )
    def test_high_priority_files(self, filename):
        assert is_low_priority(filename) is False


# ── smart_truncate_diff ──────────────────────────────────


def _make_diff(files: dict[str, int]) -> str:
    """Build a fake diff with files of given sizes (in chars of content)."""
    parts = []
    for name, size in files.items():
        header = f"diff --git a/{name} b/{name}\n"
        body = "+" + "x" * (size - len(header) - 2) + "\n"
        parts.append(header + body)
    return "".join(parts)


class TestSmartTruncateDiff:
    def test_small_diff_unchanged(self):
        diff = _make_diff({"src/main.py": 100})
        result, note = smart_truncate_diff(diff, max_chars=1000)
        assert result == diff
        assert note == ""

    def test_drops_low_priority_first(self):
        diff = _make_diff({
            "src/main.py": 500,
            "package-lock.json": 500,
        })
        result, note = smart_truncate_diff(diff, max_chars=600)
        assert "src/main.py" in result
        assert "package-lock.json" not in result
        assert "1 file(s) omitted" in note
        assert "package-lock.json" in note

    def test_drops_larger_files_first_within_same_priority(self):
        diff = _make_diff({
            "src/small.py": 100,
            "src/medium.py": 300,
            "src/large.py": 600,
        })
        result, note = smart_truncate_diff(diff, max_chars=500)
        assert "src/small.py" in result
        assert "src/medium.py" in result
        assert "src/large.py" not in result

    def test_truncation_note_lists_dropped_files(self):
        diff = _make_diff({
            "a.py": 100,
            "b.py": 200,
            "c.py": 300,
        })
        _, note = smart_truncate_diff(diff, max_chars=150)
        assert "omitted" in note

    def test_truncation_note_caps_at_10_names(self):
        files = {f"file{i}.py": 100 for i in range(15)}
        diff = _make_diff(files)
        _, note = smart_truncate_diff(diff, max_chars=200)
        assert "..." in note

    def test_empty_diff(self):
        result, note = smart_truncate_diff("", max_chars=100)
        assert result == ""
        assert note == ""

    def test_exact_limit(self):
        diff = _make_diff({"src/main.py": 100})
        result, note = smart_truncate_diff(diff, max_chars=len(diff))
        assert result == diff
        assert note == ""


# ── build.py ─────────────────────────────────────────────


@pytest.mark.usefixtures("scripts_on_path")
class TestBuild:
    def test_build_produces_valid_output(self):
        from build import build
        from pathlib import Path

        root = Path(__file__).resolve().parent.parent
        output = build(root)
        assert output.startswith("#cloud-config")
        assert "{{FILE:" not in output
        assert "agent.py" in output
        assert "prompt.md" in output

    def test_build_raises_on_missing_file(self, tmp_path):
        from build import build, BuildError

        # Write a template referencing a file that doesn't exist
        infra = tmp_path / "infra"
        infra.mkdir()
        template = infra / "cloud-init.tmpl.yaml"
        template.write_text("content: |\n  {{FILE:nonexistent.py}}\n")
        with pytest.raises(BuildError, match="nonexistent.py"):
            build(tmp_path)

    def test_build_rejects_path_traversal(self, tmp_path):
        from build import build, BuildError

        infra = tmp_path / "infra"
        infra.mkdir()
        template = infra / "cloud-init.tmpl.yaml"
        template.write_text("content: |\n  {{FILE:../../etc/passwd}}\n")
        with pytest.raises(BuildError, match="path traversal"):
            build(tmp_path)


# ── already_reviewed ────────────────────────────────────


def _subprocess_result(returncode=0, stdout="", stderr=""):
    """Build a mock subprocess.CompletedProcess."""
    return subprocess.CompletedProcess(
        args=[], returncode=returncode, stdout=stdout, stderr=stderr,
    )


class TestAlreadyReviewed:
    @patch("agent.subprocess.run")
    def test_returns_true_when_comments_found(self, mock_run):
        mock_run.return_value = _subprocess_result(stdout="2\n")
        assert already_reviewed("owner/repo", 42) is True

    @patch("agent.subprocess.run")
    def test_returns_false_when_no_comments(self, mock_run):
        mock_run.return_value = _subprocess_result(stdout="0\n")
        assert already_reviewed("owner/repo", 42) is False

    @patch("agent.subprocess.run")
    def test_returns_false_on_empty_output(self, mock_run):
        mock_run.return_value = _subprocess_result(stdout="")
        assert already_reviewed("owner/repo", 42) is False

    @patch("agent.subprocess.run")
    def test_returns_false_on_non_numeric_output(self, mock_run):
        mock_run.return_value = _subprocess_result(stdout="error: not found\n")
        assert already_reviewed("owner/repo", 42) is False

    @patch("agent.subprocess.run")
    def test_returns_false_on_command_failure(self, mock_run):
        mock_run.return_value = _subprocess_result(returncode=1, stdout="")
        assert already_reviewed("owner/repo", 42) is False

    @patch("agent.subprocess.run")
    def test_passes_correct_args(self, mock_run):
        mock_run.return_value = _subprocess_result(stdout="0\n")
        already_reviewed("org/my-repo", 99)

        args = mock_run.call_args[0][0]
        assert args[0] == "gh"
        # Verify --repo flag is followed by the repo name
        repo_idx = args.index("--repo")
        assert args[repo_idx + 1] == "org/my-repo"
        # PR number should be passed as a positional string arg
        assert "99" in args

    @patch("agent.subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="gh", timeout=30))
    def test_propagates_timeout(self, mock_run):
        with pytest.raises(subprocess.TimeoutExpired):
            already_reviewed("owner/repo", 42)


# ── collapse_old_reviews ────────────────────────────────


class TestCollapseOldReviews:
    @patch("agent.subprocess.run")
    def test_collapses_uncollapsed_reviews(self, mock_run):
        comment_json = json.dumps({
            "id": 123,
            "body": f"{REVIEW_MARKER}\n## Review\nLooks good!",
        })
        # First call: list comments; second call: PATCH
        mock_run.side_effect = [
            _subprocess_result(stdout=comment_json + "\n"),
            _subprocess_result(),
        ]

        collapse_old_reviews("owner/repo", 7)

        assert mock_run.call_count == 2
        patch_call = mock_run.call_args_list[1]
        args = patch_call[0][0]
        assert "PATCH" in args
        # Find the endpoint arg containing the comment ID
        endpoint_args = [a for a in args if "/issues/comments/" in a]
        assert any("123" in a for a in endpoint_args)
        # The -f body=... arg should contain <details>
        body_arg = [a for a in args if "body=" in a and "<details>" in a]
        assert len(body_arg) == 1
        assert "Previous review (superseded)" in body_arg[0]

    @patch("agent.subprocess.run")
    def test_skips_already_collapsed_reviews(self, mock_run):
        # The jq filter already excludes comments containing <details>,
        # so the gh api call returns empty
        mock_run.return_value = _subprocess_result(stdout="")
        collapse_old_reviews("owner/repo", 7)
        assert mock_run.call_count == 1  # only the list call

    @patch("agent.subprocess.run")
    def test_handles_multiple_comments(self, mock_run):
        comments = "\n".join(
            json.dumps({"id": i, "body": f"{REVIEW_MARKER}\nReview #{i}"})
            for i in [10, 20, 30]
        )
        mock_run.side_effect = [
            _subprocess_result(stdout=comments + "\n"),
            _subprocess_result(),  # PATCH #10
            _subprocess_result(),  # PATCH #20
            _subprocess_result(),  # PATCH #30
        ]

        collapse_old_reviews("owner/repo", 5)

        # 1 list + 3 PATCH calls
        assert mock_run.call_count == 4

    @patch("agent.subprocess.run")
    def test_noop_when_list_fails(self, mock_run):
        mock_run.return_value = _subprocess_result(returncode=1, stderr="API error")
        collapse_old_reviews("owner/repo", 5)
        assert mock_run.call_count == 1

    @patch("agent.subprocess.run")
    def test_skips_malformed_json_lines(self, mock_run):
        output = "not-json\n" + json.dumps({"id": 1, "body": f"{REVIEW_MARKER}\nOk"})
        mock_run.side_effect = [
            _subprocess_result(stdout=output + "\n"),
            _subprocess_result(),  # PATCH for the valid one
        ]

        collapse_old_reviews("owner/repo", 3)

        # Should still patch the valid comment
        assert mock_run.call_count == 2

    @patch("agent.subprocess.run")
    def test_skips_comment_with_missing_id(self, mock_run):
        output = json.dumps({"body": f"{REVIEW_MARKER}\nno id"})
        mock_run.side_effect = [
            _subprocess_result(stdout=output + "\n"),
        ]

        collapse_old_reviews("owner/repo", 3)

        # Only the list call, no PATCH because id is missing
        assert mock_run.call_count == 1

    @patch("agent.subprocess.run")
    def test_deduplicates_marker_in_collapsed_body(self, mock_run):
        """Marker appears once at the top of the collapsed body, not duplicated inside <details>."""
        original_body = f"{REVIEW_MARKER}\n## Review\nGreat code!"
        comment_json = json.dumps({"id": 5, "body": original_body})
        mock_run.side_effect = [
            _subprocess_result(stdout=comment_json + "\n"),
            _subprocess_result(),
        ]

        collapse_old_reviews("owner/repo", 1)

        patch_args = mock_run.call_args_list[1][0][0]
        body_arg = [a for a in patch_args if a.startswith("body=")][0]
        assert body_arg.count(REVIEW_MARKER) == 1


# ── review_pr ───────────────────────────────────────────


def _find_call_with_arg(mock_run, arg):
    """Find a subprocess.run call whose argv list contains `arg` as an exact element."""
    return next(
        (c for c in mock_run.call_args_list if arg in c[0][0]),
        None,
    )


class TestReviewPr:
    """Tests for the main review_pr orchestration function."""

    @patch("agent.subprocess.run")
    @patch("agent.get_prompt_template", return_value="Review {repo}#{pr_number}: {pr_title}\n{pr_body}\n{truncation_note}\n{diff}")
    def test_happy_path_opened(self, mock_template, mock_run):
        mock_run.side_effect = [
            # already_reviewed: gh pr view --json comments
            _subprocess_result(stdout="0\n"),
            # gh pr diff
            _subprocess_result(stdout="diff --git a/f.py b/f.py\n+hello\n"),
            # gh pr view --json body
            _subprocess_result(stdout="Fix the bug\n"),
            # claude -p
            _subprocess_result(stdout="LGTM, no issues found."),
            # gh pr comment
            _subprocess_result(stdout="https://github.com/owner/repo/pull/1#comment"),
        ]

        review_pr("owner/repo", 1, "Fix bug", "opened")

        # Should have called: already_reviewed, diff, body, claude, comment
        assert mock_run.call_count == 5
        # Verify claude was called with the prompt
        claude_call = _find_call_with_arg(mock_run,"claude")
        assert claude_call is not None

    @patch("agent.subprocess.run")
    @patch("agent.get_prompt_template", return_value="{repo}#{pr_number}: {pr_title}\n{pr_body}\n{truncation_note}\n{diff}")
    def test_skips_already_reviewed_on_opened(self, mock_template, mock_run):
        mock_run.return_value = _subprocess_result(stdout="1\n")

        review_pr("owner/repo", 1, "Fix bug", "opened")

        # Only already_reviewed call, nothing else
        assert mock_run.call_count == 1

    @patch("agent.subprocess.run")
    @patch("agent.get_prompt_template", return_value="{repo}#{pr_number}: {pr_title}\n{pr_body}\n{truncation_note}\n{diff}")
    def test_synchronize_collapses_old_reviews(self, mock_template, mock_run):
        mock_run.side_effect = [
            # collapse_old_reviews: gh api list comments (no uncollapsed)
            _subprocess_result(stdout=""),
            # gh pr diff
            _subprocess_result(stdout="diff --git a/f.py b/f.py\n+change\n"),
            # gh pr view --json body
            _subprocess_result(stdout="Updated\n"),
            # claude -p
            _subprocess_result(stdout="Looks good."),
            # gh pr comment
            _subprocess_result(),
        ]

        review_pr("owner/repo", 2, "Update feature", "synchronize")

        # First call should be the collapse_old_reviews (gh api), not already_reviewed
        assert _find_call_with_arg(mock_run,"api") is not None
        # Verify "Updated Review" header in posted comment
        comment_call = _find_call_with_arg(mock_run, "--body")
        assert comment_call is not None
        comment_args = comment_call[0][0]
        body_idx = comment_args.index("--body") + 1
        assert "Updated Review" in comment_args[body_idx]

    @patch("agent.subprocess.run")
    def test_returns_on_diff_failure(self, mock_run):
        mock_run.side_effect = [
            # already_reviewed
            _subprocess_result(stdout="0\n"),
            # gh pr diff — fails
            _subprocess_result(returncode=1, stderr="not found"),
        ]

        review_pr("owner/repo", 1, "Fix", "opened")

        # Should stop after diff failure — no claude or comment calls
        assert mock_run.call_count == 2

    @patch("agent.subprocess.run")
    @patch("agent.get_prompt_template", return_value="{repo}#{pr_number}: {pr_title}\n{pr_body}\n{truncation_note}\n{diff}")
    def test_returns_on_empty_diff(self, mock_template, mock_run):
        # Note: review_pr fetches the PR body before checking diff emptiness.
        # This mirrors the production ordering (diff → body → empty check).
        mock_run.side_effect = [
            _subprocess_result(stdout="0\n"),     # already_reviewed
            _subprocess_result(stdout="   \n"),   # gh pr diff — whitespace only
            _subprocess_result(stdout="desc\n"),  # gh pr view --json body
        ]

        review_pr("owner/repo", 1, "Empty PR", "opened")

        # Should stop after detecting empty diff — no claude or comment calls
        assert mock_run.call_count == 3

    @patch("agent.subprocess.run")
    @patch("agent.get_prompt_template", return_value="{repo}#{pr_number}: {pr_title}\n{pr_body}\n{truncation_note}\n{diff}")
    def test_returns_on_claude_failure(self, mock_template, mock_run):
        mock_run.side_effect = [
            _subprocess_result(stdout="0\n"),                           # already_reviewed
            _subprocess_result(stdout="diff --git a/x b/x\n+ok\n"),   # diff
            _subprocess_result(stdout="body\n"),                       # pr body
            _subprocess_result(returncode=1, stderr="claude error"),   # claude fails
        ]

        review_pr("owner/repo", 1, "Fix", "opened")

        # Should not attempt to post comment
        assert mock_run.call_count == 4

    @patch("agent.subprocess.run")
    @patch("agent.get_prompt_template", return_value="{repo}#{pr_number}: {pr_title}\n{pr_body}\n{truncation_note}\n{diff}")
    def test_returns_on_empty_claude_output(self, mock_template, mock_run):
        mock_run.side_effect = [
            _subprocess_result(stdout="0\n"),                           # already_reviewed
            _subprocess_result(stdout="diff --git a/x b/x\n+ok\n"),   # diff
            _subprocess_result(stdout="body\n"),                       # pr body
            _subprocess_result(stdout="   \n"),                        # claude empty
        ]

        review_pr("owner/repo", 1, "Fix", "opened")

        assert mock_run.call_count == 4

    @patch("agent.subprocess.run")
    @patch("agent.get_prompt_template", return_value="{repo}#{pr_number}: {pr_title}\n{pr_body}\n{truncation_note}\n{diff}")
    def test_handles_comment_post_failure(self, mock_template, mock_run):
        mock_run.side_effect = [
            _subprocess_result(stdout="0\n"),                           # already_reviewed
            _subprocess_result(stdout="diff --git a/x b/x\n+ok\n"),   # diff
            _subprocess_result(stdout="body\n"),                       # pr body
            _subprocess_result(stdout="Review text"),                  # claude
            _subprocess_result(returncode=1, stderr="post failed"),    # comment fails
        ]

        # Should not raise
        review_pr("owner/repo", 1, "Fix", "opened")
        assert mock_run.call_count == 5

    @patch("agent.subprocess.run")
    @patch("agent.get_prompt_template", return_value="{repo}#{pr_number}: {pr_title}\n{pr_body}\n{truncation_note}\n{diff}")
    def test_handles_timeout(self, mock_template, mock_run):
        mock_run.side_effect = [
            _subprocess_result(stdout="0\n"),  # already_reviewed
            subprocess.TimeoutExpired(cmd="gh", timeout=60),
        ]

        # Should not raise — timeout is caught after already_reviewed + diff fetch
        review_pr("owner/repo", 1, "Fix", "opened")
        assert mock_run.call_count == 2

    @patch("agent.subprocess.run")
    @patch("agent.get_prompt_template", return_value="{repo}#{pr_number}: {pr_title}\n{pr_body}\n{truncation_note}\n{diff}")
    def test_escapes_braces_in_title_and_body(self, mock_template, mock_run):
        mock_run.side_effect = [
            _subprocess_result(stdout="0\n"),
            _subprocess_result(stdout="diff --git a/x b/x\n+ok\n"),
            _subprocess_result(stdout="body with {braces}\n"),
            _subprocess_result(stdout="Review output"),
            _subprocess_result(),
        ]

        # Title with braces should not cause a KeyError in .format()
        review_pr("owner/repo", 1, "Fix {something}", "opened")

        # Verify claude was called (format didn't crash)
        assert _find_call_with_arg(mock_run,"claude") is not None

    @patch("agent.subprocess.run")
    @patch("agent.get_prompt_template", return_value="{repo}#{pr_number}: {pr_title}\n{pr_body}\n{truncation_note}\n{diff}")
    def test_opened_header(self, mock_template, mock_run):
        mock_run.side_effect = [
            _subprocess_result(stdout="0\n"),
            _subprocess_result(stdout="diff --git a/x b/x\n+ok\n"),
            _subprocess_result(stdout="body\n"),
            _subprocess_result(stdout="Review"),
            _subprocess_result(),
        ]

        review_pr("owner/repo", 1, "Fix", "opened")

        comment_call = _find_call_with_arg(mock_run, "--body")
        assert comment_call is not None
        comment_args = comment_call[0][0]
        body_idx = comment_args.index("--body") + 1
        assert "Review" in comment_args[body_idx]  # "📝 Review" header
        assert "Updated" not in comment_args[body_idx]

    @patch("agent.subprocess.run")
    @patch("agent.get_prompt_template", return_value="{repo}#{pr_number}: {pr_title}\n{pr_body}\n{truncation_note}\n{diff}")
    def test_pr_body_fallback_when_fetch_fails(self, mock_template, mock_run):
        mock_run.side_effect = [
            _subprocess_result(stdout="0\n"),                           # already_reviewed
            _subprocess_result(stdout="diff --git a/x b/x\n+ok\n"),   # diff
            _subprocess_result(returncode=1, stderr="err"),            # body fetch fails
            _subprocess_result(stdout="Review"),                       # claude
            _subprocess_result(),                                      # comment
        ]

        review_pr("owner/repo", 1, "Fix", "opened")

        # Claude should still be called — body defaults to ""
        assert mock_run.call_count == 5


# ── WebhookHandler ──────────────────────────────────────

SECRET = "test-secret-key"


def _sign_payload(payload: bytes) -> str:
    return "sha256=" + hmac.new(
        SECRET.encode(), payload, hashlib.sha256
    ).hexdigest()


def _make_pr_payload(action="opened", draft=False, number=1, title="Test PR"):
    return json.dumps({
        "action": action,
        "pull_request": {
            "number": number,
            "title": title,
            "draft": draft,
        },
        "repository": {"full_name": "owner/repo"},
    }).encode()


@pytest.fixture()
def http_server():
    """Start a WebhookHandler on a random port, yield (host, port), then shut down."""
    server = HTTPServer(("127.0.0.1", 0), WebhookHandler)
    port = server.server_address[1]
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield ("127.0.0.1", port)
    server.shutdown()


class TestWebhookHandlerGet:
    def test_health_endpoint(self, http_server):
        import urllib.request
        host, port = http_server
        req = urllib.request.Request(f"http://{host}:{port}/health")
        resp = urllib.request.urlopen(req)
        assert resp.status == 200
        body = json.loads(resp.read())
        assert body["status"] == "healthy"

    def test_unknown_get_returns_404(self, http_server):
        import urllib.request
        import urllib.error
        host, port = http_server
        req = urllib.request.Request(f"http://{host}:{port}/unknown")
        with pytest.raises(urllib.error.HTTPError) as exc:
            urllib.request.urlopen(req)
        assert exc.value.code == 404


class TestWebhookHandlerPost:
    def _post(self, http_server, path, payload, headers=None):
        import http.client
        host, port = http_server
        conn = http.client.HTTPConnection(host, port, timeout=5)
        conn.request("POST", path, body=payload, headers=headers or {})
        resp = conn.getresponse()
        status = resp.status
        try:
            body = resp.read()
        except ConnectionError:
            body = b""
        conn.close()
        return status, body

    def test_wrong_path_returns_404(self, http_server):
        payload = b'{"test": true}'
        status, _ = self._post(http_server, "/wrong", payload)
        assert status == 404

    def test_missing_signature_returns_403(self, http_server):
        payload = _make_pr_payload()
        headers = {"Content-Length": str(len(payload))}
        status, _ = self._post(http_server, "/webhook", payload, headers)
        assert status == 403

    def test_invalid_signature_returns_403(self, http_server):
        payload = _make_pr_payload()
        headers = {
            "Content-Length": str(len(payload)),
            "X-Hub-Signature-256": "sha256=invalid",
        }
        status, _ = self._post(http_server, "/webhook", payload, headers)
        assert status == 403

    def test_valid_signature_returns_200(self, http_server):
        payload = _make_pr_payload()
        sig = _sign_payload(payload)
        headers = {
            "Content-Length": str(len(payload)),
            "X-Hub-Signature-256": sig,
            "X-GitHub-Event": "ping",
        }
        status, body = self._post(http_server, "/webhook", payload, headers)
        assert status == 200
        assert json.loads(body)["ok"] is True

    @patch("agent.executor")
    def test_pr_opened_submits_review(self, mock_executor, http_server):
        payload = _make_pr_payload(action="opened", number=42, title="My PR")
        sig = _sign_payload(payload)
        headers = {
            "Content-Length": str(len(payload)),
            "X-Hub-Signature-256": sig,
            "X-GitHub-Event": "pull_request",
        }
        status, _ = self._post(http_server, "/webhook", payload, headers)
        assert status == 200

        # executor.submit() is called synchronously inside do_POST before
        # the response is sent, so the mock is already populated here.
        # If do_POST is ever refactored to dispatch asynchronously *after*
        # the response, this assertion would need a sync mechanism.
        mock_executor.submit.assert_called_once()
        call_args = mock_executor.submit.call_args
        assert call_args[0][0] == review_pr
        assert call_args[0][1] == "owner/repo"
        assert call_args[0][2] == 42
        assert call_args[0][3] == "My PR"
        assert call_args[0][4] == "opened"

    @patch("agent.executor")
    def test_pr_synchronize_submits_review(self, mock_executor, http_server):
        payload = _make_pr_payload(action="synchronize", number=10)
        sig = _sign_payload(payload)
        headers = {
            "Content-Length": str(len(payload)),
            "X-Hub-Signature-256": sig,
            "X-GitHub-Event": "pull_request",
        }
        status, _ = self._post(http_server, "/webhook", payload, headers)
        assert status == 200

        mock_executor.submit.assert_called_once()
        assert mock_executor.submit.call_args[0][4] == "synchronize"

    @patch("agent.executor")
    def test_pr_closed_does_not_submit(self, mock_executor, http_server):
        payload = _make_pr_payload(action="closed")
        sig = _sign_payload(payload)
        headers = {
            "Content-Length": str(len(payload)),
            "X-Hub-Signature-256": sig,
            "X-GitHub-Event": "pull_request",
        }
        status, _ = self._post(http_server, "/webhook", payload, headers)
        assert status == 200
        mock_executor.submit.assert_not_called()

    @patch("agent.executor")
    def test_draft_pr_skipped(self, mock_executor, http_server):
        payload = _make_pr_payload(action="opened", draft=True)
        sig = _sign_payload(payload)
        headers = {
            "Content-Length": str(len(payload)),
            "X-Hub-Signature-256": sig,
            "X-GitHub-Event": "pull_request",
        }
        status, _ = self._post(http_server, "/webhook", payload, headers)
        assert status == 200
        mock_executor.submit.assert_not_called()

    @patch("agent.executor")
    def test_non_pr_event_ignored(self, mock_executor, http_server):
        payload = _make_pr_payload()
        sig = _sign_payload(payload)
        headers = {
            "Content-Length": str(len(payload)),
            "X-Hub-Signature-256": sig,
            "X-GitHub-Event": "push",
        }
        status, _ = self._post(http_server, "/webhook", payload, headers)
        assert status == 200
        mock_executor.submit.assert_not_called()

    def test_oversized_payload_returns_413(self, http_server):
        # Relies on do_POST checking Content-Length *before* reading the body.
        # We send a small payload with an inflated Content-Length header to
        # avoid pushing 5MB over loopback. If the handler is ever refactored
        # to read-then-check, this test must be updated to send an actual
        # oversized payload.
        payload = b"x" * 1024
        headers = {
            "Content-Length": "5000001",
            "X-Hub-Signature-256": "sha256=dummy",
        }
        status, _ = self._post(http_server, "/webhook", payload, headers)
        assert status == 413

    @patch("agent.executor")
    def test_missing_event_header_returns_200_no_submit(self, mock_executor, http_server):
        """A valid signature but no X-GitHub-Event should return 200 but not submit."""
        payload = _make_pr_payload()
        sig = _sign_payload(payload)
        headers = {
            "Content-Length": str(len(payload)),
            "X-Hub-Signature-256": sig,
        }
        status, _ = self._post(http_server, "/webhook", payload, headers)
        assert status == 200
        mock_executor.submit.assert_not_called()


# ── get_prompt_template ─────────────────────────────────


class TestGetPromptTemplate:
    def test_returns_prompt_content(self):
        from agent import get_prompt_template
        template = get_prompt_template()
        assert "{pr_number}" in template
        assert "{diff}" in template

    def test_is_idempotent(self):
        from agent import get_prompt_template
        t1 = get_prompt_template()
        t2 = get_prompt_template()
        assert t1 is t2  # cached — same object


# ── JSONFormatter ───────────────────────────────────────


class TestJSONFormatter:
    def test_formats_log_as_json(self):
        import logging
        from agent import JSONFormatter

        formatter = JSONFormatter()
        record = logging.LogRecord(
            name="test", level=logging.INFO, pathname="", lineno=0,
            msg="hello world", args=(), exc_info=None,
        )
        output = formatter.format(record)
        parsed = json.loads(output)
        assert parsed["msg"] == "hello world"
        assert parsed["level"] == "INFO"
        assert "ts" in parsed

    def test_includes_exception_info(self):
        import logging
        from agent import JSONFormatter

        formatter = JSONFormatter()
        try:
            raise ValueError("test error")
        except ValueError:
            import sys
            exc_info = sys.exc_info()

        record = logging.LogRecord(
            name="test", level=logging.ERROR, pathname="", lineno=0,
            msg="failure", args=(), exc_info=exc_info,
        )
        output = formatter.format(record)
        parsed = json.loads(output)
        assert "exc" in parsed
        assert "ValueError" in parsed["exc"]
