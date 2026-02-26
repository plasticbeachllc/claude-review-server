"""Tests for agent.py core functions."""

import hashlib
import hmac
import json
import os
import subprocess
import textwrap
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
    extract_diff_filenames,
    format_file_contents,
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


# ── extract_diff_filenames ───────────────────────────────


class TestExtractDiffFilenames:
    def test_extracts_modified_files(self):
        diff = textwrap.dedent("""\
            diff --git a/src/main.py b/src/main.py
            index abc..def 100644
            --- a/src/main.py
            +++ b/src/main.py
            @@ -1,3 +1,4 @@
            +import os
             import sys
            diff --git a/src/utils.py b/src/utils.py
            index abc..def 100644
            --- a/src/utils.py
            +++ b/src/utils.py
            @@ -10,3 +10,4 @@
            +# comment
        """)
        assert extract_diff_filenames(diff) == ["src/main.py", "src/utils.py"]

    def test_excludes_deleted_files(self):
        diff = textwrap.dedent("""\
            diff --git a/keep.py b/keep.py
            index abc..def 100644
            --- a/keep.py
            +++ b/keep.py
            @@ -1 +1,2 @@
            +new line
            diff --git a/removed.py b/removed.py
            deleted file mode 100644
            index abc..000
            --- a/removed.py
            +++ /dev/null
            @@ -1,5 +0,0 @@
            -old content
        """)
        result = extract_diff_filenames(diff)
        assert "keep.py" in result
        assert "removed.py" not in result

    def test_excludes_dev_null_deletions(self):
        diff = textwrap.dedent("""\
            diff --git a/gone.py b/gone.py
            index abc..000
            --- a/gone.py
            +++ /dev/null
            @@ -1 +0,0 @@
            -bye
        """)
        assert extract_diff_filenames(diff) == []

    def test_handles_new_files(self):
        diff = textwrap.dedent("""\
            diff --git a/new.py b/new.py
            new file mode 100644
            index 000..abc
            --- /dev/null
            +++ b/new.py
            @@ -0,0 +1,3 @@
            +hello
        """)
        assert extract_diff_filenames(diff) == ["new.py"]

    def test_handles_renames(self):
        diff = textwrap.dedent("""\
            diff --git a/old_name.py b/new_name.py
            similarity index 95%
            rename from old_name.py
            rename to new_name.py
            index abc..def 100644
            --- a/old_name.py
            +++ b/new_name.py
            @@ -1 +1 @@
            -old
            +new
        """)
        assert extract_diff_filenames(diff) == ["new_name.py"]

    def test_no_duplicates(self):
        # Same file appearing somehow won't duplicate
        diff = (
            "diff --git a/f.py b/f.py\n--- a/f.py\n+++ b/f.py\n+x\n"
        )
        assert extract_diff_filenames(diff) == ["f.py"]

    def test_empty_diff(self):
        assert extract_diff_filenames("") == []

    def test_diff_header_as_last_line(self):
        """diff --git line at EOF with no subsequent lines."""
        diff = "diff --git a/trailing.py b/trailing.py"
        assert extract_diff_filenames(diff) == ["trailing.py"]

    def test_diff_header_only_one_line_after(self):
        """diff --git with only an index line following (no +++ line)."""
        diff = (
            "diff --git a/mode.py b/mode.py\n"
            "index abc..def 100755\n"
        )
        assert extract_diff_filenames(diff) == ["mode.py"]


# ── format_file_contents ────────────────────────────────


class TestFormatFileContents:
    def test_formats_files(self):
        files = [("src/main.py", "import os\n")]
        result, note = format_file_contents(files, max_chars=10_000)
        assert "### src/main.py" in result
        assert "import os" in result
        assert note == ""

    def test_truncates_large_files(self):
        files = [
            ("small.py", "x" * 100),
            ("big.py", "y" * 5000),
        ]
        result, note = format_file_contents(files, max_chars=200)
        assert "small.py" in result
        assert "big.py" not in result
        assert "1 file(s) contents omitted" in note
        assert "big.py" in note

    def test_drops_low_priority_first(self):
        files = [
            ("src/app.py", "x" * 300),
            ("package-lock.json", "y" * 300),
        ]
        result, note = format_file_contents(files, max_chars=400)
        assert "src/app.py" in result
        assert "package-lock.json" not in result

    def test_empty_input(self):
        result, note = format_file_contents([], max_chars=10_000)
        assert result == ""
        assert note == ""

    def test_note_caps_at_10_names(self):
        files = [(f"f{i}.py", "x" * 100) for i in range(15)]
        _, note = format_file_contents(files, max_chars=200)
        assert "..." in note

    def test_all_files_fit(self):
        files = [
            ("a.py", "aaa"),
            ("b.py", "bbb"),
        ]
        result, note = format_file_contents(files, max_chars=100_000)
        assert "a.py" in result
        assert "b.py" in result
        assert note == ""

    def test_exact_boundary(self):
        """A single file whose formatted entry exactly hits max_chars."""
        files = [("x.py", "hello")]
        entry = "### x.py\n~~~\nhello\n~~~\n"
        result, note = format_file_contents(files, max_chars=len(entry))
        assert result == entry
        assert note == ""

    def test_single_file_too_large(self):
        """One file exceeds budget — result is empty, note lists it."""
        files = [("huge.py", "x" * 10_000)]
        result, note = format_file_contents(files, max_chars=50)
        assert result == ""
        assert "huge.py" in note
        assert "1 file(s) contents omitted" in note

    def test_all_dropped(self):
        """Multiple files, all too large — every file dropped."""
        files = [
            ("a.py", "x" * 500),
            ("b.py", "y" * 500),
        ]
        result, note = format_file_contents(files, max_chars=10)
        assert result == ""
        assert "2 file(s) contents omitted" in note

    def test_mixed_priority_under_pressure(self):
        """High-priority small file kept; low-priority file and large high-priority dropped."""
        files = [
            ("src/small.py", "x" * 50),
            ("package-lock.json", "y" * 50),
            ("src/big.py", "z" * 5000),
        ]
        # Budget fits only one small file (~76 chars formatted)
        result, note = format_file_contents(files, max_chars=100)
        assert "src/small.py" in result
        assert "package-lock.json" not in result
        assert "src/big.py" not in result
        assert "2 file(s) contents omitted" in note

    def test_output_wraps_in_code_blocks(self):
        """Each file gets a markdown header and tilde-fenced code block."""
        files = [("app.py", "print('hi')")]
        result, _ = format_file_contents(files, max_chars=10_000)
        assert result.startswith("### app.py\n~~~\n")
        assert result.endswith("\n~~~\n")


# ── fetch_file_contents ─────────────────────────────────


class TestFetchFileContents:
    """Tests for fetch_file_contents filter logic (mocked subprocess)."""

    VALID_SHA = "a" * 40  # valid 40-char hex SHA

    def _make_run(self, responses: dict[str, bytes]):
        """Return a fake subprocess.run that returns bytes content keyed by filename."""
        class FakeResult:
            def __init__(self, stdout, returncode=0):
                self.stdout = stdout
                self.returncode = returncode
                self.stderr = b""

        def fake_run(cmd, **kwargs):
            # Extract filename from the gh api URL:
            #   repos/{repo}/contents/{path}?ref={sha}
            url = cmd[2]  # "repos/owner/repo/contents/path?ref=sha"
            path_part = url.split("/contents/")[1].split("?")[0]
            if path_part in responses:
                return FakeResult(responses[path_part])
            return FakeResult(b"", returncode=1)

        return fake_run

    def test_skips_low_priority_files(self, monkeypatch):
        from agent import fetch_file_contents
        fake = self._make_run({"package-lock.json": b"{}", "app.py": b"code"})
        monkeypatch.setattr("agent.subprocess.run", fake)
        result = fetch_file_contents("owner/repo", self.VALID_SHA, ["package-lock.json", "app.py"])
        names = [name for name, _ in result]
        assert "app.py" in names
        assert "package-lock.json" not in names

    def test_caps_at_15_files(self, monkeypatch):
        from agent import fetch_file_contents
        all_files = [f"file{i}.py" for i in range(20)]
        responses = {f: f"content_{f}".encode() for f in all_files}
        fake = self._make_run(responses)
        monkeypatch.setattr("agent.subprocess.run", fake)
        result = fetch_file_contents("owner/repo", self.VALID_SHA, all_files)
        assert len(result) == 15

    def test_skips_api_failures(self, monkeypatch):
        from agent import fetch_file_contents
        fake = self._make_run({})  # all files return rc=1
        monkeypatch.setattr("agent.subprocess.run", fake)
        result = fetch_file_contents("owner/repo", self.VALID_SHA, ["missing.py"])
        assert result == []

    def test_skips_empty_content(self, monkeypatch):
        from agent import fetch_file_contents
        fake = self._make_run({"empty.py": b""})
        monkeypatch.setattr("agent.subprocess.run", fake)
        result = fetch_file_contents("owner/repo", self.VALID_SHA, ["empty.py"])
        assert result == []

    def test_skips_oversized_files(self, monkeypatch):
        from agent import fetch_file_contents
        fake = self._make_run({"huge.py": b"x" * 60_000})
        monkeypatch.setattr("agent.subprocess.run", fake)
        result = fetch_file_contents("owner/repo", self.VALID_SHA, ["huge.py"])
        assert result == []

    def test_skips_binary_files(self, monkeypatch):
        from agent import fetch_file_contents
        fake = self._make_run({"image.py": b"header\x00binary_data"})
        monkeypatch.setattr("agent.subprocess.run", fake)
        result = fetch_file_contents("owner/repo", self.VALID_SHA, ["image.py"])
        assert result == []

    def test_skips_non_utf8_binary_files(self, monkeypatch):
        """Files with invalid UTF-8 bytes are detected via replacement char."""
        from agent import fetch_file_contents
        fake = self._make_run({"bin.py": b"\x89PNG\r\n\x1a\nimage_data"})
        monkeypatch.setattr("agent.subprocess.run", fake)
        result = fetch_file_contents("owner/repo", self.VALID_SHA, ["bin.py"])
        assert result == []

    def test_returns_valid_files(self, monkeypatch):
        from agent import fetch_file_contents
        fake = self._make_run({"good.py": b"import os\nprint('hello')\n"})
        monkeypatch.setattr("agent.subprocess.run", fake)
        result = fetch_file_contents("owner/repo", self.VALID_SHA, ["good.py"])
        assert len(result) == 1
        assert result[0] == ("good.py", "import os\nprint('hello')\n")

    def test_rejects_invalid_sha(self, monkeypatch):
        """Invalid head_sha format returns empty list without making API calls."""
        from agent import fetch_file_contents
        call_count = 0
        def no_calls(cmd, **kwargs):
            nonlocal call_count
            call_count += 1
        monkeypatch.setattr("agent.subprocess.run", no_calls)
        result = fetch_file_contents("owner/repo", "not-a-sha", ["file.py"])
        assert result == []
        assert call_count == 0

    def test_url_encodes_filenames(self, monkeypatch):
        """Filenames with spaces/special chars are URL-encoded in the API call."""
        from agent import fetch_file_contents
        captured_urls = []
        class FakeResult:
            stdout = b"content"
            returncode = 0
            stderr = b""
        def capture_run(cmd, **kwargs):
            captured_urls.append(cmd[2])
            return FakeResult()
        monkeypatch.setattr("agent.subprocess.run", capture_run)
        fetch_file_contents("owner/repo", self.VALID_SHA, ["path/to/my file.py"])
        assert len(captured_urls) == 1
        assert "my%20file.py" in captured_urls[0]
        assert "my file.py" not in captured_urls[0]


# ── prompt template rendering ────────────────────────────


class TestPromptRendering:
    """Verify the prompt template renders correctly with all placeholders."""

    def test_template_renders_with_file_contents(self):
        from agent import get_prompt_template
        template = get_prompt_template()

        def esc(s):
            return s.replace("{", "{{").replace("}", "}}")

        # Should not raise KeyError for any placeholder
        result = template.format(
            pr_number=42,
            repo="owner/repo",
            pr_title=esc("Add feature"),
            pr_body=esc("Implements X"),
            truncation_note="",
            file_contents=esc("### app.py\n~~~\nprint('hi')\n~~~\n"),
            diff=esc("+import os\n"),
        )
        assert "PR #42" in result
        assert "owner/repo" in result
        assert "### app.py" in result
        assert "+import os" in result

    def test_template_renders_with_empty_file_contents(self):
        from agent import get_prompt_template
        template = get_prompt_template()

        def esc(s):
            return s.replace("{", "{{").replace("}", "}}")

        result = template.format(
            pr_number=1,
            repo="a/b",
            pr_title=esc("Fix"),
            pr_body=esc("(none)"),
            truncation_note="",
            file_contents="",
            diff=esc("+x\n"),
        )
        assert "a/b" in result
        assert "+x" in result

    def test_template_handles_braces_in_file_contents(self):
        """File contents with { and } don't break .format()."""
        from agent import get_prompt_template
        template = get_prompt_template()

        def esc(s):
            return s.replace("{", "{{").replace("}", "}}")

        code_with_braces = "def main():\n    d = {key: value}\n    return d\n"
        result = template.format(
            pr_number=1,
            repo="a/b",
            pr_title=esc("Fix"),
            pr_body=esc("(none)"),
            truncation_note="",
            file_contents=esc(code_with_braces),
            diff=esc("+x\n"),
        )
        assert "{key: value}" in result


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
