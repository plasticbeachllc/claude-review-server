"""Tests for agent.py core functions."""

import hashlib
import hmac
import os
import textwrap

import pytest

# Set required env var before importing agent
os.environ.setdefault("GITHUB_WEBHOOK_SECRET", "test-secret-key")

from agent import (
    extract_diff_filenames,
    format_file_contents,
    is_low_priority,
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
        entry = "### x.py\n```\nhello\n```\n"
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
        """Each file gets a markdown header and fenced code block."""
        files = [("app.py", "print('hi')")]
        result, _ = format_file_contents(files, max_chars=10_000)
        assert result.startswith("### app.py\n```\n")
        assert result.endswith("\n```\n")


# ── fetch_file_contents ─────────────────────────────────


class TestFetchFileContents:
    """Tests for fetch_file_contents filter logic (mocked subprocess)."""

    def _make_run(self, responses: dict[str, str]):
        """Return a fake subprocess.run that returns content keyed by filename."""
        class FakeResult:
            def __init__(self, stdout, returncode=0):
                self.stdout = stdout
                self.returncode = returncode
                self.stderr = ""

        def fake_run(cmd, **kwargs):
            # Extract filename from the gh api URL:
            #   repos/{repo}/contents/{path}?ref={sha}
            url = cmd[2]  # "repos/owner/repo/contents/path?ref=sha"
            path_part = url.split("/contents/")[1].split("?")[0]
            if path_part in responses:
                return FakeResult(responses[path_part])
            return FakeResult("", returncode=1)

        return fake_run

    def test_skips_low_priority_files(self, monkeypatch):
        from agent import fetch_file_contents
        fake = self._make_run({"package-lock.json": "{}", "app.py": "code"})
        monkeypatch.setattr("agent.subprocess.run", fake)
        result = fetch_file_contents("owner/repo", "abc123", ["package-lock.json", "app.py"])
        names = [name for name, _ in result]
        assert "app.py" in names
        assert "package-lock.json" not in names

    def test_caps_at_15_files(self, monkeypatch):
        from agent import fetch_file_contents
        all_files = [f"file{i}.py" for i in range(20)]
        responses = {f: f"content_{f}" for f in all_files}
        fake = self._make_run(responses)
        monkeypatch.setattr("agent.subprocess.run", fake)
        result = fetch_file_contents("owner/repo", "abc123", all_files)
        assert len(result) == 15

    def test_skips_api_failures(self, monkeypatch):
        from agent import fetch_file_contents
        fake = self._make_run({})  # all files return rc=1
        monkeypatch.setattr("agent.subprocess.run", fake)
        result = fetch_file_contents("owner/repo", "abc123", ["missing.py"])
        assert result == []

    def test_skips_empty_content(self, monkeypatch):
        from agent import fetch_file_contents
        fake = self._make_run({"empty.py": ""})
        monkeypatch.setattr("agent.subprocess.run", fake)
        result = fetch_file_contents("owner/repo", "abc123", ["empty.py"])
        assert result == []

    def test_skips_oversized_files(self, monkeypatch):
        from agent import fetch_file_contents
        fake = self._make_run({"huge.py": "x" * 60_000})
        monkeypatch.setattr("agent.subprocess.run", fake)
        result = fetch_file_contents("owner/repo", "abc123", ["huge.py"])
        assert result == []

    def test_skips_binary_files(self, monkeypatch):
        from agent import fetch_file_contents
        fake = self._make_run({"image.py": "header\x00binary_data"})
        monkeypatch.setattr("agent.subprocess.run", fake)
        result = fetch_file_contents("owner/repo", "abc123", ["image.py"])
        assert result == []

    def test_returns_valid_files(self, monkeypatch):
        from agent import fetch_file_contents
        fake = self._make_run({"good.py": "import os\nprint('hello')\n"})
        monkeypatch.setattr("agent.subprocess.run", fake)
        result = fetch_file_contents("owner/repo", "abc123", ["good.py"])
        assert len(result) == 1
        assert result[0] == ("good.py", "import os\nprint('hello')\n")


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
            file_contents=esc("### app.py\n```\nprint('hi')\n```\n"),
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
