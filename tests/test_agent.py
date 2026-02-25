"""Tests for agent.py core functions."""

import hashlib
import hmac
import os
import textwrap

import pytest

# Set required env var before importing agent
os.environ.setdefault("GITHUB_WEBHOOK_SECRET", "test-secret-key")

from agent import (
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


# ── build.py ─────────────────────────────────────────────


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
