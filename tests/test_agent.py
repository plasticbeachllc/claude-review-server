"""Tests for agent.py core functions."""

import hashlib
import hmac
import os
import subprocess
import textwrap
import threading

import pytest
from unittest.mock import MagicMock, patch

# Set required env var before importing agent
os.environ.setdefault("GITHUB_WEBHOOK_SECRET", "test-secret-key")

from agent import (
    _bump_generation,
    _is_current,
    _PRReviewState,
    _review_state,
    _review_state_lock,
    _shutting_down,
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


# ── Generation tracking ─────────────────────────────────


@pytest.fixture(autouse=True)
def _clean_review_state():
    """Reset module-level review state between tests."""
    yield
    with _review_state_lock:
        _review_state.clear()
    _shutting_down.clear()


class TestBumpGeneration:
    def test_first_bump_returns_1(self):
        assert _bump_generation("org/repo#1") == 1

    def test_successive_bumps_increment(self):
        _bump_generation("org/repo#2")
        assert _bump_generation("org/repo#2") == 2
        assert _bump_generation("org/repo#2") == 3

    def test_independent_prs_have_separate_generations(self):
        assert _bump_generation("org/repo#10") == 1
        assert _bump_generation("org/repo#20") == 1
        assert _bump_generation("org/repo#10") == 2
        assert _bump_generation("org/repo#20") == 2

    def test_kills_active_process_on_bump(self):
        pr_key = "org/repo#3"
        _bump_generation(pr_key)

        mock_proc = MagicMock()
        mock_proc.wait.return_value = 0
        with _review_state_lock:
            _review_state[pr_key].process = mock_proc

        _bump_generation(pr_key)

        mock_proc.terminate.assert_called_once()

    def test_kills_process_with_force_on_timeout(self):
        pr_key = "org/repo#4"
        _bump_generation(pr_key)

        mock_proc = MagicMock()
        mock_proc.wait.side_effect = subprocess.TimeoutExpired("claude", 5)
        with _review_state_lock:
            _review_state[pr_key].process = mock_proc

        _bump_generation(pr_key)

        mock_proc.terminate.assert_called_once()
        mock_proc.kill.assert_called_once()

    def test_handles_already_dead_process(self):
        pr_key = "org/repo#5"
        _bump_generation(pr_key)

        mock_proc = MagicMock()
        mock_proc.terminate.side_effect = OSError("No such process")
        with _review_state_lock:
            _review_state[pr_key].process = mock_proc

        # Should not raise
        gen = _bump_generation(pr_key)
        assert gen == 2


class TestIsCurrent:
    def test_current_generation_returns_true(self):
        gen = _bump_generation("org/repo#100")
        assert _is_current("org/repo#100", gen) is True

    def test_stale_generation_returns_false(self):
        gen1 = _bump_generation("org/repo#101")
        _bump_generation("org/repo#101")  # gen2
        assert _is_current("org/repo#101", gen1) is False

    def test_unknown_pr_returns_false(self):
        assert _is_current("org/repo#999", 1) is False

    def test_shutting_down_returns_false(self):
        gen = _bump_generation("org/repo#102")
        _shutting_down.set()
        assert _is_current("org/repo#102", gen) is False


class TestReviewPrCancellation:
    """Test that review_pr bails out when superseded."""

    def _mock_diff(self, returncode=0):
        return MagicMock(
            returncode=returncode,
            stdout="diff --git a/f.py b/f.py\n+hello\n",
            stderr="",
        )

    def _mock_body(self):
        return MagicMock(returncode=0, stdout="PR body text")

    @patch("agent.get_prompt_template", return_value="{pr_number}{repo}{pr_title}{pr_body}{truncation_note}{diff}")
    @patch("agent.subprocess.run")
    def test_skips_diff_fetch_when_superseded(self, mock_run, _mock_tpl):
        pr_key = "org/repo#50"
        gen = _bump_generation(pr_key)
        _bump_generation(pr_key)  # supersede

        review_pr("org/repo", 50, "title", "synchronize", pr_key, gen)

        # subprocess.run should only have been called for collapse_old_reviews,
        # not for diff fetch.
        for call in mock_run.call_args_list:
            args = call[0][0]
            assert args[:3] != ["gh", "pr", "diff"], \
                "Should not fetch diff for superseded review"

    @patch("agent.get_prompt_template", return_value="{pr_number}{repo}{pr_title}{pr_body}{truncation_note}{diff}")
    @patch("agent.subprocess.Popen")
    @patch("agent.subprocess.run")
    def test_skips_claude_when_superseded_after_diff(self, mock_run, mock_popen, _mock_tpl):
        pr_key = "org/repo#51"
        gen = _bump_generation(pr_key)

        # subprocess.run calls: collapse_old_reviews (returns nothing), diff, body
        mock_run.side_effect = [
            MagicMock(returncode=0, stdout="", stderr=""),  # collapse api
            self._mock_diff(),  # diff
            self._mock_body(),  # body
        ]

        # Supersede after diff fetch but before Claude. We do this by making
        # _is_current return False on the second call (before Claude).
        call_count = 0

        def fake_is_current(key, g):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return True  # pass the first check (before diff)
            return False  # fail the second check (before Claude)

        with patch("agent._is_current", side_effect=fake_is_current):
            review_pr("org/repo", 51, "title", "synchronize", pr_key, gen)

        mock_popen.assert_not_called()

    @patch("agent.get_prompt_template", return_value="{pr_number}{repo}{pr_title}{pr_body}{truncation_note}{diff}")
    @patch("agent.subprocess.Popen")
    @patch("agent.subprocess.run")
    def test_skips_posting_when_superseded_after_claude(self, mock_run, mock_popen, _mock_tpl):
        pr_key = "org/repo#52"
        gen = _bump_generation(pr_key)

        mock_run.side_effect = [
            MagicMock(returncode=0, stdout="", stderr=""),  # collapse api
            self._mock_diff(),  # diff
            self._mock_body(),  # body
        ]

        mock_proc = MagicMock()
        mock_proc.communicate.return_value = ("Review output", "")
        mock_proc.returncode = 0
        mock_popen.return_value = mock_proc

        call_count = 0

        def fake_is_current(key, g):
            nonlocal call_count
            call_count += 1
            if call_count <= 2:
                return True  # pass checks before diff and before Claude
            return False  # fail the check before posting

        with patch("agent._is_current", side_effect=fake_is_current):
            review_pr("org/repo", 52, "title", "synchronize", pr_key, gen)

        # Should not have posted a comment
        for call in mock_run.call_args_list:
            args = call[0][0]
            assert args[:3] != ["gh", "pr", "comment"], \
                "Should not post comment for superseded review"

    @patch("agent.get_prompt_template", return_value="{pr_number}{repo}{pr_title}{pr_body}{truncation_note}{diff}")
    @patch("agent.subprocess.Popen")
    @patch("agent.subprocess.run")
    def test_handles_killed_claude_process(self, mock_run, mock_popen, _mock_tpl):
        """When Claude is killed by signal, review_pr logs and exits cleanly."""
        pr_key = "org/repo#53"
        gen = _bump_generation(pr_key)

        mock_run.side_effect = [
            self._mock_diff(),  # diff (no collapse for "opened")
            self._mock_body(),  # body
        ]

        mock_proc = MagicMock()
        mock_proc.communicate.return_value = ("", "")
        mock_proc.returncode = -15  # killed by SIGTERM
        mock_popen.return_value = mock_proc

        # Should not raise
        review_pr("org/repo", 53, "title", "opened", pr_key, gen)

        # No comment posted
        for call in mock_run.call_args_list:
            args = call[0][0]
            assert args[:3] != ["gh", "pr", "comment"]
