"""Tests for provisioning scripts (config loading, API construction)."""

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest


# ── Config loading ─────────────────────────────────────────


@pytest.mark.usefixtures("scripts_on_path")
class TestLoadConfig:
    def _write_env(self, tmp_path: Path, content: str) -> Path:
        env = tmp_path / ".env"
        env.write_text(content)
        return tmp_path

    def _full_env(self, **overrides) -> str:
        defaults = {
            "HCLOUD_TOKEN": "hc-test-token",
            "GH_TOKEN": "ghp_test",
            "CLAUDE_CODE_AUTH_TOKEN": "sk-ant-test",
            "CF_API_TOKEN": "cf-test-token",
            "CF_ACCOUNT_ID": "cf-account-123",
            "CF_ZONE_ID": "cf-zone-456",
            "TUNNEL_HOSTNAME": "pr-review.example.com",
            "GITHUB_ORG": "myorg",
        }
        defaults.update(overrides)
        return "\n".join(f"{k}={v}" for k, v in defaults.items())

    def test_loads_valid_config(self, tmp_path):
        from _common import load_config

        root = self._write_env(tmp_path, self._full_env())
        config = load_config(root)
        assert config["HCLOUD_TOKEN"] == "hc-test-token"
        assert config["GITHUB_ORG"] == "myorg"

    def test_applies_defaults(self, tmp_path):
        from _common import load_config

        root = self._write_env(tmp_path, self._full_env())
        config = load_config(root)
        assert config["SERVER_NAME"] == "pr-review"
        assert config["SERVER_TYPE"] == "cx22"
        assert config["SERVER_LOCATION"] == "fsn1"
        assert config["SERVER_IMAGE"] == "ubuntu-24.04"

    def test_overrides_defaults(self, tmp_path):
        from _common import load_config

        env = self._full_env() + "\nSERVER_TYPE=cx32\nSERVER_LOCATION=hel1"
        root = self._write_env(tmp_path, env)
        config = load_config(root)
        assert config["SERVER_TYPE"] == "cx32"
        assert config["SERVER_LOCATION"] == "hel1"

    def test_missing_required_key_raises(self, tmp_path):
        from _common import ProvisionError, load_config

        # Missing HCLOUD_TOKEN
        env = self._full_env(HCLOUD_TOKEN="")
        root = self._write_env(tmp_path, env)
        with pytest.raises(ProvisionError, match="HCLOUD_TOKEN"):
            load_config(root)

    def test_multiple_missing_keys(self, tmp_path):
        from _common import ProvisionError, load_config

        root = self._write_env(tmp_path, "SERVER_NAME=test\n")
        with pytest.raises(ProvisionError) as exc:
            load_config(root)
        msg = str(exc.value)
        assert "HCLOUD_TOKEN" in msg
        assert "GH_TOKEN" in msg

    def test_missing_env_file_raises(self, tmp_path):
        from _common import ProvisionError, load_config

        with pytest.raises(ProvisionError, match=".env not found"):
            load_config(tmp_path)

    def test_ignores_comments_and_blanks(self, tmp_path):
        from _common import load_config

        env = "# This is a comment\n\n" + self._full_env()
        root = self._write_env(tmp_path, env)
        config = load_config(root)
        assert config["HCLOUD_TOKEN"] == "hc-test-token"

    def test_strips_surrounding_quotes(self, tmp_path):
        from _common import load_config

        env = self._full_env(
            HCLOUD_TOKEN='"hc-quoted-double"',
            GH_TOKEN="'ghp-quoted-single'",
        )
        root = self._write_env(tmp_path, env)
        config = load_config(root)
        assert config["HCLOUD_TOKEN"] == "hc-quoted-double"
        assert config["GH_TOKEN"] == "ghp-quoted-single"

    def test_preserves_value_with_equals(self, tmp_path):
        from _common import load_config

        env = self._full_env(CF_API_TOKEN="abc=def=ghi")
        root = self._write_env(tmp_path, env)
        config = load_config(root)
        assert config["CF_API_TOKEN"] == "abc=def=ghi"


# ── SSH key detection ──────────────────────────────────────


@pytest.mark.usefixtures("scripts_on_path")
class TestFindLocalPubkey:
    def test_finds_ed25519(self, tmp_path):
        from provision import find_local_pubkey

        ssh_dir = tmp_path / ".ssh"
        ssh_dir.mkdir()
        (ssh_dir / "id_ed25519.pub").write_text("ssh-ed25519 AAAA... user@host")

        with patch("provision.Path.home", return_value=tmp_path):
            name, content = find_local_pubkey()
        assert name == "id_ed25519"
        assert content.startswith("ssh-ed25519")

    def test_finds_ecdsa(self, tmp_path):
        from provision import find_local_pubkey

        ssh_dir = tmp_path / ".ssh"
        ssh_dir.mkdir()
        (ssh_dir / "id_ecdsa.pub").write_text("ecdsa-sha2-nistp256 AAAA... user@host")

        with patch("provision.Path.home", return_value=tmp_path):
            name, content = find_local_pubkey()
        assert name == "id_ecdsa"

    def test_falls_back_to_rsa(self, tmp_path):
        from provision import find_local_pubkey

        ssh_dir = tmp_path / ".ssh"
        ssh_dir.mkdir()
        (ssh_dir / "id_rsa.pub").write_text("ssh-rsa AAAA... user@host")

        with patch("provision.Path.home", return_value=tmp_path):
            name, content = find_local_pubkey()
        assert name == "id_rsa"

    def test_raises_when_no_key(self, tmp_path):
        from _common import ProvisionError
        from provision import find_local_pubkey

        with patch("provision.Path.home", return_value=tmp_path):
            with pytest.raises(ProvisionError, match="No SSH public key"):
                find_local_pubkey()


# ── Cloudflare API request construction ────────────────────


@pytest.mark.usefixtures("scripts_on_path")
class TestCfRequest:
    @patch("_common.requests.request")
    def test_sends_auth_header(self, mock_request):
        from _common import cf_request

        mock_request.return_value = MagicMock(
            json=lambda: {"success": True, "result": {}},
        )
        cf_request("GET", "/test/path", "my-cf-token")

        call_kwargs = mock_request.call_args
        assert call_kwargs[1]["headers"]["Authorization"] == "Bearer my-cf-token"

    @patch("_common.requests.request")
    def test_raises_on_api_error(self, mock_request):
        from _common import ProvisionError, cf_request

        mock_request.return_value = MagicMock(
            json=lambda: {
                "success": False,
                "errors": [{"code": 1000, "message": "bad request"}],
            },
        )
        with pytest.raises(ProvisionError, match="Cloudflare API error"):
            cf_request("GET", "/test", "token")


# ── GitHub webhook construction ────────────────────────────


@pytest.mark.usefixtures("scripts_on_path")
class TestCreateWebhook:
    @patch("provision.requests.get")
    @patch("provision.requests.post")
    def test_posts_correct_payload(self, mock_post, mock_get):
        from provision import create_webhook

        # No existing webhooks
        mock_get.return_value = MagicMock(
            status_code=200,
            json=lambda: [],
        )
        mock_post.return_value = MagicMock(
            status_code=201,
            json=lambda: {"id": 42},
        )

        config = {"GH_TOKEN": "ghp_test", "GITHUB_ORG": "myorg"}
        create_webhook(config, "secret123", "pr-review.example.com")

        call_kwargs = mock_post.call_args
        payload = call_kwargs[1]["json"]
        assert payload["config"]["url"] == "https://pr-review.example.com/webhook"
        assert payload["config"]["secret"] == "secret123"
        assert payload["events"] == ["pull_request"]
        assert payload["active"] is True

    @patch("provision.requests.get")
    @patch("provision.requests.post")
    def test_raises_on_failure(self, mock_post, mock_get):
        from _common import ProvisionError
        from provision import create_webhook

        mock_get.return_value = MagicMock(
            status_code=200,
            json=lambda: [],
        )
        mock_post.return_value = MagicMock(
            status_code=422,
            text="Validation failed",
        )

        config = {"GH_TOKEN": "ghp_test", "GITHUB_ORG": "myorg"}
        with pytest.raises(ProvisionError, match="422"):
            create_webhook(config, "secret", "host.example.com")

    @patch("provision.requests.get")
    @patch("provision.requests.post")
    def test_skips_when_webhook_exists(self, mock_post, mock_get):
        from provision import create_webhook

        mock_get.return_value = MagicMock(
            status_code=200,
            json=lambda: [
                {"id": 99, "config": {"url": "https://pr-review.example.com/webhook"}},
            ],
        )

        config = {"GH_TOKEN": "ghp_test", "GITHUB_ORG": "myorg"}
        create_webhook(config, "secret123", "pr-review.example.com")

        mock_post.assert_not_called()


# ── Destroy script ─────────────────────────────────────────


@pytest.mark.usefixtures("scripts_on_path")
class TestDestroy:
    @patch("destroy.requests.get")
    @patch("destroy.requests.delete")
    def test_delete_webhook_finds_and_deletes(self, mock_delete, mock_get):
        from destroy import delete_webhook

        mock_get.return_value = MagicMock(
            status_code=200,
            json=lambda: [
                {"id": 1, "config": {"url": "https://other.example.com/webhook"}},
                {"id": 2, "config": {"url": "https://pr-review.example.com/webhook"}},
            ],
        )
        mock_delete.return_value = MagicMock(status_code=204)

        config = {
            "GITHUB_ORG": "myorg",
            "GH_TOKEN": "ghp_test",
            "TUNNEL_HOSTNAME": "pr-review.example.com",
        }
        delete_webhook(config)

        # Should delete hook id=2, not id=1
        assert mock_delete.called
        assert "/hooks/2" in mock_delete.call_args[0][0]

    @patch("destroy.Client")
    def test_delete_server_by_name(self, MockClient):
        from destroy import delete_server

        mock_server = MagicMock(id=123)
        mock_client = MockClient.return_value
        mock_client.servers.get_by_name.return_value = mock_server

        config = {"HCLOUD_TOKEN": "hc-test", "SERVER_NAME": "pr-review"}
        delete_server(config)

        mock_client.servers.delete.assert_called_once_with(mock_server)

    @patch("destroy.requests.get")
    def test_delete_webhook_uses_pagination(self, mock_get):
        from destroy import delete_webhook

        mock_get.return_value = MagicMock(
            status_code=200,
            json=lambda: [],
        )

        config = {
            "GITHUB_ORG": "myorg",
            "GH_TOKEN": "ghp_test",
            "TUNNEL_HOSTNAME": "pr-review.example.com",
        }
        delete_webhook(config)

        # Verify per_page=100 is sent
        call_kwargs = mock_get.call_args
        assert call_kwargs[1]["params"]["per_page"] == 100

    @patch("destroy.requests.get")
    def test_delete_webhook_raises_on_list_failure(self, mock_get):
        from _common import ProvisionError
        from destroy import delete_webhook

        mock_get.return_value = MagicMock(
            status_code=403,
            text="Forbidden",
        )

        config = {
            "GITHUB_ORG": "myorg",
            "GH_TOKEN": "ghp_test",
            "TUNNEL_HOSTNAME": "pr-review.example.com",
        }
        with pytest.raises(ProvisionError, match="403"):
            delete_webhook(config)
