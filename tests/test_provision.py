"""Tests for provisioning scripts (config loading, API construction)."""

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest


def _gh_response(status_code=200, json_data=None, text="", headers=None):
    """Create a mock GitHub API response with sensible defaults."""
    resp = MagicMock()
    resp.status_code = status_code
    resp.json = MagicMock(return_value=json_data if json_data is not None else [])
    resp.text = text
    resp.headers = headers or {}
    return resp


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
        assert config["SERVER_TYPE"] == "cx11"
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
            content = find_local_pubkey()
        assert content.startswith("ssh-ed25519")

    def test_finds_ecdsa(self, tmp_path):
        from provision import find_local_pubkey

        ssh_dir = tmp_path / ".ssh"
        ssh_dir.mkdir()
        (ssh_dir / "id_ecdsa.pub").write_text("ecdsa-sha2-nistp256 AAAA... user@host")

        with patch("provision.Path.home", return_value=tmp_path):
            content = find_local_pubkey()
        assert content.startswith("ecdsa-sha2")

    def test_falls_back_to_rsa(self, tmp_path):
        from provision import find_local_pubkey

        ssh_dir = tmp_path / ".ssh"
        ssh_dir.mkdir()
        (ssh_dir / "id_rsa.pub").write_text("ssh-rsa AAAA... user@host")

        with patch("provision.Path.home", return_value=tmp_path):
            content = find_local_pubkey()
        assert content.startswith("ssh-rsa")

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
        mock_get.return_value = _gh_response(200, [])
        mock_post.return_value = _gh_response(201, {"id": 42})

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

        mock_get.return_value = _gh_response(200, [])
        mock_post.return_value = _gh_response(422, text="Validation failed")

        config = {"GH_TOKEN": "ghp_test", "GITHUB_ORG": "myorg"}
        with pytest.raises(ProvisionError, match="422"):
            create_webhook(config, "secret", "host.example.com")

    @patch("provision.requests.get")
    @patch("provision.requests.post")
    def test_skips_when_webhook_exists(self, mock_post, mock_get):
        from provision import create_webhook

        mock_get.return_value = _gh_response(
            200, [{"id": 99, "config": {"url": "https://pr-review.example.com/webhook"}}],
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

        mock_get.return_value = _gh_response(200, [
            {"id": 1, "config": {"url": "https://other.example.com/webhook"}},
            {"id": 2, "config": {"url": "https://pr-review.example.com/webhook"}},
        ])
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

        mock_get.return_value = _gh_response(200, [])

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

        mock_get.return_value = _gh_response(403, text="Forbidden")

        config = {
            "GITHUB_ORG": "myorg",
            "GH_TOKEN": "ghp_test",
            "TUNNEL_HOSTNAME": "pr-review.example.com",
        }
        with pytest.raises(ProvisionError, match="403"):
            delete_webhook(config)


# ── Pagination overflow detection ─────────────────────────


@pytest.mark.usefixtures("scripts_on_path")
class TestCheckPagination:
    def test_no_link_header_passes(self):
        from _common import check_pagination

        resp = _gh_response(200, [])
        check_pagination(resp, "webhooks")  # should not raise

    def test_link_header_with_next_raises(self):
        from _common import ProvisionError, check_pagination

        resp = _gh_response(200, [], headers={
            "Link": '<https://api.github.com/orgs/myorg/hooks?page=2>; rel="next"',
        })
        with pytest.raises(ProvisionError, match="paginated webhooks"):
            check_pagination(resp, "webhooks")

    @patch("provision.requests.get")
    @patch("provision.requests.post")
    def test_create_webhook_raises_on_pagination(self, mock_post, mock_get):
        from _common import ProvisionError
        from provision import create_webhook

        mock_get.return_value = _gh_response(200, [], headers={
            "Link": '<https://api.github.com/orgs/x/hooks?page=2>; rel="next"',
        })
        config = {"GH_TOKEN": "ghp_test", "GITHUB_ORG": "myorg"}
        with pytest.raises(ProvisionError, match="paginated"):
            create_webhook(config, "secret", "host.example.com")
        mock_post.assert_not_called()


# ── Auto-cleanup on provision failure ─────────────────────


@pytest.mark.usefixtures("scripts_on_path")
class TestAutoCleanup:
    def test_auto_cleanup_calls_destroy_functions(self):
        from provision import _auto_cleanup

        config = {"SERVER_NAME": "test", "GITHUB_ORG": "org", "TUNNEL_HOSTNAME": "h"}
        created = {"server": "test", "tunnel": "h", "webhook": "h"}

        with patch("destroy.delete_webhook") as dw, \
             patch("destroy.delete_dns_record") as dd, \
             patch("destroy.delete_tunnel") as dt, \
             patch("destroy.delete_server") as ds:
            _auto_cleanup(created, config)

        dw.assert_called_once_with(config)
        dd.assert_called_once_with(config)
        dt.assert_called_once_with(config)
        ds.assert_called_once_with(config)

    def test_auto_cleanup_skips_when_empty(self):
        from provision import _auto_cleanup

        # Should not raise or call anything
        _auto_cleanup({}, {})

    def test_auto_cleanup_continues_on_failure(self):
        from provision import _auto_cleanup

        config = {"SERVER_NAME": "test"}
        created = {"server": "test", "tunnel": "h"}

        with patch("destroy.delete_dns_record", side_effect=Exception("boom")), \
             patch("destroy.delete_tunnel") as dt, \
             patch("destroy.delete_server") as ds:
            # Should not raise despite delete_dns_record failing
            _auto_cleanup(created, config)

        dt.assert_called_once()
        ds.assert_called_once()

    def test_main_handles_config_failure_without_unbound_error(self):
        """Regression test: load_config failure must not cause UnboundLocalError."""
        from _common import ProvisionError
        from provision import main

        with patch("provision.load_config", side_effect=ProvisionError("bad .env")):
            with pytest.raises(SystemExit) as exc:
                main()
            assert exc.value.code == 1


# ── setup_tunnel ──────────────────────────────────────────


@pytest.mark.usefixtures("scripts_on_path")
class TestSetupTunnel:
    def _config(self):
        return {
            "CF_API_TOKEN": "cf-tok",
            "CF_ACCOUNT_ID": "acct-1",
            "CF_ZONE_ID": "zone-1",
            "TUNNEL_HOSTNAME": "review.example.com",
            "SERVER_NAME": "pr-review",
        }

    @patch("provision.subprocess.run")
    @patch("provision.cf_request")
    def test_creates_new_tunnel_and_dns(self, mock_cf, mock_run):
        from provision import setup_tunnel

        # cf_request responses in order:
        # 1. GET tunnels (empty — no existing)
        # 2. POST create tunnel
        # 3. PUT ingress config
        # 4. GET DNS records (empty — no existing)
        # 5. POST create DNS
        # 6. GET connector token
        mock_cf.side_effect = [
            {"result": []},
            {"result": {"id": "tun-123"}},
            {"result": {}},
            {"result": []},
            {"result": {}},
            {"result": "connector-token-value"},
        ]
        mock_run.return_value = MagicMock(returncode=0, stderr="")

        hostname = setup_tunnel(self._config(), "1.2.3.4")

        assert hostname == "review.example.com"
        # Verify tunnel creation was POSTed
        assert mock_cf.call_args_list[1][0][0] == "POST"
        # Verify DNS creation was POSTed
        assert mock_cf.call_args_list[4][0][0] == "POST"

    @patch("provision.subprocess.run")
    @patch("provision.cf_request")
    def test_reuses_existing_tunnel(self, mock_cf, mock_run):
        from provision import setup_tunnel

        mock_cf.side_effect = [
            {"result": [{"id": "existing-tun"}]},  # GET tunnels — found existing
            {"result": {}},                          # PUT ingress config
            {"result": []},                          # GET DNS records
            {"result": {}},                          # POST create DNS
            {"result": "token-val"},                 # GET connector token
        ]
        mock_run.return_value = MagicMock(returncode=0, stderr="")

        hostname = setup_tunnel(self._config(), "1.2.3.4")

        assert hostname == "review.example.com"
        # Should NOT have POSTed a new tunnel (call 0 is GET, call 1 is PUT ingress)
        assert mock_cf.call_args_list[0][0][0] == "GET"
        assert mock_cf.call_args_list[1][0][0] == "PUT"

    @patch("provision.subprocess.run")
    @patch("provision.cf_request")
    def test_updates_existing_dns_record(self, mock_cf, mock_run):
        from provision import setup_tunnel

        mock_cf.side_effect = [
            {"result": [{"id": "tun-1"}]},                    # GET tunnels — existing
            {"result": {}},                                     # PUT ingress
            {"result": [{"id": "dns-rec-1"}]},                 # GET DNS — existing record
            {"result": {}},                                     # PUT update DNS
            {"result": "tok"},                                  # GET connector token
        ]
        mock_run.return_value = MagicMock(returncode=0, stderr="")

        setup_tunnel(self._config(), "1.2.3.4")

        # DNS step should be PUT (update), not POST (create)
        dns_call = mock_cf.call_args_list[3]
        assert dns_call[0][0] == "PUT"
        assert "dns-rec-1" in dns_call[0][1]

    @patch("provision.subprocess.run")
    @patch("provision.cf_request")
    def test_raises_on_cloudflared_install_failure(self, mock_cf, mock_run):
        from _common import ProvisionError
        from provision import setup_tunnel

        mock_cf.side_effect = [
            {"result": [{"id": "tun-1"}]},
            {"result": {}},
            {"result": []},
            {"result": {}},
            {"result": "tok"},
        ]
        mock_run.return_value = MagicMock(returncode=1, stderr="install failed")

        with pytest.raises(ProvisionError, match="cloudflared install failed"):
            setup_tunnel(self._config(), "1.2.3.4")
