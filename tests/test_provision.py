"""Tests for provisioning scripts (config loading, API construction)."""

import json
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

    def test_strips_inline_comments(self, tmp_path):
        from _common import load_config

        env = self._full_env(HCLOUD_TOKEN="real-token # this is a comment")
        root = self._write_env(tmp_path, env)
        config = load_config(root)
        assert config["HCLOUD_TOKEN"] == "real-token"

    def test_preserves_hash_without_leading_space(self, tmp_path):
        from _common import load_config

        # A bare # without a leading space is NOT an inline comment
        env = self._full_env(HCLOUD_TOKEN="token#nospace")
        root = self._write_env(tmp_path, env)
        config = load_config(root)
        assert config["HCLOUD_TOKEN"] == "token#nospace"

    def test_preserves_hash_in_quoted_values(self, tmp_path):
        from _common import load_config

        # Inline comments are not stripped inside quoted values
        env = self._full_env(HCLOUD_TOKEN='"value # with hash"')
        root = self._write_env(tmp_path, env)
        config = load_config(root)
        assert config["HCLOUD_TOKEN"] == "value # with hash"


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

    @patch("_common.requests.request")
    def test_handles_204_no_content(self, mock_request):
        from _common import cf_request

        mock_request.return_value = MagicMock(status_code=204)
        result = cf_request("DELETE", "/test/path", "my-token")

        assert result == {"success": True, "result": None}


# ── GitHub pagination ──────────────────────────────────────


@pytest.mark.usefixtures("scripts_on_path")
class TestGhPaginate:
    @patch("_common.requests.get")
    def test_single_page(self, mock_get):
        from _common import gh_paginate

        mock_get.return_value = _gh_response(200, [{"id": 1}, {"id": 2}])

        items = gh_paginate(
            "https://api.github.com/orgs/x/hooks",
            headers={"Authorization": "Bearer tok"},
            params={"per_page": 100},
        )
        assert items == [{"id": 1}, {"id": 2}]
        mock_get.assert_called_once()

    @patch("_common.requests.get")
    def test_follows_next_link(self, mock_get):
        from _common import gh_paginate

        page1 = _gh_response(200, [{"id": 1}], headers={
            "Link": '<https://api.github.com/orgs/x/hooks?page=2>; rel="next"',
        })
        page2 = _gh_response(200, [{"id": 2}])
        mock_get.side_effect = [page1, page2]

        items = gh_paginate(
            "https://api.github.com/orgs/x/hooks",
            headers={"Authorization": "Bearer tok"},
            params={"per_page": 100},
        )
        assert items == [{"id": 1}, {"id": 2}]
        assert mock_get.call_count == 2
        # Second call should use the URL from the Link header, no params
        second_call = mock_get.call_args_list[1]
        assert second_call[0][0] == "https://api.github.com/orgs/x/hooks?page=2"
        assert second_call[1]["params"] is None

    @patch("_common.requests.get")
    def test_raises_on_error(self, mock_get):
        from _common import ProvisionError, gh_paginate

        mock_get.return_value = _gh_response(403, text="Forbidden")

        with pytest.raises(ProvisionError, match="403"):
            gh_paginate(
                "https://api.github.com/orgs/x/hooks",
                headers={"Authorization": "Bearer tok"},
            )

    @patch("_common.requests.get")
    def test_follows_multiple_pages(self, mock_get):
        from _common import gh_paginate

        page1 = _gh_response(200, [{"id": 1}], headers={
            "Link": '<https://api.github.com/orgs/x/hooks?page=2>; rel="next", '
                    '<https://api.github.com/orgs/x/hooks?page=3>; rel="last"',
        })
        page2 = _gh_response(200, [{"id": 2}], headers={
            "Link": '<https://api.github.com/orgs/x/hooks?page=3>; rel="next"',
        })
        page3 = _gh_response(200, [{"id": 3}])
        mock_get.side_effect = [page1, page2, page3]

        items = gh_paginate(
            "https://api.github.com/orgs/x/hooks",
            headers={"Authorization": "Bearer tok"},
            params={"per_page": 100},
        )
        assert items == [{"id": 1}, {"id": 2}, {"id": 3}]
        assert mock_get.call_count == 3

    @patch("_common.requests.get")
    def test_raises_on_non_list_response(self, mock_get):
        from _common import ProvisionError, gh_paginate

        # GitHub might return a dict (e.g. rate-limit info) instead of a list
        mock_get.return_value = _gh_response(200, {"message": "rate limit exceeded"})

        with pytest.raises(ProvisionError, match="unexpected response shape"):
            gh_paginate(
                "https://api.github.com/orgs/x/hooks",
                headers={"Authorization": "Bearer tok"},
            )


# ── GitHub webhook construction ────────────────────────────


@pytest.mark.usefixtures("scripts_on_path")
class TestCreateWebhook:
    @patch("provision.gh_paginate", return_value=[])
    @patch("provision.requests.post")
    def test_posts_correct_payload(self, mock_post, mock_paginate):
        from provision import create_webhook

        mock_post.return_value = _gh_response(201, {"id": 42})

        config = {"GH_TOKEN": "ghp_test", "GITHUB_ORG": "myorg"}
        create_webhook(config, "secret123", "pr-review.example.com")

        call_kwargs = mock_post.call_args
        payload = call_kwargs[1]["json"]
        assert payload["config"]["url"] == "https://pr-review.example.com/webhook"
        assert payload["config"]["secret"] == "secret123"
        assert payload["events"] == ["pull_request"]
        assert payload["active"] is True

    @patch("provision.gh_paginate", return_value=[])
    @patch("provision.requests.post")
    def test_raises_on_failure(self, mock_post, mock_paginate):
        from _common import ProvisionError
        from provision import create_webhook

        mock_post.return_value = _gh_response(422, text="Validation failed")

        config = {"GH_TOKEN": "ghp_test", "GITHUB_ORG": "myorg"}
        with pytest.raises(ProvisionError, match="422"):
            create_webhook(config, "secret", "host.example.com")

    @patch("provision.gh_paginate")
    @patch("provision.requests.post")
    def test_skips_when_webhook_exists(self, mock_post, mock_paginate):
        from provision import create_webhook

        mock_paginate.return_value = [
            {"id": 99, "config": {"url": "https://pr-review.example.com/webhook"}},
        ]

        config = {"GH_TOKEN": "ghp_test", "GITHUB_ORG": "myorg"}
        create_webhook(config, "secret123", "pr-review.example.com")

        mock_post.assert_not_called()


# ── Destroy script ─────────────────────────────────────────


@pytest.mark.usefixtures("scripts_on_path")
class TestDestroy:
    @patch("destroy.gh_paginate")
    @patch("destroy.requests.delete")
    def test_delete_webhook_finds_and_deletes(self, mock_delete, mock_paginate):
        from destroy import delete_webhook

        mock_paginate.return_value = [
            {"id": 1, "config": {"url": "https://other.example.com/webhook"}},
            {"id": 2, "config": {"url": "https://pr-review.example.com/webhook"}},
        ]
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

    @patch("destroy.gh_paginate")
    def test_delete_webhook_passes_per_page(self, mock_paginate):
        from destroy import delete_webhook

        mock_paginate.return_value = []

        config = {
            "GITHUB_ORG": "myorg",
            "GH_TOKEN": "ghp_test",
            "TUNNEL_HOSTNAME": "pr-review.example.com",
        }
        delete_webhook(config)

        # Verify per_page=100 is passed to gh_paginate
        call_kwargs = mock_paginate.call_args
        assert call_kwargs[1]["params"]["per_page"] == 100

    @patch("destroy.gh_paginate")
    def test_delete_webhook_raises_on_list_failure(self, mock_paginate):
        from _common import ProvisionError
        from destroy import delete_webhook

        mock_paginate.side_effect = ProvisionError("GitHub API error (403): Forbidden")

        config = {
            "GITHUB_ORG": "myorg",
            "GH_TOKEN": "ghp_test",
            "TUNNEL_HOSTNAME": "pr-review.example.com",
        }
        with pytest.raises(ProvisionError, match="403"):
            delete_webhook(config)


# ── Auto-cleanup on provision failure ─────────────────────


@pytest.mark.usefixtures("scripts_on_path")
class TestAutoCleanup:
    def test_auto_cleanup_calls_destroy_functions(self):
        from provision import _auto_cleanup

        config = {"SERVER_NAME": "test", "GITHUB_ORG": "org", "TUNNEL_HOSTNAME": "h"}
        created = {"server": "test", "tunnel": "h", "dns": "h", "webhook": "h"}

        with patch("provision.delete_webhook") as dw, \
             patch("provision.delete_dns_record") as dd, \
             patch("provision.delete_tunnel") as dt, \
             patch("provision.delete_server") as ds:
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
        created = {"server": "test", "tunnel": "h", "dns": "h"}

        with patch("provision.delete_dns_record", side_effect=Exception("boom")), \
             patch("provision.delete_tunnel") as dt, \
             patch("provision.delete_server") as ds:
            # Should not raise despite delete_dns_record failing
            _auto_cleanup(created, config)

        dt.assert_called_once()
        ds.assert_called_once()

    def test_auto_cleanup_cleans_dns_without_tunnel(self):
        """DNS should be cleaned up even if tunnel tracking is absent."""
        from provision import _auto_cleanup

        config = {"SERVER_NAME": "test"}
        # DNS was created but setup_tunnel failed before recording "tunnel"
        created = {"server": "test", "dns": "h"}

        with patch("provision.delete_dns_record") as dd, \
             patch("provision.delete_server") as ds:
            _auto_cleanup(created, config)

        dd.assert_called_once_with(config)
        ds.assert_called_once_with(config)

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

    def _zone_response(self):
        """Zone validation response for review.example.com."""
        return {"result": {"name": "example.com"}}

    @patch("provision.subprocess.run")
    @patch("provision.cf_request")
    def test_creates_new_tunnel_and_dns(self, mock_cf, mock_run):
        from provision import setup_tunnel

        # cf_request responses in order:
        # 0. GET zone (validation)
        # 1. GET tunnels (empty — no existing)
        # 2. POST create tunnel
        # 3. PUT ingress config
        # 4. GET DNS records (empty — no existing)
        # 5. POST create DNS
        # 6. GET connector token
        mock_cf.side_effect = [
            self._zone_response(),
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
        # Verify tunnel creation was POSTed (index shifted +1 for zone check)
        assert mock_cf.call_args_list[2][0][0] == "POST"
        # Verify DNS creation was POSTed
        assert mock_cf.call_args_list[5][0][0] == "POST"

    @patch("provision.subprocess.run")
    @patch("provision.cf_request")
    def test_reuses_existing_tunnel(self, mock_cf, mock_run):
        from provision import setup_tunnel

        mock_cf.side_effect = [
            self._zone_response(),                                # GET zone
            {"result": [{"id": "existing-tun"}]},  # GET tunnels — found existing
            {"result": {}},                          # PUT ingress config
            {"result": []},                          # GET DNS records
            {"result": {}},                          # POST create DNS
            {"result": "token-val"},                 # GET connector token
        ]
        mock_run.return_value = MagicMock(returncode=0, stderr="")

        hostname = setup_tunnel(self._config(), "1.2.3.4")

        assert hostname == "review.example.com"
        # call 0 is GET zone, call 1 is GET tunnels, call 2 is PUT ingress
        assert mock_cf.call_args_list[1][0][0] == "GET"
        assert mock_cf.call_args_list[2][0][0] == "PUT"

    @patch("provision.subprocess.run")
    @patch("provision.cf_request")
    def test_updates_existing_dns_record(self, mock_cf, mock_run):
        from provision import setup_tunnel

        mock_cf.side_effect = [
            self._zone_response(),                               # GET zone
            {"result": [{"id": "tun-1"}]},                    # GET tunnels — existing
            {"result": {}},                                     # PUT ingress
            {"result": [{"id": "dns-rec-1"}]},                 # GET DNS — existing record
            {"result": {}},                                     # PUT update DNS
            {"result": "tok"},                                  # GET connector token
        ]
        mock_run.return_value = MagicMock(returncode=0, stderr="")

        setup_tunnel(self._config(), "1.2.3.4")

        # DNS step should be PUT (update), not POST (create) — index shifted +1
        dns_call = mock_cf.call_args_list[4]
        assert dns_call[0][0] == "PUT"
        assert "dns-rec-1" in dns_call[0][1]

    @patch("provision.subprocess.run")
    @patch("provision.cf_request")
    def test_raises_on_cloudflared_install_failure(self, mock_cf, mock_run):
        from _common import ProvisionError
        from provision import setup_tunnel

        mock_cf.side_effect = [
            self._zone_response(),
            {"result": [{"id": "tun-1"}]},
            {"result": {}},
            {"result": []},
            {"result": {}},
            {"result": "tok"},
        ]
        mock_run.return_value = MagicMock(returncode=1, stderr="install failed")

        with pytest.raises(ProvisionError, match="cloudflared install failed"):
            setup_tunnel(self._config(), "1.2.3.4")

    @patch("provision.subprocess.run")
    @patch("provision.cf_request")
    def test_updates_created_dict_progressively(self, mock_cf, mock_run):
        """setup_tunnel should track tunnel and DNS in `created` for cleanup."""
        from provision import setup_tunnel

        mock_cf.side_effect = [
            self._zone_response(),
            {"result": []},
            {"result": {"id": "tun-new"}},
            {"result": {}},
            {"result": []},
            {"result": {}},
            {"result": "tok"},
        ]
        mock_run.return_value = MagicMock(returncode=0, stderr="")

        created = {}
        setup_tunnel(self._config(), "1.2.3.4", created=created)

        assert "tunnel" in created
        assert "dns" in created

    @patch("provision.subprocess.run")
    @patch("provision.cf_request")
    def test_tracks_dns_even_if_cloudflared_fails(self, mock_cf, mock_run):
        """DNS should be tracked even if cloudflared install fails after."""
        from _common import ProvisionError
        from provision import setup_tunnel

        mock_cf.side_effect = [
            self._zone_response(),
            {"result": [{"id": "tun-1"}]},
            {"result": {}},
            {"result": []},
            {"result": {}},
            {"result": "tok"},
        ]
        mock_run.return_value = MagicMock(returncode=1, stderr="fail")

        created = {}
        with pytest.raises(ProvisionError):
            setup_tunnel(self._config(), "1.2.3.4", created=created)

        # DNS and tunnel should be tracked even though cloudflared failed
        assert "tunnel" in created
        assert "dns" in created

    @patch("provision.cf_request")
    def test_raises_on_zone_mismatch(self, mock_cf):
        """TUNNEL_HOSTNAME must belong to the zone identified by CF_ZONE_ID."""
        from _common import ProvisionError
        from provision import setup_tunnel

        # Zone is otherdomain.com, but hostname is review.example.com
        mock_cf.return_value = {"result": {"name": "otherdomain.com"}}

        with pytest.raises(ProvisionError, match="does not belong to zone"):
            setup_tunnel(self._config(), "1.2.3.4")


# ── wait_for_ssh ──────────────────────────────────────────


@pytest.mark.usefixtures("scripts_on_path")
class TestWaitForSsh:
    @patch("_common.time.sleep")
    @patch("_common.ssh")
    def test_returns_when_ssh_ready(self, mock_ssh, mock_sleep):
        from _common import wait_for_ssh

        mock_ssh.return_value = "ready"
        wait_for_ssh("1.2.3.4", timeout=30)

        mock_ssh.assert_called_once()
        mock_sleep.assert_not_called()

    @patch("_common.time.sleep")
    @patch("_common.time.time")
    @patch("_common.ssh")
    def test_retries_on_failure_then_succeeds(self, mock_ssh, mock_time, mock_sleep):
        from _common import ProvisionError, wait_for_ssh

        # First call fails, second succeeds
        mock_ssh.side_effect = [ProvisionError("refused"), "ready"]
        # time() returns: start, check1 (still in window), check2 (still in window)
        mock_time.side_effect = [0, 1, 6]

        wait_for_ssh("1.2.3.4", timeout=30)

        assert mock_ssh.call_count == 2
        assert mock_sleep.call_count == 1

    @patch("_common.time.sleep")
    @patch("_common.time.time")
    @patch("_common.ssh")
    def test_raises_after_timeout(self, mock_ssh, mock_time, mock_sleep):
        from _common import ProvisionError, wait_for_ssh

        mock_ssh.side_effect = ProvisionError("refused")
        # time() returns: start, check1 (in window → retry), check2 (past deadline)
        mock_time.side_effect = [0, 1, 301]

        with pytest.raises(ProvisionError, match="SSH not reachable after 300s"):
            wait_for_ssh("1.2.3.4", timeout=300)

        # Verify the retry loop actually executed at least once
        assert mock_ssh.call_count >= 1
        assert mock_sleep.call_count >= 1


# ── wait_for_cloud_init ──────────────────────────────────


@pytest.mark.usefixtures("scripts_on_path")
class TestWaitForCloudInit:
    @patch("_common.time.sleep")
    @patch("_common.ssh")
    def test_returns_when_done(self, mock_ssh, mock_sleep):
        from _common import wait_for_cloud_init

        mock_ssh.return_value = json.dumps({"status": "done"})
        wait_for_cloud_init("1.2.3.4", timeout=60)

        mock_ssh.assert_called_once()

    @patch("_common.time.sleep")
    @patch("_common.ssh")
    def test_raises_cloud_init_error(self, mock_ssh, mock_sleep):
        from _common import CloudInitError, wait_for_cloud_init

        mock_ssh.return_value = json.dumps({
            "status": "error",
            "extended_status": "modules failed",
        })

        with pytest.raises(CloudInitError, match="cloud-init failed"):
            wait_for_cloud_init("1.2.3.4", timeout=60)

    @patch("_common.time.sleep")
    @patch("_common.time.time")
    @patch("_common.ssh")
    def test_raises_after_timeout(self, mock_ssh, mock_time, mock_sleep):
        from _common import ProvisionError, wait_for_cloud_init

        mock_ssh.return_value = json.dumps({"status": "running"})
        # time() returns: deadline calc, while-check, sleep duration calc, while-check (past)
        mock_time.side_effect = [0, 1, 1, 601]

        with pytest.raises(ProvisionError, match="cloud-init did not finish"):
            wait_for_cloud_init("1.2.3.4", timeout=600)

    @patch("_common.time.sleep")
    @patch("_common.time.time")
    @patch("_common.ssh")
    def test_retries_on_transient_ssh_failure(self, mock_ssh, mock_time, mock_sleep):
        from _common import ProvisionError, wait_for_cloud_init

        # First call fails with SSH error, second returns done
        mock_ssh.side_effect = [
            ProvisionError("connection refused"),
            json.dumps({"status": "done"}),
        ]
        # time() calls: deadline calc, while-check, remaining calc, while-check
        mock_time.side_effect = [0, 1, 11, 15]

        wait_for_cloud_init("1.2.3.4", timeout=60)

        assert mock_ssh.call_count == 2


# ── inject_auth ──────────────────────────────────────────


@pytest.mark.usefixtures("scripts_on_path")
class TestInjectAuth:
    def _config(self):
        return {
            "GH_TOKEN": "ghp_test_token",
            "CLAUDE_CODE_AUTH_TOKEN": "sk-ant-test",
        }

    @patch("provision.subprocess.run")
    @patch("provision.ssh")
    def test_raises_when_gh_not_installed(self, mock_ssh, mock_run):
        from _common import ProvisionError
        from provision import inject_auth

        mock_ssh.side_effect = ProvisionError("command not found")

        with pytest.raises(ProvisionError, match="GitHub CLI.*not found"):
            inject_auth("1.2.3.4", self._config())

        # subprocess.run should not have been called (gh check failed first)
        mock_run.assert_not_called()

    @patch("provision.subprocess.run")
    @patch("provision.ssh")
    def test_raises_on_gh_auth_failure(self, mock_ssh, mock_run):
        from _common import ProvisionError
        from provision import inject_auth

        # gh preflight succeeds
        mock_ssh.return_value = "/usr/bin/gh"
        # gh auth login fails
        mock_run.return_value = MagicMock(
            returncode=1, stderr="auth error", stdout="",
        )

        with pytest.raises(ProvisionError, match="GitHub CLI auth failed"):
            inject_auth("1.2.3.4", self._config())

    @patch("provision.subprocess.run")
    @patch("provision.ssh")
    def test_succeeds_with_all_steps(self, mock_ssh, mock_run):
        from provision import inject_auth

        mock_ssh.return_value = "/usr/bin/gh"
        # 2 subprocess.run calls: gh auth, grep/mv upsert
        mock_run.side_effect = [
            MagicMock(returncode=0, stderr="", stdout=""),  # gh auth login
            MagicMock(returncode=0, stderr="", stdout=""),  # grep/mv upsert
        ]

        inject_auth("1.2.3.4", self._config())  # should not raise

        assert mock_run.call_count == 2

    @patch("provision.subprocess.run")
    @patch("provision.ssh")
    def test_pipes_gh_token_via_stdin(self, mock_ssh, mock_run):
        from provision import inject_auth

        mock_ssh.return_value = "/usr/bin/gh"
        mock_run.side_effect = [
            MagicMock(returncode=0, stderr="", stdout=""),
            MagicMock(returncode=0, stderr="", stdout=""),
        ]

        inject_auth("1.2.3.4", self._config())

        # First subprocess.run call should pipe GH_TOKEN via stdin
        first_call = mock_run.call_args_list[0]
        assert first_call[1]["input"] == "ghp_test_token"

        # Second subprocess.run call should pipe CLAUDE_CODE_AUTH_TOKEN via stdin
        second_call = mock_run.call_args_list[1]
        assert second_call[1]["input"] == "sk-ant-test"
