"""Tests for status.py health-check script."""

from unittest.mock import MagicMock, patch

import pytest


@pytest.mark.usefixtures("scripts_on_path")
class TestStatusHealthCheck:
    """Verify the health check comparison logic in status.py."""

    def _make_server(self, status="running"):
        server = MagicMock()
        server.id = 1
        server.status = status
        server.public_net.ipv4.ip = "1.2.3.4"
        server.server_type.name = "cx11"
        server.datacenter.name = "fsn1-dc14"
        server.created.isoformat.return_value = "2025-01-01T00:00:00+00:00"
        return server

    @patch("status.requests.get")
    @patch("status.ssh")
    @patch("status.Client")
    @patch("status.load_config")
    def test_healthy_server_exits_zero(self, mock_config, MockClient, mock_ssh, mock_requests_get):
        from status import main

        mock_config.return_value = {
            "SERVER_NAME": "pr-review",
            "HCLOUD_TOKEN": "tok",
            "TUNNEL_HOSTNAME": "review.example.com",
        }
        mock_client = MockClient.return_value
        mock_client.servers.get_by_name.return_value = self._make_server()

        # SSH calls: systemctl, curl
        mock_ssh.side_effect = [
            "active",                         # systemctl is-active
            '{"status":"healthy"}',           # curl health
        ]
        mock_requests_get.return_value = MagicMock(status_code=200)

        # Should exit cleanly (no sys.exit call = exit 0)
        main()

    @patch("status.requests.get")
    @patch("status.ssh")
    @patch("status.Client")
    @patch("status.load_config")
    def test_healthy_json_is_recognized(self, mock_config, MockClient, mock_ssh, mock_requests_get):
        """Regression: status.py previously compared against 'ok' instead of JSON."""
        from status import main

        mock_config.return_value = {
            "SERVER_NAME": "pr-review",
            "HCLOUD_TOKEN": "tok",
            "TUNNEL_HOSTNAME": "review.example.com",
        }
        mock_client = MockClient.return_value
        mock_client.servers.get_by_name.return_value = self._make_server()

        mock_ssh.side_effect = [
            "active",
            '{"status":"healthy"}',
        ]
        mock_requests_get.return_value = MagicMock(status_code=200)

        # Should NOT exit with code 2 (unhealthy)
        main()  # implicitly exit 0 = healthy

    @patch("status.ssh")
    @patch("status.Client")
    @patch("status.load_config")
    def test_unhealthy_service_exits_two(self, mock_config, MockClient, mock_ssh):
        from status import main

        mock_config.return_value = {
            "SERVER_NAME": "pr-review",
            "HCLOUD_TOKEN": "tok",
        }
        mock_client = MockClient.return_value
        mock_client.servers.get_by_name.return_value = self._make_server()

        mock_ssh.side_effect = [
            "inactive",                       # systemctl is-active
            '{"status":"healthy"}',           # curl health
        ]

        with pytest.raises(SystemExit) as exc:
            main()
        assert exc.value.code == 2

    @patch("status.Client")
    @patch("status.load_config")
    def test_not_found_exits_three(self, mock_config, MockClient):
        from status import main

        mock_config.return_value = {
            "SERVER_NAME": "pr-review",
            "HCLOUD_TOKEN": "tok",
        }
        mock_client = MockClient.return_value
        mock_client.servers.get_by_name.return_value = None

        with pytest.raises(SystemExit) as exc:
            main()
        assert exc.value.code == 3

    @patch("status.Client")
    @patch("status.load_config")
    def test_not_running_exits_one(self, mock_config, MockClient):
        from status import main

        mock_config.return_value = {
            "SERVER_NAME": "pr-review",
            "HCLOUD_TOKEN": "tok",
        }
        mock_client = MockClient.return_value
        mock_client.servers.get_by_name.return_value = self._make_server(status="off")

        with pytest.raises(SystemExit) as exc:
            main()
        assert exc.value.code == 1

    @patch("status.ssh")
    @patch("status.Client")
    @patch("status.load_config")
    def test_unreachable_health_exits_two(self, mock_config, MockClient, mock_ssh):
        from status import main

        mock_config.return_value = {
            "SERVER_NAME": "pr-review",
            "HCLOUD_TOKEN": "tok",
        }
        mock_client = MockClient.return_value
        mock_client.servers.get_by_name.return_value = self._make_server()

        mock_ssh.side_effect = [
            "active",
            "unreachable",  # curl failed
        ]

        with pytest.raises(SystemExit) as exc:
            main()
        assert exc.value.code == 2
