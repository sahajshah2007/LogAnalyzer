"""
Tests for AlertManager — console output, Discord webhook, database persistence,
and statistics retrieval.
"""

import json
import pytest
from datetime import datetime
from unittest.mock import patch, MagicMock, call
from io import StringIO

from analyzer import ThreatAlert
from alerts import AlertManager, Colors


# ─────────────────────────────────────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture
def alert_manager(base_config):
    return AlertManager(base_config)


@pytest.fixture
def critical_alert(make_threat_alert):
    return make_threat_alert(
        event_type="SQL_INJECTION_ATTEMPT",
        source_ip="10.0.0.1",
        severity="CRITICAL",
        description="SQL injection detected",
        raw_log="GET /search?q=1 UNION SELECT * FROM users--",
        mitre_tactics=["Initial Access"],
        mitre_techniques=["T1190"],
        matched_keywords=["union select"],
    )


@pytest.fixture
def warning_alert(make_threat_alert):
    return make_threat_alert(
        event_type="NETWORK_PORT_SCAN_DETECTION",
        source_ip="10.0.0.2",
        severity="WARNING",
        description="Port scan detected",
        raw_log="nmap SYN scan from 10.0.0.2",
        mitre_tactics=["Discovery"],
        mitre_techniques=["T1046"],
    )


@pytest.fixture
def info_alert(make_threat_alert):
    return make_threat_alert(
        event_type="SUSPICIOUS_FILE_DOWNLOAD",
        source_ip="10.0.0.3",
        severity="INFO",
        description="Suspicious download",
        raw_log="wget http://example.com/file.sh",
    )


# ─────────────────────────────────────────────────────────────────────────────
# Initialization
# ─────────────────────────────────────────────────────────────────────────────

class TestAlertManagerInit:
    def test_discord_disabled_by_default(self, alert_manager):
        assert alert_manager.discord_enabled is False

    def test_discord_enabled_when_configured(self, base_config):
        cfg = dict(base_config)
        cfg["discord"] = {
            "enabled": True,
            "webhook_url": "https://discord.com/api/webhooks/123/abc",
        }
        mgr = AlertManager(cfg)
        assert mgr.discord_enabled is True
        assert mgr.discord_webhook == "https://discord.com/api/webhooks/123/abc"

    def test_db_manager_initialized(self, alert_manager):
        assert alert_manager.db_manager is not None


# ─────────────────────────────────────────────────────────────────────────────
# Console logging
# ─────────────────────────────────────────────────────────────────────────────

class TestConsoleLogging:
    def test_log_console_prints_severity(self, alert_manager, critical_alert, capsys):
        alert_manager.log_console(critical_alert)
        out = capsys.readouterr().out
        assert "CRITICAL" in out

    def test_log_console_prints_source_ip(self, alert_manager, critical_alert, capsys):
        alert_manager.log_console(critical_alert)
        out = capsys.readouterr().out
        assert "10.0.0.1" in out

    def test_log_console_prints_event_type(self, alert_manager, critical_alert, capsys):
        alert_manager.log_console(critical_alert)
        out = capsys.readouterr().out
        assert "SQL_INJECTION_ATTEMPT" in out

    def test_log_console_prints_description(self, alert_manager, critical_alert, capsys):
        alert_manager.log_console(critical_alert)
        out = capsys.readouterr().out
        assert "SQL injection detected" in out

    def test_log_console_warning_severity(self, alert_manager, warning_alert, capsys):
        alert_manager.log_console(warning_alert)
        out = capsys.readouterr().out
        assert "WARNING" in out

    def test_log_console_info_severity(self, alert_manager, info_alert, capsys):
        alert_manager.log_console(info_alert)
        out = capsys.readouterr().out
        assert "INFO" in out

    def test_log_console_abuse_score_shown(self, alert_manager, make_threat_alert, capsys):
        alert = make_threat_alert()
        alert.abuse_confidence_score = 85
        alert_manager.log_console(alert)
        out = capsys.readouterr().out
        assert "85" in out


# ─────────────────────────────────────────────────────────────────────────────
# Database persistence
# ─────────────────────────────────────────────────────────────────────────────

class TestDatabasePersistence:
    def test_save_alert_persists_to_db(self, alert_manager, critical_alert):
        alert_manager.save_alert(critical_alert)
        stats = alert_manager.db_manager.get_stats()
        assert stats["total_alerts"] >= 1

    def test_save_alert_correct_severity(self, alert_manager, critical_alert):
        alert_manager.save_alert(critical_alert)
        alerts, _ = alert_manager.db_manager.get_alerts(
            {"severity": "CRITICAL"}, limit=10, offset=0
        )
        assert len(alerts) >= 1

    def test_save_alert_correct_event_type(self, alert_manager, critical_alert):
        alert_manager.save_alert(critical_alert)
        alerts, _ = alert_manager.db_manager.get_alerts(
            {"event_type": "SQL_INJECTION_ATTEMPT"}, limit=10, offset=0
        )
        assert len(alerts) >= 1

    def test_save_alert_json_fields_stored(self, alert_manager, critical_alert):
        alert_manager.save_alert(critical_alert)
        alerts, _ = alert_manager.db_manager.get_alerts({}, limit=1, offset=0)
        a = alerts[0]
        assert isinstance(a["matched_keywords"], list)
        assert "union select" in a["matched_keywords"]
        assert isinstance(a["mitre_tactics"], list)
        assert "Initial Access" in a["mitre_tactics"]

    def test_save_multiple_alerts(self, alert_manager, critical_alert, warning_alert):
        alert_manager.save_alert(critical_alert)
        alert_manager.save_alert(warning_alert)
        stats = alert_manager.db_manager.get_stats()
        assert stats["total_alerts"] >= 2

    def test_save_alert_db_error_does_not_raise(self, base_config):
        """A DB write failure must be caught silently."""
        mgr = AlertManager(base_config)
        with patch.object(mgr.db_manager, "insert_alert", side_effect=Exception("DB down")):
            # Should not raise
            from analyzer import ThreatAlert
            alert = ThreatAlert(
                timestamp=datetime.now(),
                event_type="TEST",
                source_ip="1.2.3.4",
                description="test",
                severity="INFO",
                raw_log="test",
            )
            mgr.save_alert(alert)  # must not raise


# ─────────────────────────────────────────────────────────────────────────────
# Discord
# ─────────────────────────────────────────────────────────────────────────────

class TestDiscordAlerts:
    def test_discord_not_called_when_disabled(self, alert_manager, critical_alert):
        with patch("requests.post") as mock_post:
            alert_manager.send_discord_alert(critical_alert)
            mock_post.assert_not_called()

    def test_discord_called_when_enabled(self, base_config, critical_alert):
        cfg = dict(base_config)
        cfg["discord"] = {
            "enabled": True,
            "webhook_url": "https://discord.com/api/webhooks/123/abc",
        }
        mgr = AlertManager(cfg)
        mock_response = MagicMock()
        mock_response.status_code = 204
        with patch("requests.post", return_value=mock_response) as mock_post:
            mgr.send_discord_alert(critical_alert)
            mock_post.assert_called_once()

    def test_discord_payload_has_embed(self, base_config, critical_alert):
        cfg = dict(base_config)
        cfg["discord"] = {
            "enabled": True,
            "webhook_url": "https://discord.com/api/webhooks/123/abc",
        }
        mgr = AlertManager(cfg)
        mock_response = MagicMock()
        mock_response.status_code = 204
        with patch("requests.post", return_value=mock_response) as mock_post:
            mgr.send_discord_alert(critical_alert)
            _, kwargs = mock_post.call_args
            payload = kwargs.get("json", {})
            assert "embeds" in payload
            assert len(payload["embeds"]) == 1

    def test_discord_embed_color_critical(self, base_config, critical_alert):
        cfg = dict(base_config)
        cfg["discord"] = {
            "enabled": True,
            "webhook_url": "https://discord.com/api/webhooks/123/abc",
        }
        mgr = AlertManager(cfg)
        mock_response = MagicMock()
        mock_response.status_code = 204
        with patch("requests.post", return_value=mock_response) as mock_post:
            mgr.send_discord_alert(critical_alert)
            _, kwargs = mock_post.call_args
            embed = kwargs["json"]["embeds"][0]
            assert embed["color"] == 0xFF0000  # Red for CRITICAL

    def test_discord_network_error_does_not_raise(self, base_config, critical_alert):
        cfg = dict(base_config)
        cfg["discord"] = {
            "enabled": True,
            "webhook_url": "https://discord.com/api/webhooks/123/abc",
        }
        mgr = AlertManager(cfg)
        import requests as req
        with patch("requests.post", side_effect=req.RequestException("timeout")):
            mgr.send_discord_alert(critical_alert)  # must not raise

    def test_discord_placeholder_url_skipped(self, base_config, critical_alert):
        cfg = dict(base_config)
        cfg["discord"] = {
            "enabled": True,
            "webhook_url": "https://discord.com/api/webhooks/YOUR_WEBHOOK_ID/token",
        }
        mgr = AlertManager(cfg)
        with patch("requests.post") as mock_post:
            mgr.send_discord_alert(critical_alert)
            mock_post.assert_not_called()


# ─────────────────────────────────────────────────────────────────────────────
# process_alert
# ─────────────────────────────────────────────────────────────────────────────

class TestProcessAlert:
    def test_process_alert_calls_all_channels(self, alert_manager, critical_alert):
        with (
            patch.object(alert_manager, "log_console") as mock_console,
            patch.object(alert_manager, "save_alert") as mock_save,
            patch.object(alert_manager, "send_discord_alert") as mock_discord,
        ):
            alert_manager.process_alert(critical_alert)
            mock_console.assert_called_once_with(critical_alert)
            mock_save.assert_called_once_with(critical_alert)
            mock_discord.assert_called_once_with(critical_alert)


# ─────────────────────────────────────────────────────────────────────────────
# Statistics
# ─────────────────────────────────────────────────────────────────────────────

class TestAlertStats:
    def test_get_alert_stats_empty(self, alert_manager):
        stats = alert_manager.get_alert_stats()
        assert stats.get("total_alerts", 0) == 0

    def test_get_alert_stats_after_save(self, alert_manager, critical_alert, warning_alert):
        alert_manager.save_alert(critical_alert)
        alert_manager.save_alert(warning_alert)
        stats = alert_manager.get_alert_stats()
        assert stats["total_alerts"] >= 2
        assert "by_severity" in stats
        assert "by_type" in stats

    def test_get_alert_stats_db_error_returns_empty(self, alert_manager):
        with patch.object(alert_manager.db_manager, "get_stats", side_effect=Exception("DB error")):
            stats = alert_manager.get_alert_stats()
            assert stats == {}
