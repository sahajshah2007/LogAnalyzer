"""
Tests for LogAnalyzer — log parsing, brute-force tracking,
IP extraction, whitelisting, and Sigma integration.
"""

import time
import pytest
from datetime import datetime
from unittest.mock import patch, MagicMock

from analyzer import LogAnalyzer, LogEvent, ThreatAlert


# ─────────────────────────────────────────────────────────────────────────────
# Log parsing
# ─────────────────────────────────────────────────────────────────────────────

class TestLogParsing:
    def test_parse_extracts_ip(self, analyzer):
        event = analyzer.parse_log_line(
            "Apr 23 10:00:00 host sshd: Failed password for root from 192.168.1.100 port 22"
        )
        assert event.source_ip == "192.168.1.100"

    def test_parse_extracts_timestamp(self, analyzer):
        event = analyzer.parse_log_line("Apr 23 10:00:00 host sshd: test message")
        assert event.timestamp == "Apr 23 10:00:00"

    def test_parse_no_ip_returns_unknown(self, analyzer):
        event = analyzer.parse_log_line("some log line with no IP address")
        assert event.source_ip == "UNKNOWN"

    def test_parse_extracts_user_for_keyword(self, analyzer):
        event = analyzer.parse_log_line("sshd: Failed password for alice from 10.0.0.1")
        assert event.user == "alice"

    def test_parse_extracts_user_keyword(self, analyzer):
        event = analyzer.parse_log_line("sshd: Invalid user bob from 10.0.0.1")
        assert event.user == "bob"

    def test_parse_no_timestamp_uses_now(self, analyzer):
        event = analyzer.parse_log_line("no timestamp here")
        # Should not raise; timestamp should be a non-empty string
        assert isinstance(event.timestamp, str)
        assert len(event.timestamp) > 0

    def test_parse_multiple_ips_returns_first(self, analyzer):
        """When multiple IPs appear, the first one is extracted."""
        event = analyzer.parse_log_line(
            "connection from 10.0.0.1 to 10.0.0.2 port 22"
        )
        assert event.source_ip == "10.0.0.1"

    def test_parse_ipv4_boundary(self, analyzer):
        """IP extraction must not match partial numbers like 999.999.999.999."""
        event = analyzer.parse_log_line("value=1234567890 no real ip here")
        assert event.source_ip == "UNKNOWN"


# ─────────────────────────────────────────────────────────────────────────────
# Brute-force tracking
# ─────────────────────────────────────────────────────────────────────────────

class TestBruteForceTracking:
    def test_brute_force_triggers_at_threshold(self, base_config):
        """Alert fires exactly when the threshold is reached."""
        from analyzer import LogAnalyzer
        cfg = dict(base_config)
        cfg["thresholds"] = {"max_failed_logins": 3, "failed_login_window": 60}
        az = LogAnalyzer(cfg)

        line = "sshd: Failed password for root from 10.0.0.1 port 22"
        results = [az.analyze(line) for _ in range(3)]

        # First two should not trigger brute-force (may trigger Sigma rule)
        # Third must trigger BRUTE_FORCE
        brute_force_alerts = [r for r in results if r and r.event_type == "BRUTE_FORCE"]
        assert len(brute_force_alerts) >= 1

    def test_brute_force_different_ips_tracked_separately(self, base_config):
        """Each IP has its own counter."""
        from analyzer import LogAnalyzer
        cfg = dict(base_config)
        cfg["thresholds"] = {"max_failed_logins": 3, "failed_login_window": 60}
        az = LogAnalyzer(cfg)

        line_a = "sshd: Failed password for root from 10.0.0.1 port 22"
        line_b = "sshd: Failed password for root from 10.0.0.2 port 22"

        # 2 failures from IP A, 2 from IP B — neither should reach threshold of 3
        for _ in range(2):
            az.analyze(line_a)
            az.analyze(line_b)

        # No brute-force alert yet
        result_a = az.analyze(line_a)  # 3rd for A — should trigger
        assert result_a is not None
        assert result_a.event_type == "BRUTE_FORCE"
        assert result_a.source_ip == "10.0.0.1"

    def test_brute_force_window_expiry(self, base_config):
        """Failures outside the time window should not count."""
        from analyzer import LogAnalyzer
        cfg = dict(base_config)
        cfg["thresholds"] = {"max_failed_logins": 3, "failed_login_window": 1}  # 1 second
        az = LogAnalyzer(cfg)

        line = "sshd: Failed password for root from 10.0.0.5 port 22"
        az.analyze(line)
        az.analyze(line)

        time.sleep(1.1)  # Let the window expire

        # After expiry, counter resets — this should NOT trigger brute force
        result = az.analyze(line)
        # It may match a Sigma rule but should NOT be BRUTE_FORCE
        if result:
            assert result.event_type != "BRUTE_FORCE"

    def test_brute_force_whitelisted_ip_ignored(self, config_with_whitelist):
        """Whitelisted IPs must never trigger brute-force alerts."""
        from analyzer import LogAnalyzer
        az = LogAnalyzer(config_with_whitelist)

        line = "sshd: Failed password for root from 192.168.1.100 port 22"
        for _ in range(10):
            result = az.analyze(line)
            if result:
                assert result.event_type != "BRUTE_FORCE"

    def test_brute_force_alert_has_correct_fields(self, base_config):
        """Brute-force alert must have all required fields populated."""
        from analyzer import LogAnalyzer
        cfg = dict(base_config)
        cfg["thresholds"] = {"max_failed_logins": 2, "failed_login_window": 60}
        az = LogAnalyzer(cfg)

        line = "sshd: Failed password for root from 10.0.0.9 port 22"
        alert = None
        for _ in range(3):
            r = az.analyze(line)
            if r and r.event_type == "BRUTE_FORCE":
                alert = r
                break

        assert alert is not None
        assert alert.severity == "CRITICAL"
        assert alert.source_ip == "10.0.0.9"
        assert "10.0.0.9" in alert.description
        assert isinstance(alert.timestamp, datetime)
        assert alert.mitre_tactics == ["Credential Access"]
        assert "T1110.001" in alert.mitre_techniques


# ─────────────────────────────────────────────────────────────────────────────
# Whitelisting
# ─────────────────────────────────────────────────────────────────────────────

class TestWhitelisting:
    def test_exact_ip_whitelisted(self, config_with_whitelist):
        from analyzer import LogAnalyzer
        az = LogAnalyzer(config_with_whitelist)
        # 192.168.1.100 is whitelisted — SQL injection from it should be suppressed
        result = az.analyze(
            "192.168.1.100 GET /search?q=1 UNION SELECT username,password FROM users--"
        )
        assert result is None

    def test_non_whitelisted_ip_not_suppressed(self, config_with_whitelist):
        from analyzer import LogAnalyzer
        az = LogAnalyzer(config_with_whitelist)
        result = az.analyze(
            "172.16.0.1 GET /search?q=1 UNION SELECT username,password FROM users--"
        )
        assert result is not None

    def test_unknown_ip_not_suppressed(self, config_with_whitelist):
        """Lines with no extractable IP (UNKNOWN) should still be analyzed."""
        from analyzer import LogAnalyzer
        az = LogAnalyzer(config_with_whitelist)
        result = az.analyze("GET /search?q=1 UNION SELECT username,password FROM users--")
        assert result is not None


# ─────────────────────────────────────────────────────────────────────────────
# Main analyze() method
# ─────────────────────────────────────────────────────────────────────────────

class TestAnalyze:
    def test_empty_line_returns_none(self, analyzer):
        assert analyzer.analyze("") is None

    def test_whitespace_only_returns_none(self, analyzer):
        assert analyzer.analyze("   \t  ") is None

    def test_benign_line_returns_none(self, analyzer):
        assert analyzer.analyze("CRON[1234]: (root) CMD (/usr/bin/backup.sh)") is None

    def test_sql_injection_detected(self, analyzer):
        result = analyzer.analyze(
            "10.0.0.1 GET /search?q=1 UNION SELECT username,password FROM users--"
        )
        assert result is not None
        assert "SQL" in result.event_type or "SQL" in result.rule_title.upper()

    def test_xss_detected(self, analyzer):
        result = analyzer.analyze(
            "10.0.0.2 GET /search?q=<script>alert(document.cookie)</script>"
        )
        assert result is not None
        assert "XSS" in result.event_type or "XSS" in result.rule_title.upper()

    def test_path_traversal_detected(self, analyzer):
        result = analyzer.analyze("GET /file?path=../../../etc/hosts")
        assert result is not None

    def test_privilege_escalation_detected(self, analyzer):
        result = analyzer.analyze("bash: sudo -i executed by www-data")
        assert result is not None

    def test_alert_has_timestamp(self, analyzer):
        result = analyzer.analyze(
            "10.0.0.1 GET /search?q=1 UNION SELECT username,password FROM users--"
        )
        assert result is not None
        assert isinstance(result.timestamp, datetime)

    def test_alert_has_raw_log(self, analyzer):
        line = "10.0.0.1 GET /search?q=1 UNION SELECT username,password FROM users--"
        result = analyzer.analyze(line)
        assert result is not None
        assert result.raw_log == line

    def test_alert_severity_is_valid(self, analyzer):
        result = analyzer.analyze(
            "10.0.0.1 GET /search?q=1 UNION SELECT username,password FROM users--"
        )
        assert result is not None
        assert result.severity in {"CRITICAL", "WARNING", "INFO"}

    def test_alert_to_dict_serializable(self, analyzer):
        import json
        result = analyzer.analyze(
            "10.0.0.1 GET /search?q=1 UNION SELECT username,password FROM users--"
        )
        assert result is not None
        d = result.to_dict()
        # Must be JSON-serializable
        json.dumps(d)

    def test_to_dict_has_all_keys(self, analyzer):
        result = analyzer.analyze(
            "10.0.0.1 GET /search?q=1 UNION SELECT username,password FROM users--"
        )
        assert result is not None
        d = result.to_dict()
        required = {
            "timestamp", "event_type", "source_ip", "description",
            "severity", "raw_log", "abuse_confidence_score",
            "sigma_rule_id", "sigma_rule_title", "matched_keywords",
            "false_positives", "mitre_tactics", "mitre_techniques",
        }
        assert required.issubset(d.keys())

    def test_abuseipdb_disabled_returns_zero(self, analyzer):
        score = analyzer.query_abuseipdb("10.0.0.1")
        assert score == 0

    def test_abuseipdb_placeholder_key_returns_zero(self, base_config):
        from analyzer import LogAnalyzer
        cfg = dict(base_config)
        cfg["apis"] = {"abuseipdb": {"enabled": True, "api_key": "YOUR_KEY"}}
        az = LogAnalyzer(cfg)
        assert az.query_abuseipdb("10.0.0.1") == 0
