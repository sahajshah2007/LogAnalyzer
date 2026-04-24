"""
Tests for the database abstraction layer — SQLiteBackend, DatabaseManager,
schema creation, CRUD operations, filtering, pagination, and stats.
"""

import json
import pytest
import sqlite3
from datetime import datetime
from pathlib import Path

from database import SQLiteBackend, DatabaseManager


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _sample_alert(**overrides):
    base = {
        "timestamp": datetime.now().isoformat(),
        "event_type": "SQL_INJECTION_ATTEMPT",
        "severity": "CRITICAL",
        "source_ip": "10.0.0.1",
        "description": "SQL injection detected",
        "raw_log": "GET /search?q=1 UNION SELECT * FROM users--",
        "matched_keywords": ["union select"],
        "false_positives": ["Legitimate DB admin"],
        "mitre_tactics": ["Initial Access"],
        "mitre_techniques": ["T1190"],
        "sigma_rule_id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        "sigma_rule_title": "SQL Injection Attempt",
    }
    base.update(overrides)
    return base


# ─────────────────────────────────────────────────────────────────────────────
# SQLiteBackend
# ─────────────────────────────────────────────────────────────────────────────

class TestSQLiteBackend:
    @pytest.fixture
    def backend(self, tmp_path):
        return SQLiteBackend(str(tmp_path / "test.db"))

    def test_schema_created_on_init(self, backend):
        """alerts table must exist after init."""
        with backend.get_connection() as conn:
            tables = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
            names = {t["name"] for t in tables}
        assert "alerts" in names

    def test_indexes_created(self, backend):
        """Required indexes must be created."""
        with backend.get_connection() as conn:
            indexes = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='index'"
            ).fetchall()
            names = {i["name"] for i in indexes}
        assert "idx_severity" in names
        assert "idx_event_type" in names
        assert "idx_source_ip" in names

    def test_insert_alert_returns_id(self, backend):
        alert_id = backend.insert_alert(_sample_alert())
        assert isinstance(alert_id, int)
        assert alert_id > 0

    def test_insert_multiple_alerts_increments_id(self, backend):
        id1 = backend.insert_alert(_sample_alert())
        id2 = backend.insert_alert(_sample_alert())
        assert id2 > id1

    def test_get_alerts_returns_inserted(self, backend):
        backend.insert_alert(_sample_alert(source_ip="1.2.3.4"))
        alerts, total = backend.get_alerts({}, limit=10, offset=0)
        assert total >= 1
        ips = [a["source_ip"] for a in alerts]
        assert "1.2.3.4" in ips

    def test_get_alerts_pagination(self, backend):
        for i in range(5):
            backend.insert_alert(_sample_alert(source_ip=f"10.0.0.{i}"))
        page1, total = backend.get_alerts({}, limit=2, offset=0)
        page2, _ = backend.get_alerts({}, limit=2, offset=2)
        assert total == 5
        assert len(page1) == 2
        assert len(page2) == 2
        # Pages must not overlap
        ids1 = {a["id"] for a in page1}
        ids2 = {a["id"] for a in page2}
        assert ids1.isdisjoint(ids2)

    def test_filter_by_severity(self, backend):
        backend.insert_alert(_sample_alert(severity="CRITICAL"))
        backend.insert_alert(_sample_alert(severity="WARNING"))
        alerts, total = backend.get_alerts({"severity": "CRITICAL"}, limit=10, offset=0)
        assert total >= 1
        assert all(a["severity"] == "CRITICAL" for a in alerts)

    def test_filter_by_event_type(self, backend):
        backend.insert_alert(_sample_alert(event_type="SQL_INJECTION_ATTEMPT"))
        backend.insert_alert(_sample_alert(event_type="XSS_ATTEMPT"))
        alerts, total = backend.get_alerts(
            {"event_type": "SQL_INJECTION_ATTEMPT"}, limit=10, offset=0
        )
        assert total >= 1
        assert all(a["event_type"] == "SQL_INJECTION_ATTEMPT" for a in alerts)

    def test_filter_by_source_ip(self, backend):
        backend.insert_alert(_sample_alert(source_ip="192.168.1.50"))
        backend.insert_alert(_sample_alert(source_ip="10.0.0.1"))
        alerts, total = backend.get_alerts({"source_ip": "192.168.1.50"}, limit=10, offset=0)
        assert total >= 1
        assert all("192.168.1.50" in a["source_ip"] for a in alerts)

    def test_filter_by_search(self, backend):
        backend.insert_alert(_sample_alert(description="unique_search_term_xyz"))
        alerts, total = backend.get_alerts(
            {"search": "unique_search_term_xyz"}, limit=10, offset=0
        )
        assert total >= 1

    def test_json_columns_deserialized(self, backend):
        """matched_keywords, mitre_tactics etc. must come back as lists."""
        backend.insert_alert(_sample_alert(
            matched_keywords=["kw1", "kw2"],
            mitre_tactics=["Initial Access"],
            mitre_techniques=["T1190"],
        ))
        alerts, _ = backend.get_alerts({}, limit=1, offset=0)
        a = alerts[0]
        assert isinstance(a["matched_keywords"], list)
        assert isinstance(a["mitre_tactics"], list)
        assert isinstance(a["mitre_techniques"], list)

    def test_get_stats_structure(self, backend):
        backend.insert_alert(_sample_alert(severity="CRITICAL"))
        backend.insert_alert(_sample_alert(severity="WARNING"))
        stats = backend.get_stats()
        assert "total_alerts" in stats
        assert "by_severity" in stats
        assert "by_type" in stats
        assert "top_ips" in stats
        assert stats["total_alerts"] >= 2

    def test_get_stats_by_severity_counts(self, backend):
        backend.insert_alert(_sample_alert(severity="CRITICAL"))
        backend.insert_alert(_sample_alert(severity="CRITICAL"))
        backend.insert_alert(_sample_alert(severity="WARNING"))
        stats = backend.get_stats()
        sev_map = {s["severity"]: s["count"] for s in stats["by_severity"]}
        assert sev_map.get("CRITICAL", 0) >= 2
        assert sev_map.get("WARNING", 0) >= 1

    def test_delete_old_alerts(self, backend):
        """delete_old_alerts with a very large days value deletes nothing,
        but inserting a backdated row and deleting with days=0 removes it."""
        # Insert a row with a past timestamp by manipulating created_at
        with backend.get_connection() as conn:
            conn.execute("""
                INSERT INTO alerts (timestamp, event_type, severity, source_ip,
                    description, raw_log, created_at)
                VALUES (?, ?, ?, ?, ?, ?, datetime('now', '-31 days'))
            """, (
                "2020-01-01T00:00:00", "TEST", "INFO", "1.2.3.4",
                "old alert", "old log",
            ))
        deleted = backend.delete_old_alerts(30)
        assert deleted >= 1
        _, total = backend.get_alerts({}, limit=10, offset=0)
        assert total == 0

    def test_delete_old_alerts_keeps_recent(self, backend):
        """delete_old_alerts(30) should keep recently inserted alerts."""
        backend.insert_alert(_sample_alert())
        deleted = backend.delete_old_alerts(30)
        assert deleted == 0
        _, total = backend.get_alerts({}, limit=10, offset=0)
        assert total == 1

    def test_empty_db_stats(self, backend):
        stats = backend.get_stats()
        assert stats["total_alerts"] == 0
        assert stats["by_severity"] == []

    def test_db_file_created(self, tmp_path):
        db_path = tmp_path / "subdir" / "new.db"
        SQLiteBackend(str(db_path))
        assert db_path.exists()


# ─────────────────────────────────────────────────────────────────────────────
# DatabaseManager
# ─────────────────────────────────────────────────────────────────────────────

class TestDatabaseManager:
    @pytest.fixture
    def manager(self, tmp_path):
        config = {
            "database": {
                "type": "sqlite",
                "path": str(tmp_path / "manager_test.db"),
            }
        }
        return DatabaseManager(config)

    def test_defaults_to_sqlite(self, manager):
        assert isinstance(manager.backend, SQLiteBackend)

    def test_insert_and_retrieve(self, manager):
        alert_id = manager.insert_alert(_sample_alert())
        assert alert_id > 0
        alerts, total = manager.get_alerts()
        assert total >= 1

    def test_get_stats_delegates(self, manager):
        manager.insert_alert(_sample_alert())
        stats = manager.get_stats()
        assert stats["total_alerts"] >= 1

    def test_delete_old_alerts_delegates(self, manager):
        """Insert a backdated alert and verify delete_old_alerts removes it."""
        from database import SQLiteBackend
        assert isinstance(manager.backend, SQLiteBackend)
        with manager.backend.get_connection() as conn:
            conn.execute("""
                INSERT INTO alerts (timestamp, event_type, severity, source_ip,
                    description, raw_log, created_at)
                VALUES (?, ?, ?, ?, ?, ?, datetime('now', '-31 days'))
            """, ("2020-01-01T00:00:00", "TEST", "INFO", "1.2.3.4", "old", "old"))
        deleted = manager.delete_old_alerts(30)
        assert deleted >= 1

    def test_unknown_db_type_defaults_to_sqlite(self, tmp_path):
        config = {
            "database": {
                "type": "unknown_db",
                "path": str(tmp_path / "fallback.db"),
            }
        }
        mgr = DatabaseManager(config)
        assert isinstance(mgr.backend, SQLiteBackend)

    def test_missing_database_config_defaults_to_sqlite(self, tmp_path):
        """No database key in config should still work with SQLite default."""
        config = {}
        # Should not raise
        mgr = DatabaseManager(config)
        assert isinstance(mgr.backend, SQLiteBackend)
