"""
Shared fixtures and configuration for the SentinelLog test suite.
"""

import os
import sys
import json
import sqlite3
import tempfile
import pytest
from pathlib import Path
from datetime import datetime
from unittest.mock import MagicMock, patch

# ── Make backend importable ───────────────────────────────────────────────────
BACKEND_DIR = Path(__file__).parent.parent / "backend"
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(BACKEND_DIR))
sys.path.insert(0, str(PROJECT_ROOT))


# ── Minimal config used across tests ─────────────────────────────────────────
@pytest.fixture
def base_config(tmp_path):
    """Minimal config dict pointing at a temp SQLite DB and real sigma rules."""
    db = tmp_path / "test_alerts.db"
    return {
        "database": {
            "type": "sqlite",
            "path": str(db),
        },
        "sigma_rules": {
            "paths": [str(PROJECT_ROOT / "sigma" / "rules")],
        },
        "thresholds": {
            "max_failed_logins": 3,
            "failed_login_window": 60,
        },
        "whitelist": {"ips": []},
        "discord": {"enabled": False},
        "apis": {"abuseipdb": {"enabled": False}},
    }


@pytest.fixture
def config_with_whitelist(base_config):
    """Config with a whitelisted IP."""
    cfg = dict(base_config)
    cfg["whitelist"] = {"ips": ["192.168.1.100", "10.0.0.0/24"]}
    return cfg


@pytest.fixture
def temp_db(tmp_path):
    """Isolated SQLite database for each test."""
    db_path = tmp_path / "alerts.db"
    conn = sqlite3.connect(str(db_path))
    conn.execute("""
        CREATE TABLE alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            event_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            source_ip TEXT,
            description TEXT,
            raw_log TEXT,
            matched_keywords TEXT DEFAULT '[]',
            false_positives TEXT DEFAULT '[]',
            mitre_tactics TEXT DEFAULT '[]',
            mitre_techniques TEXT DEFAULT '[]',
            sigma_rule_id TEXT,
            sigma_rule_title TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.execute("""
        CREATE TABLE live_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            source TEXT,
            message TEXT NOT NULL,
            is_alert INTEGER DEFAULT 0,
            severity TEXT,
            event_type TEXT,
            description TEXT,
            source_ip TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    conn.close()
    return db_path


@pytest.fixture
def sigma_engine():
    """Real SigmaEngine loaded from the project's sigma/rules directory."""
    from sigma_engine import SigmaEngine
    return SigmaEngine([str(PROJECT_ROOT / "sigma" / "rules")])


@pytest.fixture
def analyzer(base_config):
    """LogAnalyzer instance with real Sigma rules."""
    from analyzer import LogAnalyzer
    return LogAnalyzer(base_config)


@pytest.fixture
def make_threat_alert():
    """Factory for ThreatAlert objects."""
    from analyzer import ThreatAlert

    def _make(
        event_type="SSH_BRUTE_FORCE_AUTHENTICATION_FAILURE",
        source_ip="10.0.0.1",
        severity="CRITICAL",
        description="Test alert",
        raw_log="Apr 23 sshd: Failed password for root from 10.0.0.1",
        mitre_tactics=None,
        mitre_techniques=None,
        matched_keywords=None,
    ):
        return ThreatAlert(
            timestamp=datetime.now(),
            event_type=event_type,
            source_ip=source_ip,
            description=description,
            severity=severity,
            raw_log=raw_log,
            mitre_tactics=mitre_tactics or ["Credential Access"],
            mitre_techniques=mitre_techniques or ["T1110.001"],
            matched_keywords=matched_keywords or ["Failed password"],
        )

    return _make


@pytest.fixture
def api_client(tmp_path, base_config):
    """
    FastAPI TestClient with an isolated database.
    Patches DB_PATH and CONFIG_PATH so tests never touch the real alerts.db.
    """
    import api as api_module
    from fastapi.testclient import TestClient

    db_path = tmp_path / "test_alerts.db"

    # Reset module-level singletons so each test starts clean
    api_module._sigma_engine = None
    api_module._event_analyzer = None
    api_module._alert_manager = None
    api_module._monitor_proc = None

    with (
        patch.object(api_module, "DB_PATH", db_path),
        patch.object(api_module, "CONFIG_PATH", PROJECT_ROOT / "config.yaml"),
    ):
        api_module._ensure_db()
        client = TestClient(api_module.app, raise_server_exceptions=True)
        yield client
