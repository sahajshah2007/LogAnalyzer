"""
Tests for LogMonitor (legacy file tail) and LiveMonitor sources —
file tailing, rotation detection, availability checks, and config parsing.
"""

import os
import time
import pytest
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock


# ─────────────────────────────────────────────────────────────────────────────
# LogMonitor (legacy file tail)
# ─────────────────────────────────────────────────────────────────────────────

class TestLogMonitor:
    @pytest.fixture
    def log_file(self, tmp_path):
        f = tmp_path / "test.log"
        f.write_text("initial line\n")
        return f

    def _collect_lines(self, monitor, count=1, timeout=3.0):
        """Run monitor.tail() in a thread and collect up to `count` lines."""
        import threading
        lines = []
        done = threading.Event()
        started = threading.Event()

        def _run():
            gen = monitor.tail()
            started.set()
            for line in gen:
                lines.append(line)
                if len(lines) >= count:
                    done.set()
                    return

        t = threading.Thread(target=_run, daemon=True)
        t.start()
        started.wait(timeout=1.0)
        return lines, done

    def test_tail_yields_new_lines(self, log_file):
        from monitor import LogMonitor
        import time
        monitor = LogMonitor(str(log_file), check_interval=0.05)
        monitor._open_file()

        lines, done = self._collect_lines(monitor, count=2, timeout=5.0)

        # Small delay to ensure the generator has entered its sleep loop
        time.sleep(0.15)

        with open(log_file, "a") as f:
            f.write("new line 1\n")
            f.write("new line 2\n")

        done.wait(timeout=5.0)
        assert "new line 1" in lines
        assert "new line 2" in lines

    def test_tail_skips_existing_content(self, log_file):
        """tail() must seek to end on open — existing content is not replayed."""
        from monitor import LogMonitor
        import time
        monitor = LogMonitor(str(log_file), check_interval=0.05)
        monitor._open_file()

        lines, done = self._collect_lines(monitor, count=1, timeout=3.0)
        time.sleep(0.1)  # let the generator reach its read loop
        with open(log_file, "a") as f:
            f.write("after open\n")
        done.wait(timeout=3.0)

        assert "initial line" not in lines
        assert "after open" in lines

    def test_tail_detects_rotation(self, tmp_path):
        """When the log file is replaced (rotation), tail() reopens and reads new content."""
        from monitor import LogMonitor
        import time
        log_path = tmp_path / "rotating.log"
        log_path.write_text("old content\n")

        monitor = LogMonitor(str(log_path), check_interval=0.05)
        monitor._open_file()

        lines, done = self._collect_lines(monitor, count=1, timeout=5.0)

        # Wait for the generator to enter its sleep loop
        time.sleep(0.15)

        # Simulate rotation: delete old file, create new one
        log_path.unlink()
        log_path.write_text("")  # empty new file

        # Wait for the generator to detect rotation and reopen the file
        time.sleep(0.2)

        # Now write content to the new file — generator is now watching it
        with open(log_path, "a") as f:
            f.write("post rotation line\n")

        done.wait(timeout=5.0)
        assert any("post rotation" in l for l in lines)

    def test_context_manager(self, log_file):
        from monitor import LogMonitor
        with LogMonitor(str(log_file)) as monitor:
            assert monitor.file_handle is not None
        assert monitor.file_handle.closed

    def test_nonexistent_file_waits(self, tmp_path):
        from monitor import LogMonitor
        monitor = LogMonitor(str(tmp_path / "nonexistent.log"), check_interval=0.05)
        monitor._open_file()
        assert monitor.file_handle is None

    def test_get_inode_returns_none_for_missing_file(self, tmp_path):
        from monitor import LogMonitor
        monitor = LogMonitor(str(tmp_path / "missing.log"))
        assert monitor._get_inode() is None

    def test_get_inode_returns_int_for_existing_file(self, log_file):
        from monitor import LogMonitor
        monitor = LogMonitor(str(log_file))
        inode = monitor._get_inode()
        assert isinstance(inode, int)
        assert inode > 0


# ─────────────────────────────────────────────────────────────────────────────
# JournalctlSource
# ─────────────────────────────────────────────────────────────────────────────

class TestJournalctlSource:
    def test_is_available_when_journalctl_present(self):
        from live_monitor import JournalctlSource
        src = JournalctlSource()
        # On a Linux system with systemd this should be True
        # On CI without systemd it may be False — just check it doesn't raise
        result = src.is_available()
        assert isinstance(result, bool)

    def test_is_not_available_when_journalctl_missing(self):
        from live_monitor import JournalctlSource
        src = JournalctlSource()
        with patch("subprocess.run", side_effect=FileNotFoundError):
            assert src.is_available() is False

    def test_normalise_since_shorthand_minutes(self):
        from live_monitor import JournalctlSource
        assert JournalctlSource._normalise_since("5m") == "5 min ago"
        assert JournalctlSource._normalise_since("10min") == "10 min ago"

    def test_normalise_since_shorthand_hours(self):
        from live_monitor import JournalctlSource
        assert JournalctlSource._normalise_since("1h") == "1 hour ago"
        assert JournalctlSource._normalise_since("2hour") == "2 hour ago"

    def test_normalise_since_passthrough(self):
        from live_monitor import JournalctlSource
        assert JournalctlSource._normalise_since("1 min ago") == "1 min ago"
        assert JournalctlSource._normalise_since("now") == "now"

    def test_str_representation_no_unit(self):
        from live_monitor import JournalctlSource
        src = JournalctlSource()
        assert "journalctl" in str(src)

    def test_str_representation_with_unit(self):
        from live_monitor import JournalctlSource
        src = JournalctlSource(unit="sshd")
        assert "sshd" in str(src)


# ─────────────────────────────────────────────────────────────────────────────
# SyslogSource
# ─────────────────────────────────────────────────────────────────────────────

class TestSyslogSource:
    def test_is_available_when_syslog_exists(self, tmp_path):
        from live_monitor import SyslogSource
        syslog = tmp_path / "syslog"
        syslog.write_text("Apr 23 test log\n")
        src = SyslogSource()
        src.syslog_path = syslog
        assert src.is_available() is True

    def test_is_not_available_when_no_syslog(self, tmp_path):
        from live_monitor import SyslogSource
        src = SyslogSource()
        src.syslog_path = tmp_path / "nonexistent_syslog"
        assert src.is_available() is False

    def test_detect_syslog_path_returns_path_or_none(self):
        from live_monitor import SyslogSource
        result = SyslogSource._detect_syslog_path()
        assert result is None or isinstance(result, Path)

    def test_str_representation(self, tmp_path):
        from live_monitor import SyslogSource
        src = SyslogSource()
        src.syslog_path = tmp_path / "syslog"
        assert "syslog" in str(src)

    def test_stream_yields_new_lines(self, tmp_path):
        from live_monitor import SyslogSource
        import threading
        import time
        syslog = tmp_path / "syslog"
        syslog.write_text("")

        src = SyslogSource(check_interval=0.05)
        src.syslog_path = syslog
        src._open_file()

        lines = []
        done = threading.Event()
        started = threading.Event()

        def _run():
            gen = src.stream()
            started.set()
            for line in gen:
                lines.append(line)
                done.set()
                return

        t = threading.Thread(target=_run, daemon=True)
        t.start()
        started.wait(timeout=1.0)
        time.sleep(0.15)  # let the generator reach its read loop

        with open(syslog, "a") as f:
            f.write("Apr 23 10:00:00 host sshd: test message\n")
        done.wait(timeout=3.0)

        assert len(lines) == 1
        assert "test message" in lines[0]


# ─────────────────────────────────────────────────────────────────────────────
# ApplicationLogSource
# ─────────────────────────────────────────────────────────────────────────────

class TestApplicationLogSource:
    def test_is_available_for_existing_file(self, tmp_path):
        from live_monitor import ApplicationLogSource
        log = tmp_path / "app.log"
        log.write_text("initial\n")
        src = ApplicationLogSource(str(log))
        assert src.is_available() is True

    def test_is_not_available_for_missing_file(self, tmp_path):
        from live_monitor import ApplicationLogSource
        src = ApplicationLogSource(str(tmp_path / "missing.log"))
        assert src.is_available() is False

    def test_stream_yields_new_lines(self, tmp_path):
        from live_monitor import ApplicationLogSource
        import threading
        import time
        log = tmp_path / "app.log"
        log.write_text("")

        src = ApplicationLogSource(str(log), check_interval=0.05)
        src._open_file()

        lines = []
        done = threading.Event()

        def _run():
            for line in src.stream():
                lines.append(line)
                done.set()
                return

        t = threading.Thread(target=_run, daemon=True)
        t.start()

        # Wait for the generator to enter its sleep loop
        time.sleep(0.15)

        with open(log, "a") as f:
            f.write("new app log line\n")
        done.wait(timeout=5.0)

        assert len(lines) >= 1
        assert "new app log line" in lines[0]

    def test_rotation_detection(self, tmp_path):
        from live_monitor import ApplicationLogSource
        log = tmp_path / "app.log"
        log.write_text("old content\n")

        src = ApplicationLogSource(str(log), check_interval=0.05)
        src._open_file()
        old_inode = src.last_inode

        # Simulate rotation
        log.unlink()
        log.write_text("new content\n")

        new_inode = src._get_inode()
        assert new_inode != old_inode

    def test_str_representation(self, tmp_path):
        from live_monitor import ApplicationLogSource
        log = tmp_path / "app.log"
        src = ApplicationLogSource(str(log))
        assert "app.log" in str(src)


# ─────────────────────────────────────────────────────────────────────────────
# LiveMonitor.from_config
# ─────────────────────────────────────────────────────────────────────────────

class TestLiveMonitorFromConfig:
    def test_from_config_no_sources(self):
        from live_monitor import LiveMonitor
        monitor = LiveMonitor.from_config({})
        assert len(monitor.sources) == 0

    def test_from_config_journalctl_enabled(self):
        from live_monitor import LiveMonitor, JournalctlSource
        # units: [None] means "all units" — one JournalctlSource with unit=None
        config = {
            "live_sources": {
                "journalctl": {"enabled": True, "units": [None], "since": "1m"},
            }
        }
        monitor = LiveMonitor.from_config(config)
        assert any(isinstance(s, JournalctlSource) for s in monitor.sources)

    def test_from_config_syslog_enabled(self):
        from live_monitor import LiveMonitor, SyslogSource
        config = {
            "live_sources": {
                "syslog": {"enabled": True},
            }
        }
        monitor = LiveMonitor.from_config(config)
        assert any(isinstance(s, SyslogSource) for s in monitor.sources)

    def test_from_config_app_logs(self, tmp_path):
        from live_monitor import LiveMonitor, ApplicationLogSource
        log = tmp_path / "app.log"
        log.write_text("")
        config = {
            "live_sources": {
                "application_logs": [
                    {"path": str(log), "enabled": True},
                ]
            }
        }
        monitor = LiveMonitor.from_config(config)
        assert any(isinstance(s, ApplicationLogSource) for s in monitor.sources)

    def test_from_config_disabled_sources_excluded(self):
        from live_monitor import LiveMonitor, JournalctlSource
        config = {
            "live_sources": {
                "journalctl": {"enabled": False},
                "syslog": {"enabled": False},
            }
        }
        monitor = LiveMonitor.from_config(config)
        assert len(monitor.sources) == 0

    def test_stream_all_no_available_sources(self):
        """stream_all() with no available sources should return immediately."""
        from live_monitor import LiveMonitor
        mock_source = MagicMock()
        mock_source.is_available.return_value = False
        monitor = LiveMonitor([mock_source])
        lines = list(monitor.stream_all())
        assert lines == []
