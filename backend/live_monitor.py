"""
Log analyzer Live Monitor Module
Captures logs from live system sources in real-time
"""

import subprocess
import os
import time
from typing import Generator, Optional
from pathlib import Path
from abc import ABC, abstractmethod
import logging


class LiveLogSource(ABC):
    """Abstract base class for live log sources"""

    def __init__(self, name: str):
        self.name = name
        self.logger = logging.getLogger(f"LiveMonitor.{name}")

    @abstractmethod
    def stream(self) -> Generator[str, None, None]:
        """Stream log lines from the source"""
        pass

    @abstractmethod
    def is_available(self) -> bool:
        """Check if the source is available on this system"""
        pass


class JournalctlSource(LiveLogSource):
    """Monitor systemd/journalctl logs"""

    def __init__(self, unit: Optional[str] = None, since: str = "10m"):
        """
        Initialize journalctl source.

        Args:
            unit: Specific systemd unit to monitor (e.g., 'sshd', 'apache2')
            since: How far back to start (e.g., '10m', '1h', 'now')
        """
        super().__init__("journalctl")
        self.unit = unit
        self.since = since

    def is_available(self) -> bool:
        """Check if journalctl is available"""
        try:
            subprocess.run(["journalctl", "--version"], capture_output=True, timeout=2)
            return True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def stream(self) -> Generator[str, None, None]:
        """Stream logs from journalctl with follow mode, auto-retry on disconnect."""
        cmd = ["journalctl", "--since", self.since, "--follow", "--output", "short"]

        if self.unit:
            cmd.extend(["--unit", self.unit])

        while True:
            process = None
            try:
                process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    bufsize=1,  # Line buffered
                )

                while True:
                    line = process.stdout.readline()
                    if not line:
                        break
                    line = line.rstrip("\n")
                    if line:
                        yield line

            except Exception as e:
                self.logger.error(f"Error reading from journalctl: {e}")

            finally:
                if process and process.poll() is None:
                    process.terminate()

            # Stream ended — wait and retry
            self.logger.info(f"journalctl stream ended for {self.unit or 'all'}, retrying in 5s...")
            time.sleep(5)
            # After first run switch to "now" so we only get new entries on retry
            cmd = ["journalctl", "--since", "now", "--follow", "--output", "short"]
            if self.unit:
                cmd.extend(["--unit", self.unit])

    def __str__(self):
        return f"journalctl({'unit=' + self.unit if self.unit else 'all'})"


class SyslogSource(LiveLogSource):
    """Monitor syslog files and streams"""

    def __init__(self, facility: Optional[str] = None, check_interval: float = 1.0):
        """
        Initialize syslog source.

        Args:
            facility: Syslog facility filter (e.g., 'auth', 'sshd')
            check_interval: Time between checks for new content (seconds)
        """
        super().__init__("syslog")
        self.facility = facility
        self.check_interval = check_interval
        self.syslog_path = self._detect_syslog_path()
        self.file_handle = None
        self.last_position = 0

    @staticmethod
    def _detect_syslog_path() -> Optional[Path]:
        """Detect the syslog file path on this system"""
        possible_paths = [
            "/var/log/syslog",  # Debian/Ubuntu
            "/var/log/messages",  # RHEL/CentOS
            "/var/log/system.log",  # macOS
        ]

        for path in possible_paths:
            if Path(path).exists():
                return Path(path)
        return None

    def is_available(self) -> bool:
        """Check if syslog is available"""
        return self.syslog_path is not None and self.syslog_path.exists()

    def _open_file(self):
        """Open the syslog file"""
        if self.file_handle:
            self.file_handle.close()

        if self.syslog_path and self.syslog_path.exists():
            try:
                self.file_handle = open(
                    self.syslog_path, "r", encoding="utf-8", errors="ignore"
                )
                # Seek to current end
                self.file_handle.seek(0, 2)
                self.last_position = self.file_handle.tell()
            except PermissionError:
                self.logger.error(f"Permission denied reading {self.syslog_path}")
                self.file_handle = None

    def stream(self) -> Generator[str, None, None]:
        """Stream logs from syslog file"""
        self._open_file()

        while True:
            if not self.syslog_path or not self.syslog_path.exists():
                time.sleep(self.check_interval)
                continue

            if self.file_handle is None:
                self._open_file()

            # Check for file rotation by size
            try:
                current_size = self.syslog_path.stat().st_size
                if current_size < self.last_position:
                    # File was rotated
                    self.logger.info("Syslog file rotation detected")
                    self._open_file()
            except (OSError, RuntimeError):
                time.sleep(self.check_interval)
                continue

            # Read new lines
            try:
                lines = self.file_handle.readlines()
                if lines:
                    for line in lines:
                        line = line.rstrip("\n")
                        # Filter by facility if specified
                        if self.facility and self.facility not in line:
                            continue
                        if line:
                            yield line
                    self.last_position = self.file_handle.tell()
                else:
                    time.sleep(self.check_interval)
            except IOError:
                time.sleep(self.check_interval)

    def __str__(self):
        return f"syslog({self.syslog_path})"


class ApplicationLogSource(LiveLogSource):
    """Monitor application-specific log files"""

    def __init__(self, log_path: str, check_interval: float = 1.0):
        """
        Initialize application log source.

        Args:
            log_path: Path to the application log file
            check_interval: Time between checks for new content (seconds)
        """
        super().__init__("app_log")
        self.log_path = Path(log_path)
        self.check_interval = check_interval
        self.file_handle = None
        self.last_inode = None

    def is_available(self) -> bool:
        """Check if the log file exists and is readable"""
        return self.log_path.exists() and os.access(self.log_path, os.R_OK)

    def _get_inode(self) -> Optional[int]:
        """Get the inode of the log file to detect rotation"""
        if self.log_path.exists():
            return os.stat(self.log_path).st_ino
        return None

    def _open_file(self):
        """Open or reopen the log file"""
        if self.file_handle:
            self.file_handle.close()

        if self.log_path.exists():
            try:
                self.file_handle = open(
                    self.log_path, "r", encoding="utf-8", errors="ignore"
                )
                # Seek to end of file for initial run
                self.file_handle.seek(0, 2)
                self.last_inode = self._get_inode()
            except PermissionError:
                self.logger.error(f"Permission denied reading {self.log_path}")
                self.file_handle = None

    def stream(self) -> Generator[str, None, None]:
        """Stream logs from application log file"""
        self._open_file()

        while True:
            if not self.log_path.exists() or self.file_handle is None:
                time.sleep(self.check_interval)
                self._open_file()
                continue

            # Check for log rotation (inode change)
            current_inode = self._get_inode()
            if current_inode != self.last_inode:
                self.logger.info(f"Log rotation detected for {self.log_path}")
                self._open_file()

            # Read new lines
            try:
                lines = self.file_handle.readlines()
                if lines:
                    for line in lines:
                        line = line.rstrip("\n")
                        if line:
                            yield line
                else:
                    time.sleep(self.check_interval)
            except IOError:
                time.sleep(self.check_interval)

    def __str__(self):
        return f"app_log({self.log_path})"


class LiveMonitor:
    """Monitor multiple live log sources simultaneously"""

    def __init__(self, sources: list):
        """
        Initialize the live monitor.

        Args:
            sources: List of LiveLogSource instances to monitor
        """
        self.sources = sources
        self.logger = logging.getLogger("LiveMonitor")

    def stream_all(self) -> Generator[tuple[str, str], None, None]:
        """
        Stream logs from all sources simultaneously.

        Yields:
            tuple: (source_name, log_line)

        Note: This uses a simple round-robin approach. For production,
        consider using selectors or asyncio for true concurrent streaming.
        """
        file_handles = {}
        source_gens = {}

        # Initialize generators for all available sources
        for source in self.sources:
            if source.is_available():
                try:
                    source_gens[source.name] = source.stream()
                    self.logger.info(f"Streaming from: {source}")
                except Exception as e:
                    self.logger.error(f"Failed to start streaming from {source}: {e}")

        if not source_gens:
            self.logger.error("No log sources available!")
            return

        # Round-robin through sources
        available_sources = list(source_gens.keys())
        idle_cycles = 0

        while available_sources:
            got_line = False
            for source_name in list(available_sources):
                try:
                    line = next(source_gens[source_name])
                    yield (source_name, line)
                    got_line = True
                    idle_cycles = 0
                except StopIteration:
                    self.logger.warning(f"Stream ended for {source_name}, restarting...")
                    # Try to restart the source
                    for src in self.sources:
                        if src.name == source_name and src.is_available():
                            try:
                                source_gens[source_name] = src.stream()
                            except Exception:
                                available_sources.remove(source_name)
                            break
                    else:
                        available_sources.remove(source_name)
                except Exception as e:
                    self.logger.error(f"Error reading from {source_name}: {e}")
                    available_sources.remove(source_name)

            if not got_line:
                idle_cycles += 1
                time.sleep(min(idle_cycles * 0.5, 5))  # Back off up to 5s when idle

            if not available_sources:
                break

    @classmethod
    def from_config(cls, config: dict) -> "LiveMonitor":
        """
        Create a LiveMonitor from configuration.

        Args:
            config: Configuration dictionary with 'live_sources' key

        Returns:
            LiveMonitor instance
        """
        sources = []
        sources_config = config.get("live_sources", {})

        # Add journalctl sources
        if sources_config.get("journalctl", {}).get("enabled", False):
            jc_config = sources_config.get("journalctl", {})
            units = jc_config.get("units", [None])  # None = all units
            for unit in units:
                sources.append(
                    JournalctlSource(
                        unit=unit, since=jc_config.get("since", "10m")
                    )
                )

        # Add syslog source
        if sources_config.get("syslog", {}).get("enabled", False):
            syslog_config = sources_config.get("syslog", {})
            sources.append(
                SyslogSource(facility=syslog_config.get("facility", None))
            )

        # Add application log sources
        app_logs = sources_config.get("application_logs") or []
        for log_config in app_logs:
            if isinstance(log_config, dict) and log_config.get("enabled", False):
                sources.append(ApplicationLogSource(log_config["path"]))
            elif isinstance(log_config, str):
                # Simple string path
                sources.append(ApplicationLogSource(log_config))

        return cls(sources)
