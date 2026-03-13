"""
Log analyzer Monitor Module
Tail log files in real-time and handle log rotation
"""

import os
import time
from typing import Generator
from pathlib import Path


class LogMonitor:
    """Monitor log files in real-time, similar to 'tail -f'"""

    def __init__(self, log_path: str, check_interval: float = 1.0):
        """
        Initialize the log monitor.

        Args:
            log_path: Path to the log file to monitor
            check_interval: Time between checks for new content (seconds)
        """
        self.log_path = Path(log_path)
        self.check_interval = check_interval
        self.last_inode = None
        self.file_handle = None

    def _get_inode(self) -> int:
        """Get the inode of the log file to detect rotation."""
        if self.log_path.exists():
            return os.stat(self.log_path).st_ino
        return None

    def _open_file(self):
        """Open or reopen the log file."""
        if self.file_handle:
            self.file_handle.close()

        if self.log_path.exists():
            self.file_handle = open(self.log_path, "r", encoding="utf-8", errors="ignore")
            # Seek to end of file for initial run (skip historical logs)
            self.file_handle.seek(0, 2)
            self.last_inode = self._get_inode()
        else:
            self.file_handle = None

    def tail(self) -> Generator[str, None, None]:
        """
        Generator that yields new log lines as they are written.

        Handles log rotation by detecting inode changes.

        Yields:
            str: Lines from the log file
        """
        self._open_file()

        while True:
            if not self.log_path.exists() or self.file_handle is None:
                # File doesn't exist, wait for it
                time.sleep(self.check_interval)
                self._open_file()
                continue

            # Check for log rotation (inode change)
            current_inode = self._get_inode()
            if current_inode != self.last_inode:
                print(f"[*] Log rotation detected for {self.log_path}")
                self._open_file()

            # Read new lines
            lines = self.file_handle.readlines()
            if lines:
                for line in lines:
                    line = line.rstrip("\n")
                    if line:  # Skip empty lines
                        yield line
            else:
                # No new data, wait a bit
                time.sleep(self.check_interval)

    def __enter__(self):
        """Context manager entry."""
        self._open_file()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        if self.file_handle:
            self.file_handle.close()
