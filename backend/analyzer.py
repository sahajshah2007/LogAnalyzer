"""
Log analyzer Analyzer Module
Processes log lines to detect threats using Sigma rules + MITRE ATT&CK mapping.
"""

import re
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional
from collections import defaultdict
from datetime import datetime
import requests

from sigma_engine import SigmaEngine


@dataclass
class LogEvent:
    """Represents a parsed log event."""
    timestamp: str
    raw_line: str
    source_ip: str
    user: Optional[str] = None
    action: str = ""
    severity: str = "INFO"


@dataclass
class ThreatAlert:
    """Represents a detected threat alert with MITRE ATT&CK mapping."""
    timestamp: datetime
    event_type: str
    source_ip: str
    description: str
    severity: str                         # INFO | WARNING | CRITICAL
    raw_log: str
    abuse_confidence_score: int = 0

    # Sigma rule metadata
    sigma_rule_id: str = ""
    sigma_rule_title: str = ""
    matched_keywords: List[str] = field(default_factory=list)
    false_positives: List[str] = field(default_factory=list)

    # MITRE ATT&CK
    mitre_tactics: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        """Convert to dictionary for database / API storage."""
        return {
            "timestamp":               self.timestamp.isoformat(),
            "event_type":              self.event_type,
            "source_ip":               self.source_ip,
            "description":             self.description,
            "severity":                self.severity,
            "raw_log":                 self.raw_log,
            "abuse_confidence_score":  self.abuse_confidence_score,
            "sigma_rule_id":           self.sigma_rule_id,
            "sigma_rule_title":        self.sigma_rule_title,
            "matched_keywords":        self.matched_keywords,
            "false_positives":         self.false_positives,
            "mitre_tactics":           self.mitre_tactics,
            "mitre_techniques":        self.mitre_techniques,
        }


class LogAnalyzer:
    """Analyzes log lines for security threats using the Sigma engine."""

    def __init__(self, config: dict):
        self.config = config
        self.whitelist_ips = self._parse_whitelist()

        # Brute-force state tracking (kept independently of Sigma)
        self.failed_logins: Dict[str, List[float]] = defaultdict(list)
        self.brute_force_threshold = config.get("thresholds", {}).get("max_failed_logins", 5)
        self.login_window = config.get("thresholds", {}).get("failed_login_window", 60)

        # Sigma engine
        sigma_paths = self._resolve_sigma_paths(config)
        self.sigma = SigmaEngine(sigma_paths)

    # ── Config helpers ────────────────────────────────────────────────────────

    def _resolve_sigma_paths(self, config: dict) -> List[str]:
        """Resolve Sigma rule paths relative to the project root."""
        from pathlib import Path

        project_root = Path(__file__).parent.parent

        raw_paths = (
            config.get("sigma_rules", {}).get("paths", [])
            or config.get("sigma_rules", {}).get("files", [])
        )

        if not raw_paths:
            default = project_root / "sigma" / "rules"
            return [str(default)] if default.exists() else []

        resolved = []
        for p in raw_paths:
            p = Path(p)
            if not p.is_absolute():
                p = project_root / p
            resolved.append(str(p))
        return resolved

    def _parse_whitelist(self) -> List[str]:
        return self.config.get("whitelist", {}).get("ips", [])

    def _is_whitelisted(self, ip: str) -> bool:
        if ip in self.whitelist_ips:
            return True
        for w in self.whitelist_ips:
            if "/" in w:
                network = w.split("/")[0]
                if ip.startswith(network.rsplit(".", 1)[0]):
                    return True
        return False

    # ── Extraction helpers ────────────────────────────────────────────────────

    def _extract_ip(self, log_line: str) -> Optional[str]:
        m = re.search(
            r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b",
            log_line,
        )
        return m.group(0) if m else None

    def _extract_timestamp(self, log_line: str) -> str:
        m = re.search(r"^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})", log_line)
        return m.group(1) if m else datetime.now().strftime("%b %d %H:%M:%S")

    def parse_log_line(self, line: str) -> LogEvent:
        ip = self._extract_ip(line)
        timestamp = self._extract_timestamp(line)
        user_m = re.search(r"(?:for|user)\s+(\w+)", line)
        return LogEvent(
            timestamp=timestamp,
            raw_line=line,
            source_ip=ip or "UNKNOWN",
            user=user_m.group(1) if user_m else None,
        )

    # ── Brute-force tracker ───────────────────────────────────────────────────

    _FAILED_LOGIN_RE = re.compile(
        r"Failed password|Invalid user|Authentication failure|sshd.*Failed|"
        r"denied by pam|failed.*ssh|Too many authentication failures",
        re.IGNORECASE,
    )

    def _track_brute_force(self, event: LogEvent) -> Optional[ThreatAlert]:
        """
        Independently track failed login counts per IP.
        Returns a BRUTE_FORCE alert once the threshold is exceeded.
        """
        if not self._FAILED_LOGIN_RE.search(event.raw_line):
            return None
        if self._is_whitelisted(event.source_ip):
            return None

        now = time.time()
        window_start = now - self.login_window
        self.failed_logins[event.source_ip].append(now)
        self.failed_logins[event.source_ip] = [
            t for t in self.failed_logins[event.source_ip] if t > window_start
        ]

        count = len(self.failed_logins[event.source_ip])
        if count >= self.brute_force_threshold:
            return ThreatAlert(
                timestamp=datetime.now(),
                event_type="BRUTE_FORCE",
                source_ip=event.source_ip,
                description=(
                    f"{count} failed login attempts from {event.source_ip} "
                    f"within {self.login_window}s"
                ),
                severity="CRITICAL",
                raw_log=event.raw_line,
                sigma_rule_title="SSH Brute Force Authentication Failure",
                mitre_tactics=["Credential Access"],
                mitre_techniques=["T1110.001"],
            )
        return None

    # ── AbuseIPDB ─────────────────────────────────────────────────────────────

    def query_abuseipdb(self, ip: str) -> int:
        api_cfg = self.config.get("apis", {}).get("abuseipdb", {})
        if not api_cfg.get("enabled"):
            return 0
        key = api_cfg.get("api_key", "")
        if not key or key.startswith("YOUR_"):
            return 0
        try:
            r = requests.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={"Key": key, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": 90},
                timeout=api_cfg.get("timeout", 5),
            )
            if r.status_code == 200:
                return int(r.json().get("data", {}).get("abuseConfidenceScore", 0))
        except requests.RequestException:
            pass
        return 0

    # ── Main entry ────────────────────────────────────────────────────────────

    def analyze(self, log_line: str) -> Optional[ThreatAlert]:
        """
        Analyze a raw log line.

        1. Parse the line into a LogEvent.
        2. Check the brute-force counter independently (threshold-based).
        3. Run all Sigma rules against the line.
        4. Return the highest-severity match.
        """
        if not log_line.strip():
            return None

        event = self.parse_log_line(log_line)

        # Brute-force counter (threshold-based, not just single-line)
        bf_alert = self._track_brute_force(event)
        if bf_alert:
            return bf_alert

        # Sigma rule matching
        match = self.sigma.match(log_line)
        if match is None:
            return None

        ip = event.source_ip
        if ip != "UNKNOWN" and self._is_whitelisted(ip):
            return None

        return ThreatAlert(
            timestamp=datetime.now(),
            event_type=match.event_type,
            source_ip=ip,
            description=match.description,
            severity=match.severity,
            raw_log=log_line,
            sigma_rule_id=match.rule_id,
            sigma_rule_title=match.rule_title,
            matched_keywords=match.matched_keywords,
            false_positives=match.false_positives,
            mitre_tactics=match.mitre_tactics,
            mitre_techniques=match.mitre_techniques,
        )
