"""
Log analyzer Sigma Engine
Loads and evaluates Sigma rules against log lines using pySigma.
"""

import re
import os
import glob
from pathlib import Path
from typing import List, Optional, Dict, Any
from dataclasses import dataclass, field

import yaml
from sigma.rule import SigmaRule
from sigma.collection import SigmaCollection
from sigma.types import SigmaString

# Maps Sigma level → internal severity
_LEVEL_TO_SEVERITY = {
    "critical":      "CRITICAL",
    "high":          "CRITICAL",
    "medium":        "WARNING",
    "low":           "INFO",
    "informational": "INFO",
}

# Maps raw MITRE tactic tag → human-readable name
_TACTIC_MAP = {
    "initial_access":        "Initial Access",
    "execution":             "Execution",
    "persistence":           "Persistence",
    "privilege_escalation":  "Privilege Escalation",
    "defense_evasion":       "Defense Evasion",
    "credential_access":     "Credential Access",
    "discovery":             "Discovery",
    "lateral_movement":      "Lateral Movement",
    "collection":            "Collection",
    "command_and_control":   "Command and Control",
    "exfiltration":          "Exfiltration",
    "impact":                "Impact",
}


@dataclass
class SigmaMatchResult:
    """Result of a Sigma rule match against a log line."""
    rule_id: str
    rule_title: str
    description: str
    severity: str
    event_type: str
    mitre_tactics: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    false_positives: List[str] = field(default_factory=list)
    matched_keywords: List[str] = field(default_factory=list)


class SigmaEngine:
    """
    Loads Sigma YAML rule files and evaluates them against log lines.

    Uses keyword-based matching, extracting all string values from a rule's
    detection block and testing them case-insensitively against the raw log line.
    """

    def __init__(self, rule_paths: List[str]):
        """
        Args:
            rule_paths: List of file paths or directories containing Sigma YAML rules.
        """
        self._rules: List[tuple] = []   # (SigmaRule, [(compiled_pattern, original_text)])
        self._load_stats: Dict[str, Any] = {
            "total_loaded": 0,
            "total_skipped": 0,
            "total_errors": 0,
            "by_path": [],  # [{path, loaded, skipped, errors}]
        }
        self._load_rules(rule_paths)

    # ── Rule loading ──────────────────────────────────────────────────────────

    def _load_rules(self, rule_paths: List[str]):
        """Recursively load all .yml/.yaml Sigma rule files."""
        for path in rule_paths:
            path_obj = Path(path)
            path_stat = {"path": str(path), "loaded": 0, "skipped": 0, "errors": 0}

            if path_obj.is_dir():
                files = list(path_obj.glob("**/*.yml")) + list(path_obj.glob("**/*.yaml"))
            elif path_obj.is_file():
                files = [path_obj]
            else:
                print(f"[!] Sigma path not found: {path}")
                continue

            for f in files:
                try:
                    with open(f, "r", encoding="utf-8") as fh:
                        content = fh.read()
                    rule = SigmaRule.from_yaml(content)
                    patterns = self._extract_keyword_patterns(rule)
                    if patterns:
                        self._rules.append((rule, patterns))
                        path_stat["loaded"] += 1
                    else:
                        # Field-based rule (e.g. EventID conditions) — no extractable keywords
                        path_stat["skipped"] += 1
                except Exception as e:
                    path_stat["errors"] += 1

            self._load_stats["by_path"].append(path_stat)
            self._load_stats["total_loaded"] += path_stat["loaded"]
            self._load_stats["total_skipped"] += path_stat["skipped"]
            self._load_stats["total_errors"] += path_stat["errors"]

            label = Path(path).name or path
            print(
                f"[+] Sigma: {label:30s}  "
                f"loaded={path_stat['loaded']:4d}  "
                f"skipped={path_stat['skipped']:4d}  "
                f"errors={path_stat['errors']:3d}"
            )

        s = self._load_stats
        print(
            f"[+] Sigma engine ready: {s['total_loaded']} rules active, "
            f"{s['total_skipped']} skipped (field-only), "
            f"{s['total_errors']} parse errors"
        )

    def _extract_keyword_patterns(self, rule: SigmaRule) -> List[tuple]:
        """
        Extract all string keyword values from the rule's detection block
        and compile them as case-insensitive regex patterns.
        Returns a list of (compiled_pattern, original_text) tuples.
        """
        patterns = []
        seen = set()

        for det_name, sigma_det in rule.detection.detections.items():
            if det_name == "condition":
                continue
            for item in sigma_det.detection_items:
                if hasattr(item, "value") and item.value:
                    for val in item.value:
                        text = str(val) if isinstance(val, SigmaString) else str(val)
                        text = text.strip()
                        if text and text not in seen:
                            seen.add(text)
                            try:
                                patterns.append((re.compile(re.escape(text), re.IGNORECASE), text))
                            except re.error:
                                pass
                # Handle nested detections (SigmaDetection inside SigmaDetection)
                if hasattr(item, "detection_items"):
                    for sub in item.detection_items:
                        if hasattr(sub, "value") and sub.value:
                            for val in sub.value:
                                text = str(val).strip()
                                if text and text not in seen:
                                    seen.add(text)
                                    try:
                                        patterns.append((re.compile(re.escape(text), re.IGNORECASE), text))
                                    except re.error:
                                        pass
        return patterns

    # ── MITRE tag parsing ─────────────────────────────────────────────────────

    def _parse_mitre_tags(self, rule: SigmaRule):
        """Parse MITRE ATT&CK tactics and techniques from Sigma rule tags."""
        tactics = []
        techniques = []
        for tag in rule.tags:
            name = tag.name.lower()
            # Techniques: match tNNNN or tNNNN.NNN
            if re.match(r"^t\d{4}(\.\d{3})?$", name):
                techniques.append(name.upper())
            # Tactics: known tactic names
            elif name in _TACTIC_MAP:
                tactics.append(_TACTIC_MAP[name])
        return tactics, techniques

    # ── Matching ──────────────────────────────────────────────────────────────

    def match(self, log_line: str) -> Optional[SigmaMatchResult]:
        """
        Evaluate all loaded rules against a log line.
        Returns the first (highest severity) match, or None.

        Rules are checked in order; CRITICAL-level rules appear first because
        they are sorted below.
        """
        best: Optional[SigmaMatchResult] = None
        best_sev_rank = -1
        _SEV_RANK = {"CRITICAL": 3, "WARNING": 2, "INFO": 1}

        for rule, patterns in self._rules:
            hits = [orig for pat, orig in patterns if pat.search(log_line)]
            if not hits:
                continue

            severity = _LEVEL_TO_SEVERITY.get(rule.level.name.lower() if rule.level else "", "INFO")
            rank = _SEV_RANK.get(severity, 0)
            if rank <= best_sev_rank:
                continue  # Keep only highest-severity match

            tactics, techniques = self._parse_mitre_tags(rule)
            fps = rule.falsepositives if rule.falsepositives else []

            # Derive a clean event_type from the rule title
            event_type = re.sub(r"[^A-Z0-9]+", "_",
                                rule.title.upper()).strip("_")

            best_sev_rank = rank
            best = SigmaMatchResult(
                rule_id=str(rule.id) if rule.id else "",
                rule_title=rule.title,
                description=rule.description or rule.title,
                severity=severity,
                event_type=event_type,
                mitre_tactics=tactics,
                mitre_techniques=techniques,
                false_positives=[str(f) for f in fps],
                matched_keywords=hits,
            )

        return best

    def match_all(self, log_line: str) -> List[SigmaMatchResult]:
        """Return all rule matches for a log line (not just the best)."""
        results = []
        for rule, patterns in self._rules:
            hits = [orig for pat, orig in patterns if pat.search(log_line)]
            if not hits:
                continue
            severity = _LEVEL_TO_SEVERITY.get(rule.level.name.lower() if rule.level else "", "INFO")
            tactics, techniques = self._parse_mitre_tags(rule)
            fps = rule.falsepositives if rule.falsepositives else []
            event_type = re.sub(r"[^A-Z0-9]+", "_", rule.title.upper()).strip("_")
            results.append(SigmaMatchResult(
                rule_id=str(rule.id) if rule.id else "",
                rule_title=rule.title,
                description=rule.description or rule.title,
                severity=severity,
                event_type=event_type,
                mitre_tactics=tactics,
                mitre_techniques=techniques,
                false_positives=[str(f) for f in fps],
                matched_keywords=hits,
            ))
        return results

    @property
    def rule_count(self) -> int:
        return len(self._rules)

    @property
    def load_stats(self) -> Dict[str, Any]:
        return self._load_stats

    def list_rules_metadata(self) -> List[Dict[str, Any]]:
        """Return metadata for all loaded rules (used by /api/sigma/rules)."""
        out = []
        for rule, patterns in self._rules:
            tactics, techniques = self._parse_mitre_tags(rule)
            out.append({
                "id":           str(rule.id) if rule.id else "",
                "title":        rule.title,
                "description":  rule.description or "",
                "level":        rule.level.name.lower() if rule.level else "medium",
                "status":       rule.status.name.lower() if rule.status else "",
                "tags":         [str(t) for t in rule.tags],
                "mitre_tactics":    tactics,
                "mitre_techniques": techniques,
                "false_positives":  [str(f) for f in rule.falsepositives] if rule.falsepositives else [],
                "keyword_count":    len(patterns),
            })
        return out
