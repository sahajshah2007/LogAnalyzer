"""
Log analyzer Sigma Engine
Loads and evaluates Sigma rules against log lines.

Detection strategy
──────────────────
All 15 bundled rules use the Sigma `keywords` detection style:

    detection:
      keywords:
        - "some string"
        - "another string"
      condition: keywords

pySigma's internal API for walking detection items is fragile across
versions, so we parse the YAML directly for keyword extraction and use
pySigma only for validated metadata (title, description, level, tags).

Condition support
─────────────────
  keywords          – ANY keyword matches  (OR logic)
  keywords | all    – ALL keywords must match (AND logic)
  selection         – ANY item in the selection list matches (OR logic)
  selection | all   – ALL items must match (AND logic)
  1 of them         – at least one named detection group matches
  all of them       – every named detection group must match
  <name> and <name> – both groups must match
  <name> or <name>  – either group matches
"""

import re
import yaml
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from dataclasses import dataclass, field

# ── Optional pySigma import (used only for metadata validation) ───────────────
try:
    from sigma.rule import SigmaRule as _PySigmaRule
    _PYSIGMA_AVAILABLE = True
except ImportError:
    _PYSIGMA_AVAILABLE = False

# ── Severity mapping ──────────────────────────────────────────────────────────
_LEVEL_TO_SEVERITY: Dict[str, str] = {
    "critical":      "CRITICAL",
    "high":          "CRITICAL",
    "medium":        "WARNING",
    "low":           "INFO",
    "informational": "INFO",
}

# ── MITRE tactic tag → human-readable name ────────────────────────────────────
_TACTIC_MAP: Dict[str, str] = {
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

_SEV_RANK: Dict[str, int] = {"CRITICAL": 3, "WARNING": 2, "INFO": 1}


# ─────────────────────────────────────────────────────────────────────────────
# Data classes
# ─────────────────────────────────────────────────────────────────────────────

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


@dataclass
class _CompiledRule:
    """Internal representation of a loaded and compiled Sigma rule."""
    rule_id: str
    title: str
    description: str
    severity: str                        # CRITICAL | WARNING | INFO
    event_type: str
    mitre_tactics: List[str]
    mitre_techniques: List[str]
    false_positives: List[str]
    # Detection groups: name → list of (compiled_pattern, original_text)
    groups: Dict[str, List[Tuple[re.Pattern, str]]]
    # Parsed condition expression
    condition: str
    # Raw keyword count for metadata
    keyword_count: int


# ─────────────────────────────────────────────────────────────────────────────
# SigmaEngine
# ─────────────────────────────────────────────────────────────────────────────

class SigmaEngine:
    """
    Loads Sigma YAML rule files and evaluates them against raw log lines.

    Keyword extraction and condition evaluation are done via direct YAML
    parsing so the engine works reliably regardless of pySigma version.
    """

    def __init__(self, rule_paths: List[str]):
        self._rules: List[_CompiledRule] = []
        self._load_stats: Dict[str, Any] = {
            "total_loaded": 0,
            "total_skipped": 0,
            "total_errors": 0,
            "by_path": [],
        }
        self._load_rules(rule_paths)

    # ── Rule loading ──────────────────────────────────────────────────────────

    def _load_rules(self, rule_paths: List[str]) -> None:
        for path in rule_paths:
            path_obj = Path(path)
            stat = {"path": str(path), "loaded": 0, "skipped": 0, "errors": 0}

            if path_obj.is_dir():
                files = sorted(
                    list(path_obj.glob("**/*.yml")) +
                    list(path_obj.glob("**/*.yaml"))
                )
            elif path_obj.is_file():
                files = [path_obj]
            else:
                print(f"[!] Sigma path not found: {path}")
                continue

            for f in files:
                try:
                    compiled = self._compile_rule_file(f)
                    if compiled:
                        self._rules.append(compiled)
                        stat["loaded"] += 1
                    else:
                        stat["skipped"] += 1
                except Exception as exc:
                    stat["errors"] += 1
                    print(f"[!] Sigma error loading {f.name}: {exc}")

            self._load_stats["by_path"].append(stat)
            self._load_stats["total_loaded"] += stat["loaded"]
            self._load_stats["total_skipped"] += stat["skipped"]
            self._load_stats["total_errors"] += stat["errors"]

            label = Path(path).name or str(path)
            print(
                f"[+] Sigma: {label:30s}  "
                f"loaded={stat['loaded']:4d}  "
                f"skipped={stat['skipped']:4d}  "
                f"errors={stat['errors']:3d}"
            )

        s = self._load_stats
        print(
            f"[+] Sigma engine ready: {s['total_loaded']} rules active, "
            f"{s['total_skipped']} skipped, "
            f"{s['total_errors']} parse errors"
        )

    def _compile_rule_file(self, path: Path) -> Optional[_CompiledRule]:
        """Parse a single Sigma YAML file and return a compiled rule."""
        with open(path, "r", encoding="utf-8") as fh:
            raw = yaml.safe_load(fh.read())

        if not isinstance(raw, dict):
            return None

        detection = raw.get("detection", {})
        if not detection:
            return None

        # ── Extract detection groups ──────────────────────────────────────────
        groups: Dict[str, List[Tuple[re.Pattern, str]]] = {}
        for group_name, group_value in detection.items():
            if group_name == "condition":
                continue
            patterns = self._extract_patterns(group_value)
            if patterns:
                groups[group_name] = patterns

        if not groups:
            return None  # No extractable patterns → skip

        condition = str(detection.get("condition", "keywords")).strip().lower()

        # ── Metadata ──────────────────────────────────────────────────────────
        title = str(raw.get("title", path.stem))
        description = str(raw.get("description", title))
        level = str(raw.get("level", "medium")).lower()
        severity = _LEVEL_TO_SEVERITY.get(level, "WARNING")
        rule_id = str(raw.get("id", ""))
        fps = raw.get("falsepositives", [])
        if isinstance(fps, str):
            fps = [fps]
        fps = [str(f) for f in (fps or [])]

        tactics, techniques = self._parse_mitre_tags(raw.get("tags", []))

        event_type = re.sub(r"[^A-Z0-9]+", "_", title.upper()).strip("_")

        keyword_count = sum(len(v) for v in groups.values())

        return _CompiledRule(
            rule_id=rule_id,
            title=title,
            description=description,
            severity=severity,
            event_type=event_type,
            mitre_tactics=tactics,
            mitre_techniques=techniques,
            false_positives=fps,
            groups=groups,
            condition=condition,
            keyword_count=keyword_count,
        )

    # ── Pattern extraction ────────────────────────────────────────────────────

    # Patterns that look like regexes (contain .*, \d, \w, etc.)
    _REGEX_HINT = re.compile(r'\.\*|\\d|\\w|\\s|\[\^|\(\?|\(\.\)')

    def _extract_patterns(self, value: Any) -> List[Tuple[re.Pattern, str]]:
        """
        Recursively extract string patterns from a detection group value.

        Handles:
          - Plain list of strings (keywords list)
          - Dict of field: [values]  (field-based selection)
          - Nested lists/dicts

        If a string looks like a regex (contains .*, \\d, etc.) it is compiled
        directly as a regex rather than being escaped.  This supports the common
        pattern of writing regex-style keywords in Sigma rules.
        """
        patterns: List[Tuple[re.Pattern, str]] = []
        seen: set = set()

        def _collect(v: Any) -> None:
            if isinstance(v, str):
                text = v.strip()
                if not text or text in seen:
                    return
                seen.add(text)
                try:
                    if self._REGEX_HINT.search(text):
                        # Treat as a native regex
                        patterns.append((re.compile(text, re.IGNORECASE), text))
                    else:
                        # Treat as a literal string
                        patterns.append(
                            (re.compile(re.escape(text), re.IGNORECASE), text)
                        )
                except re.error:
                    # Fall back to literal if regex compilation fails
                    try:
                        patterns.append(
                            (re.compile(re.escape(text), re.IGNORECASE), text)
                        )
                    except re.error:
                        pass
            elif isinstance(v, list):
                for item in v:
                    _collect(item)
            elif isinstance(v, dict):
                for sub in v.values():
                    _collect(sub)

        _collect(value)
        return patterns

    # ── MITRE tag parsing ─────────────────────────────────────────────────────

    def _parse_mitre_tags(self, tags: Any) -> Tuple[List[str], List[str]]:
        """
        Parse MITRE ATT&CK tactics and techniques from Sigma rule tags.

        Tags look like:
          - attack.credential_access
          - attack.t1110.001
        """
        tactics: List[str] = []
        techniques: List[str] = []

        if not tags:
            return tactics, techniques

        for tag in tags:
            tag_str = str(tag).lower()
            # Strip leading namespace (e.g. "attack.")
            if "." in tag_str:
                parts = tag_str.split(".", 1)
                name = parts[1]
            else:
                name = tag_str

            # Technique: tNNNN or tNNNN.NNN
            if re.match(r"^t\d{4}(\.\d{3})?$", name):
                techniques.append(name.upper())
            # Tactic: known tactic slug
            elif name in _TACTIC_MAP:
                tactics.append(_TACTIC_MAP[name])

        return tactics, techniques

    # ── Condition evaluation ──────────────────────────────────────────────────

    def _eval_condition(
        self,
        condition: str,
        groups: Dict[str, List[Tuple[re.Pattern, str]]],
        log_line: str,
    ) -> List[str]:
        """
        Evaluate a Sigma condition string against a log line.

        Returns the list of matched keyword strings (non-empty = match).
        Supports:
          keywords / selection          → any keyword in the group matches
          keywords | all / selection | all → all keywords must match
          1 of them                     → any group matches
          all of them                   → all groups must match
          <name> and <name>             → both groups match
          <name> or <name>              → either group matches
        """
        hits: List[str] = []

        # ── "1 of them" ───────────────────────────────────────────────────────
        if re.match(r"^1\s+of\s+them$", condition):
            for patterns in groups.values():
                group_hits = [orig for pat, orig in patterns if pat.search(log_line)]
                if group_hits:
                    hits.extend(group_hits)
                    break
            return hits

        # ── "all of them" ─────────────────────────────────────────────────────
        if re.match(r"^all\s+of\s+them$", condition):
            for patterns in groups.values():
                group_hits = [orig for pat, orig in patterns if pat.search(log_line)]
                if not group_hits:
                    return []  # One group failed → no match
                hits.extend(group_hits)
            return hits

        # ── "1 of <name>*" ────────────────────────────────────────────────────
        m = re.match(r"^1\s+of\s+(\w+)\*?$", condition)
        if m:
            prefix = m.group(1)
            for gname, patterns in groups.items():
                if gname.startswith(prefix):
                    group_hits = [orig for pat, orig in patterns if pat.search(log_line)]
                    if group_hits:
                        hits.extend(group_hits)
                        break
            return hits

        # ── "all of <name>*" ─────────────────────────────────────────────────
        m = re.match(r"^all\s+of\s+(\w+)\*?$", condition)
        if m:
            prefix = m.group(1)
            for gname, patterns in groups.items():
                if gname.startswith(prefix):
                    group_hits = [orig for pat, orig in patterns if pat.search(log_line)]
                    if not group_hits:
                        return []
                    hits.extend(group_hits)
            return hits

        # ── Compound: "A and B" / "A or B" ───────────────────────────────────
        if " and " in condition:
            parts = [p.strip() for p in condition.split(" and ")]
            for part in parts:
                part_hits = self._eval_single_group(part, groups, log_line)
                if not part_hits:
                    return []
                hits.extend(part_hits)
            return hits

        if " or " in condition:
            parts = [p.strip() for p in condition.split(" or ")]
            for part in parts:
                part_hits = self._eval_single_group(part, groups, log_line)
                if part_hits:
                    return part_hits
            return []

        # ── Single group (most common: "keywords" or "selection") ─────────────
        return self._eval_single_group(condition, groups, log_line)

    def _eval_single_group(
        self,
        name: str,
        groups: Dict[str, List[Tuple[re.Pattern, str]]],
        log_line: str,
    ) -> List[str]:
        """
        Evaluate a single group name (possibly with '| all' modifier).

        name examples:
          "keywords"
          "keywords | all"
          "selection"
          "selection | all"
        """
        require_all = False
        if "|" in name:
            parts = [p.strip() for p in name.split("|")]
            name = parts[0]
            if len(parts) > 1 and parts[1] == "all":
                require_all = True

        patterns = groups.get(name)
        if not patterns:
            # Try prefix match (e.g. condition says "keywords" but group is "keywords")
            for gname, gpats in groups.items():
                if gname.startswith(name):
                    patterns = gpats
                    break

        if not patterns:
            return []

        if require_all:
            hits = [orig for pat, orig in patterns if pat.search(log_line)]
            return hits if len(hits) == len(patterns) else []
        else:
            return [orig for pat, orig in patterns if pat.search(log_line)]

    # ── Public matching API ───────────────────────────────────────────────────

    def match(self, log_line: str) -> Optional[SigmaMatchResult]:
        """
        Evaluate all loaded rules against a log line.
        Returns the highest-severity match, or None.
        """
        best: Optional[SigmaMatchResult] = None
        best_rank = -1

        for rule in self._rules:
            hits = self._eval_condition(rule.condition, rule.groups, log_line)
            if not hits:
                continue

            rank = _SEV_RANK.get(rule.severity, 0)
            if rank <= best_rank:
                continue

            best_rank = rank
            best = SigmaMatchResult(
                rule_id=rule.rule_id,
                rule_title=rule.title,
                description=rule.description,
                severity=rule.severity,
                event_type=rule.event_type,
                mitre_tactics=rule.mitre_tactics,
                mitre_techniques=rule.mitre_techniques,
                false_positives=rule.false_positives,
                matched_keywords=hits,
            )

        return best

    def match_all(self, log_line: str) -> List[SigmaMatchResult]:
        """Return all rule matches for a log line (not just the best)."""
        results: List[SigmaMatchResult] = []

        for rule in self._rules:
            hits = self._eval_condition(rule.condition, rule.groups, log_line)
            if not hits:
                continue
            results.append(SigmaMatchResult(
                rule_id=rule.rule_id,
                rule_title=rule.title,
                description=rule.description,
                severity=rule.severity,
                event_type=rule.event_type,
                mitre_tactics=rule.mitre_tactics,
                mitre_techniques=rule.mitre_techniques,
                false_positives=rule.false_positives,
                matched_keywords=hits,
            ))

        return results

    # ── Metadata ──────────────────────────────────────────────────────────────

    @property
    def rule_count(self) -> int:
        return len(self._rules)

    @property
    def load_stats(self) -> Dict[str, Any]:
        return self._load_stats

    def list_rules_metadata(self) -> List[Dict[str, Any]]:
        """Return metadata for all loaded rules (used by /api/sigma/rules)."""
        return [
            {
                "id":               rule.rule_id,
                "title":            rule.title,
                "description":      rule.description,
                "level":            next(
                    (k for k, v in _LEVEL_TO_SEVERITY.items() if v == rule.severity),
                    "medium",
                ),
                "severity":         rule.severity,
                "event_type":       rule.event_type,
                "mitre_tactics":    rule.mitre_tactics,
                "mitre_techniques": rule.mitre_techniques,
                "false_positives":  rule.false_positives,
                "keyword_count":    rule.keyword_count,
                "condition":        rule.condition,
            }
            for rule in self._rules
        ]
