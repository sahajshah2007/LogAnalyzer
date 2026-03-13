"""
Log analyzer Alert Manager Module
Handles console output, Discord notifications, and database logging
"""

import json
from datetime import datetime
from typing import Optional
import requests
from analyzer import ThreatAlert
from database import DatabaseManager


class Colors:
    """ANSI color codes for terminal output"""

    CRITICAL = "\033[91m"  # Bright red
    WARNING = "\033[93m"  # Bright yellow
    INFO = "\033[92m"  # Bright green
    RESET = "\033[0m"
    BOLD = "\033[1m"


class AlertManager:
    """Manages alerts across multiple channels (console, Discord, database)"""

    def __init__(self, config: dict):
        """
        Initialize the alert manager.

        Args:
            config: Configuration dictionary from config.yaml
        """
        self.config = config
        self.discord_webhook = config.get("discord", {}).get("webhook_url")
        self.discord_enabled = config.get("discord", {}).get("enabled", False)

        # Initialize database manager (supports SQLite and PostgreSQL)
        self.db_manager = DatabaseManager(config)

    def save_alert(self, alert: ThreatAlert):
        """Save alert to database using the database manager."""
        try:
            alert_data = {
                'timestamp': alert.timestamp.isoformat(),
                'event_type': alert.event_type,
                'source_ip': alert.source_ip,
                'description': alert.description,
                'severity': alert.severity,
                'raw_log': alert.raw_log,
                'matched_keywords': getattr(alert, "matched_keywords", []),
                'false_positives': getattr(alert, "false_positives", []),
                'mitre_tactics': getattr(alert, "mitre_tactics", []),
                'mitre_techniques': getattr(alert, "mitre_techniques", []),
                'sigma_rule_id': getattr(alert, "sigma_rule_id", ""),
                'sigma_rule_title': getattr(alert, "sigma_rule_title", "")
            }
            
            self.db_manager.insert_alert(alert_data)
        except Exception as e:
            print(f"{Colors.CRITICAL}[!] Error saving alert to database: {e}{Colors.RESET}")

    def _get_color(self, severity: str) -> str:
        """Get color code based on severity level."""
        severity_colors = {
            "INFO": Colors.INFO,
            "WARNING": Colors.WARNING,
            "CRITICAL": Colors.CRITICAL,
        }
        return severity_colors.get(severity, Colors.INFO)

    def log_console(self, alert: ThreatAlert):
        """
        Print color-coded alert to console.

        Output format:
        [TIMESTAMP] [SEVERITY] [IP] Event: description
        """
        color = self._get_color(alert.severity)

        timestamp_str = alert.timestamp.strftime("%Y-%m-%d %H:%M:%S")
        severity_str = f"{color}{Colors.BOLD}{alert.severity:<8}{Colors.RESET}"

        message = (
            f"{timestamp_str} {severity_str} "
            f"{color}[{alert.source_ip}]{Colors.RESET} "
            f"{alert.event_type}: {alert.description}"
        )

        print(message)

        if alert.abuse_confidence_score > 0:
            score_color = Colors.CRITICAL if alert.abuse_confidence_score > 75 else Colors.WARNING
            print(
                f"  {score_color}└─ Abuse Confidence Score: "
                f"{alert.abuse_confidence_score}/100{Colors.RESET}"
            )

    def send_discord_alert(self, alert: ThreatAlert):
        """
        Send alert to Discord via webhook.

        Creates a rich embed with threat information.
        """
        if not self.discord_enabled or not self.discord_webhook:
            return

        # Validate webhook URL
        if "YOUR_WEBHOOK_ID" in self.discord_webhook:
            return

        try:
            # Determine embed color based on severity
            embed_colors = {
                "INFO": 0x00FF00,  # Green
                "WARNING": 0xFFFF00,  # Yellow
                "CRITICAL": 0xFF0000,  # Red
            }
            embed_color = embed_colors.get(alert.severity, 0x808080)

            # Build the embed
            embed = {
                "title": f"🚨 {alert.event_type}",
                "description": alert.description,
                "color": embed_color,
                "fields": [
                    {
                        "name": "Source IP",
                        "value": f"`{alert.source_ip}`",
                        "inline": True,
                    },
                    {
                        "name": "Severity",
                        "value": alert.severity,
                        "inline": True,
                    },
                    {
                        "name": "Timestamp",
                        "value": alert.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC"),
                        "inline": False,
                    },
                    {
                        "name": "Raw Log",
                        "value": f"```{alert.raw_log[:256]}...```"
                        if len(alert.raw_log) > 256
                        else f"```{alert.raw_log}```",
                        "inline": False,
                    },
                ],
                "footer": {
                    "text": "Log analyzer HIDS",
                    "icon_url": "https://raw.githubusercontent.com/github/gitignore/main/.gitignore_templates/Python.gitignore",
                },
                "timestamp": alert.timestamp.isoformat(),
            }

            # Add abuse confidence score if available
            if alert.abuse_confidence_score > 0:
                abuse_field = {
                    "name": "Abuse Confidence Score",
                    "value": f"{alert.abuse_confidence_score}/100",
                    "inline": True,
                }
                embed["fields"].insert(3, abuse_field)

            payload = {"embeds": [embed]}

            response = requests.post(
                self.discord_webhook,
                json=payload,
                timeout=10,
            )

            if response.status_code != 204:
                print(
                    f"{Colors.WARNING}[!] Discord webhook returned status "
                    f"{response.status_code}{Colors.RESET}"
                )
        except requests.RequestException as e:
            print(f"{Colors.WARNING}[!] Failed to send Discord alert: {e}{Colors.RESET}")

    def process_alert(self, alert: ThreatAlert):
        """
        Process an alert through all output channels.

        Args:
            alert: ThreatAlert object to process
        """
        # Console output
        self.log_console(alert)

        # Database storage
        self.save_alert(alert)

        # Discord notification
        self.send_discord_alert(alert)

    def get_alert_stats(self) -> dict:
        """Get summary statistics of recorded alerts."""
        try:
            stats = self.db_manager.get_stats()
            
            # Convert to the expected format for backward compatibility
            by_severity = {item['severity']: item['count'] for item in stats.get('by_severity', [])}
            by_type = {item['event_type']: item['count'] for item in stats.get('by_type', [])}
            top_ips = {item['source_ip']: item['count'] for item in stats.get('top_ips', [])}
            
            return {
                "total_alerts": stats.get('total_alerts', 0),
                "by_severity": by_severity,
                "by_type": by_type,
                "top_10_ips": top_ips,
            }
        except Exception as e:
            print(f"{Colors.CRITICAL}[!] Error retrieving stats: {e}{Colors.RESET}")
            return {}
