"""
SentinelLog Main Module
Entry point for the Host-Based Intrusion Detection System
"""

import sys
import signal
import yaml
import logging
from pathlib import Path
from typing import List

from monitor import LogMonitor
from live_monitor import LiveMonitor
from analyzer import LogAnalyzer as EventAnalyzer
from alerts import AlertManager, Colors


class LogAnalyzer:
    """Main HIDS orchestrator"""

    def __init__(self, config_path: str = "config.yaml", live_mode: bool = True):
        """
        Initialize Log analyzer.

        Args:
            config_path: Path to configuration file
            live_mode: If True, use live log sources; if False, use legacy file monitoring
        """
        self.config = self._load_config(config_path)
        self.live_mode = live_mode
        self.monitors: List[LogMonitor] = []
        self.live_monitor = None
        self.analyzer = EventAnalyzer(self.config)
        self.alert_manager = AlertManager(self.config)
        self.running = True
        self.lines_processed = 0
        self.alerts_triggered = 0
        
        # Setup logging
        logging.basicConfig(
            level=logging.WARNING,  # Only show warnings and errors
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )

    @staticmethod
    def _load_config(config_path: str) -> dict:
        """Load configuration from YAML file."""
        config_file = Path(config_path)
        if not config_file.exists():
            print(f"{Colors.CRITICAL}[!] Config file not found: {config_path}{Colors.RESET}")
            sys.exit(1)

        try:
            with open(config_file, "r") as f:
                config = yaml.safe_load(f)
            print(f"{Colors.INFO}[+] Configuration loaded from {config_path}{Colors.RESET}")
            return config
        except yaml.YAMLError as e:
            print(f"{Colors.CRITICAL}[!] Error parsing config file: {e}{Colors.RESET}")
            sys.exit(1)

    def initialize_monitors(self):
        """Initialize log monitors for all configured log paths."""
        log_paths = self.config.get("logs", {}).get("paths", ["./server.log"])

        for log_path in log_paths:
            monitor = LogMonitor(
                log_path,
                check_interval=self.config.get("logs", {}).get("rotation_check_interval", 5),
            )
            self.monitors.append(monitor)
            print(f"{Colors.INFO}[+] Monitoring: {log_path}{Colors.RESET}")

        if not self.monitors:
            print(f"{Colors.CRITICAL}[!] No log files to monitor{Colors.RESET}")
            sys.exit(1)

    def _handle_signal(self, signum, frame):
        """Handle interrupt signals for graceful shutdown."""
        print(
            f"\n{Colors.WARNING}[*] Received signal {signum}, shutting down gracefully...{Colors.RESET}"
        )
        self.running = False

    def print_banner(self):
        """Print welcome banner."""
        banner = f"""
{Colors.CRITICAL}
╔═══════════════════════════════════════════╗
║                                           ║
║          {Colors.BOLD}Log analyzer v1.0{Colors.RESET}{Colors.CRITICAL}                  ║
║   Host-Based Intrusion Detection System   ║
║                                           ║
╚═══════════════════════════════════════════╝
{Colors.RESET}
"""
        print(banner)

    def print_stats(self):
        """Print current statistics."""
        stats = self.alert_manager.get_alert_stats()

        print(
            f"\n{Colors.INFO}{Colors.BOLD}═══ Log analyzer Statistics ═══{Colors.RESET}\n"
        )
        print(f"  Lines Processed: {self.lines_processed}")
        print(f"  Alerts Triggered: {self.alerts_triggered}")
        print(f"  Total Alerts in DB: {stats.get('total_alerts', 0)}")

        if stats.get("by_severity"):
            print(f"\n  {Colors.BOLD}By Severity:{Colors.RESET}")
            for severity, count in sorted(stats["by_severity"].items()):
                print(f"    - {severity}: {count}")

        if stats.get("by_type"):
            print(f"\n  {Colors.BOLD}Top Attack Types:{Colors.RESET}")
            for attack_type, count in list(stats["by_type"].items())[:5]:
                print(f"    - {attack_type}: {count}")

        if stats.get("top_10_ips"):
            print(f"\n  {Colors.BOLD}Top Attacker IPs:{Colors.RESET}")
            for ip, count in list(stats["top_10_ips"].items())[:5]:
                print(f"    - {ip}: {count} alerts")

        print()

    def run(self):
        """Main monitoring loop."""
        self.print_banner()

        # Register signal handlers
        signal.signal(signal.SIGINT, self._handle_signal)
        signal.signal(signal.SIGTERM, self._handle_signal)

        if self.live_mode:
            self._run_live_mode()
        else:
            self._run_legacy_mode()

    def _run_live_mode(self):
        """Run in live log monitoring mode (systemd, syslog, app logs)"""
        print(f"{Colors.INFO}[*] Starting LIVE log monitoring...{Colors.RESET}")
        print(
            f"{Colors.INFO}[*] Monitoring system logs from journalctl, syslog, and configured sources{Colors.RESET}\n"
        )

        try:
            self.live_monitor = LiveMonitor.from_config(self.config)

            # If no live sources are configured/available, keep monitoring by falling back.
            if not getattr(self.live_monitor, "sources", None):
                print(
                    f"{Colors.WARNING}[!] No live log sources configured. Falling back to legacy file monitoring mode.{Colors.RESET}"
                )
                self._run_legacy_mode()
                return
            
            for source_name, line in self.live_monitor.stream_all():
                if not self.running:
                    break

                # Add source context to line for analysis
                enriched_line = f"[{source_name}] {line}"
                self.lines_processed += 1

                # Analyze the line
                alert = self.analyzer.analyze(enriched_line)

                if alert:
                    self.alerts_triggered += 1
                    self.alert_manager.process_alert(alert)

        except KeyboardInterrupt:
            print(
                f"\n{Colors.WARNING}[*] Interrupted by user{Colors.RESET}"
            )
        except Exception as e:
            print(
                f"{Colors.CRITICAL}[!] Unexpected error: {e}{Colors.RESET}"
            )
            import traceback

            traceback.print_exc()
        finally:
            self.shutdown()

    def _run_legacy_mode(self):
        """Run in legacy file monitoring mode (tail files)"""
        self.initialize_monitors()

        print(
            f"{Colors.INFO}[*] Starting legacy file monitoring...{Colors.RESET}\n"
        )

        try:
            while self.running and self.monitors:
                # Monitor the first configured log file
                monitor = self.monitors[0]

                with monitor:
                    for line in monitor.tail():
                        if not self.running:
                            break

                        self.lines_processed += 1

                        # Analyze the line
                        alert = self.analyzer.analyze(line)

                        if alert:
                            self.alerts_triggered += 1
                            self.alert_manager.process_alert(alert)

        except KeyboardInterrupt:
            print(
                f"\n{Colors.WARNING}[*] Interrupted by user{Colors.RESET}"
            )
        except Exception as e:
            print(
                f"{Colors.CRITICAL}[!] Unexpected error: {e}{Colors.RESET}"
            )
            import traceback

            traceback.print_exc()
        finally:
            self.shutdown()

    def shutdown(self):
        """Gracefully close resources and print statistics."""
        print(f"\n{Colors.WARNING}[*] Shutting down...{Colors.RESET}")

        # Close monitors
        for monitor in self.monitors:
            try:
                if hasattr(monitor, "file_handle") and monitor.file_handle:
                    monitor.file_handle.close()
            except Exception as e:
                print(f"{Colors.WARNING}[!] Error closing monitor: {e}{Colors.RESET}")

        # Print final statistics
        self.print_stats()

        print(
            f"{Colors.INFO}[+] Log analyzer shutdown complete. "
            f"Alerts saved to {self.config['database']['path']}{Colors.RESET}"
        )


def main():
    """Entry point."""
    import argparse

    parser = argparse.ArgumentParser(
        description="Log analyzer - Host-Based Intrusion Detection System",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py                         # Run with default config (live mode)
  python main.py --legacy               # Run in legacy file monitoring mode
  python main.py -c custom_config.yaml  # Run with custom config (live mode)
  python main.py --stats                # Show alert statistics and exit
        """,
    )

    parser.add_argument(
        "-c",
        "--config",
        default="config.yaml",
        help="Path to configuration file (default: config.yaml)",
    )

    parser.add_argument(
        "--legacy",
        action="store_true",
        help="Use legacy file monitoring mode instead of live mode",
    )

    parser.add_argument(
        "--stats",
        action="store_true",
        help="Display alert statistics and exit without monitoring",
    )

    args = parser.parse_args()

    # Initialize Log analyzer in the appropriate mode
    sentinel = LogAnalyzer(args.config, live_mode=not args.legacy)

    if args.stats:
        # Just print statistics and exit
        sentinel.print_banner()
        sentinel.print_stats()
    else:
        # Run the monitoring loop
        sentinel.run()


if __name__ == "__main__":
    main()

