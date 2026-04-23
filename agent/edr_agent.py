#!/usr/bin/env python3
"""
Log Analyzer EDR Agent
Lightweight agent for endpoint log collection and forwarding
"""

import os
import sys
import time
import json
import queue
import signal
import socket
import logging
import hashlib
import threading
import subprocess
from pathlib import Path
from typing import Optional, Dict, List
from datetime import datetime
from collections import deque

try:
    import requests
    import yaml
except ImportError:
    print("ERROR: Required packages not installed. Run: pip install requests pyyaml")
    sys.exit(1)


class LogBuffer:
    """Thread-safe log buffer with size limits"""
    
    def __init__(self, max_size: int = 1000, max_age_seconds: int = 300):
        self.buffer = deque(maxlen=max_size)
        self.lock = threading.Lock()
        self.max_age = max_age_seconds
        self.logger = logging.getLogger("LogBuffer")
        
    def add(self, log_entry: dict):
        """Add a log entry to the buffer"""
        with self.lock:
            log_entry['buffered_at'] = time.time()
            self.buffer.append(log_entry)
    
    def get_batch(self, max_count: int = 100) -> List[dict]:
        """Get a batch of logs, removing stale entries"""
        with self.lock:
            current_time = time.time()
            batch = []
            stale_count = 0
            
            # Remove stale entries and collect batch
            while self.buffer and len(batch) < max_count:
                entry = self.buffer.popleft()
                
                # Skip if too old
                if current_time - entry.get('buffered_at', 0) > self.max_age:
                    stale_count += 1
                    continue
                    
                # Remove internal tracking field
                entry.pop('buffered_at', None)
                batch.append(entry)
            
            if stale_count > 0:
                self.logger.warning(f"Dropped {stale_count} stale log entries (older than {self.max_age}s)")
            
            return batch
    
    def requeue(self, entries: List[dict]):
        """Put entries back at the front of the buffer after a failed send."""
        with self.lock:
            now = time.time()
            for entry in reversed(entries):
                entry['buffered_at'] = now
                self.buffer.appendleft(entry)
    
    def size(self) -> int:
        """Get current buffer size"""
        with self.lock:
            return len(self.buffer)


class LogCollector:
    """Collects logs from various sources on the endpoint"""
    
    def __init__(self, config: dict, buffer: LogBuffer):
        self.config = config
        self.buffer = buffer
        self.running = False
        self.hostname = socket.gethostname()
        self.logger = logging.getLogger("LogCollector")
        self.collectors = []
        
    def start(self):
        """Start all configured log collectors"""
        self.running = True
        
        # Start journalctl collector if enabled
        if self.config.get('sources', {}).get('journalctl', {}).get('enabled', True):
            thread = threading.Thread(target=self._collect_journalctl, daemon=True)
            thread.start()
            self.collectors.append(thread)
            self.logger.info("Started journalctl collector")
        
        # Start file collectors for each configured file
        for file_config in self.config.get('sources', {}).get('files', []):
            if isinstance(file_config, dict):
                path = file_config.get('path')
                enabled = file_config.get('enabled', True)
            else:
                path = file_config
                enabled = True
                
            if enabled and path:
                thread = threading.Thread(
                    target=self._collect_file,
                    args=(path,),
                    daemon=True
                )
                thread.start()
                self.collectors.append(thread)
                self.logger.info(f"Started file collector for {path}")
    
    def stop(self):
        """Stop all collectors"""
        self.running = False
        for collector in self.collectors:
            collector.join(timeout=2)
    
    def _collect_journalctl(self):
        """Collect logs from journalctl"""
        units = self.config.get('sources', {}).get('journalctl', {}).get('units', [])
        
        cmd = ['journalctl', '-f', '--output=json', '--since=now']
        
        # Add unit filters if specified
        for unit in units:
            cmd.extend(['--unit', unit])
        
        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1
            )
            
            while self.running:
                line = process.stdout.readline()
                if not line:
                    break
                    
                try:
                    log_data = json.loads(line.strip())
                    
                    # Create standardized log entry
                    entry = {
                        'timestamp': datetime.now().isoformat(),
                        'hostname': self.hostname,
                        'source': 'journalctl',
                        'message': log_data.get('MESSAGE', ''),
                        'priority': log_data.get('PRIORITY', '6'),
                        'unit': log_data.get('_SYSTEMD_UNIT', 'unknown'),
                        'raw': line.strip()
                    }
                    
                    self.buffer.add(entry)
                    
                except json.JSONDecodeError:
                    # Handle non-JSON lines
                    entry = {
                        'timestamp': datetime.now().isoformat(),
                        'hostname': self.hostname,
                        'source': 'journalctl',
                        'message': line.strip(),
                        'raw': line.strip()
                    }
                    self.buffer.add(entry)
                    
        except FileNotFoundError:
            self.logger.error("journalctl not found - skipping journalctl collection")
        except Exception as e:
            self.logger.error(f"Error in journalctl collector: {e}")
        finally:
            if 'process' in locals():
                process.terminate()
    
    def _collect_file(self, filepath: str):
        """Tail a log file and collect new entries"""
        path = Path(filepath)
        
        if not path.exists():
            self.logger.warning(f"Log file not found: {filepath}")
            return
        
        try:
            # Open file and seek to end
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                f.seek(0, 2)  # Seek to end
                last_inode = os.stat(filepath).st_ino
                
                while self.running:
                    # Check for log rotation
                    try:
                        current_inode = os.stat(filepath).st_ino
                        if current_inode != last_inode:
                            # File was rotated, reopen
                            f.close()
                            f = open(path, 'r', encoding='utf-8', errors='ignore')
                            last_inode = current_inode
                            self.logger.info(f"Detected log rotation for {filepath}")
                    except FileNotFoundError:
                        time.sleep(1)
                        continue
                    
                    # Read new lines
                    lines = f.readlines()
                    if lines:
                        for line in lines:
                            line = line.strip()
                            if line:
                                entry = {
                                    'timestamp': datetime.now().isoformat(),
                                    'hostname': self.hostname,
                                    'source': f'file:{filepath}',
                                    'message': line,
                                    'raw': line
                                }
                                self.buffer.add(entry)
                    else:
                        time.sleep(0.5)
                        
        except PermissionError:
            self.logger.error(f"Permission denied reading {filepath}")
        except Exception as e:
            self.logger.error(f"Error collecting from {filepath}: {e}")


class LogForwarder:
    """Forwards buffered logs to the central server"""
    
    def __init__(self, config: dict, buffer: LogBuffer):
        self.config = config
        self.buffer = buffer
        self.running = False
        self.logger = logging.getLogger("LogForwarder")
        
        # Server configuration
        self.server_url = config.get('server', {}).get('url', 'http://localhost:5005')
        self.api_key = config.get('server', {}).get('api_key', '')
        self.hostname = socket.gethostname()
        
        # Forwarding settings
        self.batch_size = config.get('forwarding', {}).get('batch_size', 50)
        self.interval = config.get('forwarding', {}).get('interval_seconds', 10)
        self.max_retries = config.get('forwarding', {}).get('max_retries', 3)
        self.timeout = config.get('forwarding', {}).get('timeout_seconds', 30)
        
        # Statistics
        self.stats = {
            'logs_sent': 0,
            'logs_failed': 0,
            'batches_sent': 0,
            'last_success': None,
            'last_error': None
        }
    
    def start(self):
        """Start the forwarding thread"""
        self.running = True
        self.thread = threading.Thread(target=self._forward_loop, daemon=True)
        self.thread.start()
        self.logger.info(f"Started log forwarder to {self.server_url}")
    
    def stop(self):
        """Stop the forwarder"""
        self.running = False
        if hasattr(self, 'thread'):
            self.thread.join(timeout=5)
    
    def _forward_loop(self):
        """Main forwarding loop"""
        while self.running:
            try:
                # Wait for interval or until buffer has enough logs
                time.sleep(self.interval)
                
                if self.buffer.size() == 0:
                    continue
                
                # Get batch of logs
                batch = self.buffer.get_batch(self.batch_size)
                
                if not batch:
                    continue
                
                # Send batch to server
                success = self._send_batch(batch)
                
                if success:
                    self.stats['logs_sent'] += len(batch)
                    self.stats['batches_sent'] += 1
                    self.stats['last_success'] = datetime.now().isoformat()
                    self.logger.debug(f"Sent batch of {len(batch)} logs")
                else:
                    self.stats['logs_failed'] += len(batch)
                    # Re-queue failed batch so logs aren't permanently lost
                    self.buffer.requeue(batch)
                    self.logger.warning(f"Re-queued {len(batch)} logs after failed send")
                    
            except Exception as e:
                self.logger.error(f"Error in forward loop: {e}")
                self.stats['last_error'] = str(e)
    
    def _send_batch(self, batch: List[dict]) -> bool:
        """Send a batch of logs to the server"""
        endpoint = f"{self.server_url.rstrip('/')}/api/agent/ingest"
        
        payload = {
            'agent_id': self._get_agent_id(),
            'hostname': self.hostname,
            'timestamp': datetime.now().isoformat(),
            'logs': batch
        }
        
        headers = {
            'Content-Type': 'application/json',
            'X-Agent-Key': self.api_key
        }
        
        for attempt in range(self.max_retries):
            try:
                response = requests.post(
                    endpoint,
                    json=payload,
                    headers=headers,
                    timeout=self.timeout
                )
                
                if response.status_code == 200:
                    return True
                elif response.status_code == 401:
                    self.logger.error("Authentication failed - check API key")
                    return False
                elif response.status_code >= 500:
                    self.logger.warning(f"Server error ({response.status_code}), retrying...")
                    time.sleep(2 ** attempt)  # Exponential backoff
                else:
                    self.logger.error(f"Failed to send logs: {response.status_code} - {response.text}")
                    return False
                    
            except requests.exceptions.Timeout:
                self.logger.warning(f"Request timeout (attempt {attempt + 1}/{self.max_retries})")
                time.sleep(2 ** attempt)
            except requests.exceptions.ConnectionError:
                self.logger.warning(f"Connection error (attempt {attempt + 1}/{self.max_retries})")
                time.sleep(2 ** attempt)
            except Exception as e:
                self.logger.error(f"Unexpected error sending logs: {e}")
                return False
        
        return False
    
    def _get_agent_id(self) -> str:
        """Generate a unique agent ID based on hostname and MAC address"""
        try:
            # Try to get MAC address
            import uuid
            mac = ':'.join(['{:02x}'.format((uuid.getnode() >> elements) & 0xff)
                           for elements in range(0, 2*6, 2)][::-1])
            unique_str = f"{self.hostname}:{mac}"
        except:
            unique_str = self.hostname
        
        return hashlib.sha256(unique_str.encode()).hexdigest()[:16]
    
    def get_stats(self) -> dict:
        """Get forwarder statistics"""
        return {
            **self.stats,
            'buffer_size': self.buffer.size()
        }


class EDRAgent:
    """Main EDR Agent orchestrator"""
    
    def __init__(self, config_path: str = '/etc/log-analyzer/agent.yaml'):
        self.config_path = config_path
        self.config = self._load_config()
        self.running = False
        
        # Setup logging
        log_level = getattr(logging, self.config.get('logging', {}).get('level', 'INFO'))
        log_file = self.config.get('logging', {}).get('file')
        
        handlers = []
        if log_file:
            handlers.append(logging.FileHandler(log_file))
        else:
            handlers.append(logging.StreamHandler())
        
        logging.basicConfig(
            level=log_level,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=handlers
        )
        
        self.logger = logging.getLogger("EDRAgent")
        
        # Initialize components
        buffer_size = self.config.get('forwarding', {}).get('buffer_size', 1000)
        self.buffer = LogBuffer(max_size=buffer_size)
        self.collector = LogCollector(self.config, self.buffer)
        self.forwarder = LogForwarder(self.config, self.buffer)
    
    def _load_config(self) -> dict:
        """Load agent configuration"""
        config_file = Path(self.config_path)
        
        if not config_file.exists():
            self.logger.error(f"Config file not found: {self.config_path}")
            # Return default config
            return self._get_default_config()
        
        try:
            with open(config_file, 'r') as f:
                return yaml.safe_load(f)
        except Exception as e:
            print(f"Error loading config: {e}")
            return self._get_default_config()
    
    def _get_default_config(self) -> dict:
        """Get default configuration"""
        return {
            'server': {
                'url': 'http://localhost:5005',
                'api_key': 'change-me'
            },
            'sources': {
                'journalctl': {
                    'enabled': True,
                    'units': []
                },
                'files': []
            },
            'forwarding': {
                'batch_size': 50,
                'buffer_size': 1000,
                'interval_seconds': 10,
                'max_retries': 3,
                'timeout_seconds': 30
            },
            'logging': {
                'level': 'INFO',
                'file': '/var/log/log-analyzer-agent.log'
            }
        }
    
    def _handle_signal(self, signum, frame):
        """Handle shutdown signals"""
        self.logger.info(f"Received signal {signum}, shutting down...")
        self.stop()
    
    def start(self):
        """Start the EDR agent"""
        self.logger.info("Starting Log Analyzer EDR Agent")
        self.logger.info(f"Hostname: {socket.gethostname()}")
        self.logger.info(f"Server: {self.config.get('server', {}).get('url')}")
        
        # Register signal handlers
        signal.signal(signal.SIGINT, self._handle_signal)
        signal.signal(signal.SIGTERM, self._handle_signal)
        
        self.running = True
        
        # Start components
        self.collector.start()
        self.forwarder.start()
        
        # Status loop
        try:
            while self.running:
                time.sleep(60)
                stats = self.forwarder.get_stats()
                self.logger.info(
                    f"Stats - Buffer: {stats['buffer_size']}, "
                    f"Sent: {stats['logs_sent']}, "
                    f"Failed: {stats['logs_failed']}, "
                    f"Batches: {stats['batches_sent']}"
                )
        except KeyboardInterrupt:
            self.logger.info("Interrupted by user")
        finally:
            self.stop()
    
    def stop(self):
        """Stop the agent"""
        if not self.running:
            return
            
        self.logger.info("Stopping EDR agent...")
        self.running = False
        
        self.collector.stop()
        self.forwarder.stop()
        
        # Flush remaining logs
        remaining = self.buffer.size()
        if remaining > 0:
            self.logger.info(f"Flushing {remaining} remaining logs...")
            batch = self.buffer.get_batch(remaining)
            if batch:
                self.forwarder._send_batch(batch)
        
        self.logger.info("EDR agent stopped")


def main():
    """Entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Log Analyzer EDR Agent",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument(
        '-c', '--config',
        default='/etc/log-analyzer/agent.yaml',
        help='Path to agent configuration file'
    )
    
    parser.add_argument(
        '--generate-config',
        action='store_true',
        help='Generate a sample configuration file and exit'
    )
    
    args = parser.parse_args()
    
    if args.generate_config:
        agent = EDRAgent(args.config)
        sample_config = agent._get_default_config()
        print(yaml.dump(sample_config, default_flow_style=False))
        return
    
    # Run agent
    agent = EDRAgent(args.config)
    agent.start()


if __name__ == '__main__':
    main()
