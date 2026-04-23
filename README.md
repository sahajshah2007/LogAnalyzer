# SentinelLog

A personal SIEM and host-based intrusion detection system (HIDS). SentinelLog monitors your device's logs in real-time, detects threats using 60 Sigma rules mapped to MITRE ATT&CK, and presents everything in a live React dashboard.

![Stack](https://img.shields.io/badge/Python-3.10+-blue) ![Stack](https://img.shields.io/badge/React-18-61dafb) ![Stack](https://img.shields.io/badge/FastAPI-0.110-009688) ![Rules](https://img.shields.io/badge/Sigma_Rules-60-orange)

---

## What it does

- Streams logs from `journalctl`, `syslog`, and application log files in real-time
- Runs every log line through 60 Sigma detection rules covering the full MITRE ATT&CK matrix
- Tracks stateful brute-force attempts across a sliding time window
- Stores alerts in SQLite (or PostgreSQL for scale) with full metadata
- Sends rich alerts to Discord via webhook
- Enriches source IPs with AbuseIPDB reputation scores
- Exposes a REST API consumed by a live React dashboard
- Supports lightweight EDR agents on remote endpoints that forward logs back to the central server

---

## Dashboard

Four tabs:

| Tab | What's there |
|---|---|
| **Dashboard** | Stats cards, severity donut, attack-type bar chart, 24h timeline, top attacker IPs, monitor start/stop |
| **Alerts** | Paginated, filterable table with expandable rows — Sigma rule, MITRE tactics/techniques, matched keywords, raw log |
| **Live Feed** | Auto-refreshing stream of every log line (alerts highlighted), updates every 3 seconds |
| **Log Analyzer** | Drag-and-drop any log file for offline batch analysis with full MITRE breakdown |

---

## Detection Coverage

60 Sigma rules across the full MITRE ATT&CK matrix:

**Initial Access** — SQL Injection, XSS, Path Traversal, Command Injection, Web Shell, CVE Exploitation (Log4Shell, Shellshock, EternalBlue, Spring4Shell, Zerologon, PrintNightmare, and more), Phishing, Supply Chain, Web App Scanning, API Abuse, Wireless Attacks, Email Attacks, Database Attacks, Generic Web Attacks

**Execution** — Suspicious Process, Malicious Scripts, Application Exploitation, Windows Attack Techniques (WMI, PowerShell, LOLBins), LDAP Injection

**Persistence** — Cron/Scheduled Tasks, Startup Files & Boot Config, Account Manipulation

**Privilege Escalation** — Privilege Escalation, Container Escape & Docker Abuse, Process Injection

**Defense Evasion** — Obfuscation & Encoding, Rootkit & Kernel Tampering, Firewall Evasion, AV/EDR Evasion, Log Tampering, Memory Forensics Evasion

**Credential Access** — SSH Brute Force, Generic Brute Force, Password Cracking, Credential Dumping, MITM Attacks, Token Theft & Impersonation, Active Directory & Kerberos Attacks (Pass-the-Hash, Kerberoasting, DCSync, Golden Ticket)

**Discovery** — Reconnaissance, Port Scanning, Web App Scanning, Suspicious User Agents, Kubernetes & Cloud-Native, SSH Anomaly

**Lateral Movement** — Lateral Movement, SSH Anomaly

**Collection** — Insider Threat & Data Staging, Suspicious Archive & Compression

**Exfiltration** — Data Exfiltration, DNS-Based Exfiltration

**Command & Control** — C2 Communication, Network Tunneling, Suspicious Outbound Connections

**Impact** — Ransomware, Data Destruction, DoS, Cryptocurrency Mining

**Cloud** — Cloud Credential & Metadata Service Abuse (AWS IMDS, GCP, Azure)

---

## Project Structure

```
sentinellog/
├── agent/
│   └── edr_agent.py          # Lightweight EDR agent for remote endpoints
├── backend/
│   ├── api.py                # FastAPI REST API (port 5005)
│   ├── main.py               # HIDS entry point and orchestrator
│   ├── live_monitor.py       # Live log streaming (journalctl, syslog, app logs)
│   ├── monitor.py            # Legacy file tail monitoring
│   ├── analyzer.py           # Threat detection engine + brute-force tracker
│   ├── sigma_engine.py       # Sigma rule loader and evaluator
│   ├── alerts.py             # Alert manager (console, Discord, database)
│   └── database.py           # Database abstraction (SQLite / PostgreSQL)
├── frontend/
│   └── src/
│       ├── components/       # Dashboard, AlertsTable, LiveFeed, LogAnalyzer, charts
│       ├── hooks/
│       │   └── usePolling.js # Auto-refresh hook
│       └── App.jsx           # Tab routing
├── sigma/
│   └── rules/                # 60 Sigma detection rules
├── config.yaml               # All configuration
├── requirements.txt          # Python dependencies
└── start.sh                  # One-command setup and launch
```

---

## Requirements

- Python 3.10+
- Node.js 18+
- Linux (for live `journalctl`/`syslog` monitoring)

---

## Quick Start

```bash
git clone https://github.com/your-username/sentinellog.git
cd sentinellog
chmod +x start.sh
./start.sh
```

`start.sh` handles everything automatically:
1. Checks Python 3.10+ and Node.js
2. Creates and activates a Python virtual environment
3. Installs Python dependencies from `requirements.txt`
4. Installs frontend npm packages
5. Runs a syntax check on all backend modules
6. Starts the FastAPI server and React dev server

| Service | URL |
|---|---|
| Dashboard | http://localhost:5006 |
| REST API | http://localhost:5005 |
| API Docs (Swagger) | http://localhost:5005/docs |

Press **Ctrl+C** to stop everything.

---

## Manual Setup

```bash
# Backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Frontend
cd frontend
npm install
cd ..

# Start API server
python -m uvicorn backend.api:app --host 0.0.0.0 --port 5005 --reload

# Start frontend (separate terminal)
cd frontend && npm run dev -- --port 5006
```

---

## Configuration

Everything lives in `config.yaml`:

```yaml
database:
  type: sqlite          # or "postgresql"
  path: ./alerts.db

sigma_rules:
  paths:
    - ./sigma/rules/

thresholds:
  max_failed_logins: 5  # trigger brute-force alert after N failures
  failed_login_window: 60  # within this many seconds

whitelist:
  ips: []               # e.g. ["192.168.1.0/24", "10.0.0.1"]

discord:
  enabled: false
  webhook_url: "https://discord.com/api/webhooks/YOUR_ID/YOUR_TOKEN"

apis:
  abuseipdb:
    enabled: false
    api_key: "YOUR_KEY"

live_sources:
  journalctl:
    enabled: true
    units: []           # empty = all systemd units
    since: "1m"
  syslog:
    enabled: true
  application_logs:
    - path: /var/log/auth.log
      enabled: true
    - path: /var/log/kern.log
      enabled: true
    - path: /var/log/ufw.log
      enabled: true
```

### Discord alerts

1. In your Discord server: **Settings → Integrations → Webhooks → New Webhook**
2. Copy the URL and add it to `config.yaml`:

```yaml
discord:
  enabled: true
  webhook_url: "https://discord.com/api/webhooks/YOUR_ID/YOUR_TOKEN"
```

### AbuseIPDB enrichment

1. Register at [abuseipdb.com](https://www.abuseipdb.com/) and get a free API key
2. Add it to `config.yaml`:

```yaml
apis:
  abuseipdb:
    enabled: true
    api_key: "YOUR_KEY"
```

---

## Running the Monitor Directly

```bash
source venv/bin/activate

python backend/main.py           # live mode (journalctl + syslog)
python backend/main.py --legacy  # legacy file tail mode
python backend/main.py --stats   # print stats and exit
```

---

## How It Works

```
journalctl / syslog / app logs
        │
        ▼
  LiveMonitor (one thread per source)
        │
        ▼
  LogAnalyzer.analyze()
    ├── Brute-force tracker  (stateful, sliding window per IP)
    └── SigmaEngine.match()  (60 rules, keyword + regex matching)
        │
        ▼
  ThreatAlert (if matched)
        │
        ▼
  AlertManager
    ├── Console  (color-coded by severity)
    ├── Discord  (rich embed with MITRE context)
    └── Database (SQLite / PostgreSQL)
              │
              ▼
         FastAPI  :5005
              │
              ▼
     React Dashboard  :5006
```

---

## Sigma Engine

Rules live in `sigma/rules/` as standard Sigma YAML files. The engine:

- Loads all `.yml` files recursively
- Supports `keywords` and `selection` detection styles
- Handles `condition: keywords`, `condition: keywords | all`, `1 of them`, `all of them`, `and`/`or` compound conditions
- Detects regex-style patterns (containing `.*`) and compiles them as native regexes; everything else is matched as a literal string
- Maps rule `level` → internal severity: `critical/high` → `CRITICAL`, `medium` → `WARNING`, `low/informational` → `INFO`
- Parses MITRE ATT&CK tactics and techniques from rule `tags`
- Returns the highest-severity match per log line

To add a custom rule, drop a `.yml` file in `sigma/rules/`:

```yaml
title: My Custom Rule
id: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
status: stable
description: Detects something suspicious.
tags:
  - attack.execution
  - attack.t1059
logsource:
  category: linux
  product: process_creation
detection:
  keywords:
    - "suspicious_binary"
    - "evil --flag"
  condition: keywords
level: high
falsepositives:
  - Legitimate use of this tool
```

No restart needed if you're running in `--reload` mode. Otherwise restart the API server.

---

## EDR Agent

Deploy the lightweight agent to any Linux endpoint to forward its logs to the central server.

```bash
# On the endpoint
scp agent/edr_agent.py user@endpoint:/opt/sentinellog/
ssh user@endpoint

# Create agent config at /etc/log-analyzer/agent.yaml
sudo mkdir -p /etc/log-analyzer
sudo tee /etc/log-analyzer/agent.yaml <<EOF
server:
  url: http://YOUR_SERVER_IP:5005
  api_key: YOUR_API_KEY
sources:
  journalctl:
    enabled: true
    units: []
  files:
    - path: /var/log/auth.log
      enabled: true
forwarding:
  batch_size: 50
  interval_seconds: 10
  max_retries: 3
EOF

# Run the agent
python3 /opt/sentinellog/edr_agent.py
```

The agent buffers up to 1000 log entries, batches them every 10 seconds, and retries with exponential backoff on failure. Logs are forwarded to `/api/agent/ingest` and analyzed by the central server.

```bash
# Check registered agents
curl http://localhost:5005/api/agent/list
```

---

## PostgreSQL (Production)

For high-volume deployments with multiple agents:

```bash
# 1. Install and configure PostgreSQL
sudo apt install postgresql postgresql-contrib
sudo -u postgres psql -c "CREATE DATABASE log_analyzer;"
sudo -u postgres psql -c "CREATE USER log_analyzer_user WITH PASSWORD 'your-password';"
sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE log_analyzer TO log_analyzer_user;"

# 2. Update config.yaml
```

```yaml
database:
  type: postgresql
  postgres:
    host: localhost
    port: 5432
    database: log_analyzer
    user: log_analyzer_user
    password: your-password
```

```bash
# 3. Restart
./start.sh
```

---

## Querying the Database

```bash
sqlite3 alerts.db
```

```sql
-- Recent critical alerts
SELECT timestamp, source_ip, event_type, description
FROM alerts
WHERE severity = 'CRITICAL'
ORDER BY timestamp DESC
LIMIT 20;

-- Top attacker IPs
SELECT source_ip, COUNT(*) AS hits
FROM alerts
GROUP BY source_ip
ORDER BY hits DESC
LIMIT 10;

-- Alerts by MITRE tactic
SELECT event_type, COUNT(*) AS count
FROM alerts
GROUP BY event_type
ORDER BY count DESC;

-- Last hour
SELECT * FROM alerts
WHERE timestamp > datetime('now', '-1 hour');
```

---

## API Reference

| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/alerts` | Paginated alerts with filters (severity, event_type, search, limit, offset) |
| GET | `/api/alerts/recent` | Last N alerts |
| GET | `/api/stats` | Summary statistics |
| GET | `/api/live-logs` | Recent live log entries |
| GET | `/api/attacks/timeline` | Alert counts per hour (last 24h) |
| GET | `/api/sigma/rules` | List all loaded Sigma rules with metadata |
| POST | `/api/analyze` | Upload a log file for batch analysis |
| POST | `/api/control/start` | Start the log monitor subprocess |
| POST | `/api/control/stop` | Stop the log monitor subprocess |
| POST | `/api/agent/ingest` | Receive log batches from EDR agents |
| GET | `/api/agent/list` | List registered agents |

Full interactive docs at **http://localhost:5005/docs**

---

## Security Notes

- Never commit `config.yaml` with real API keys or webhook URLs — add it to `.gitignore` or use environment variable substitution
- Restrict permissions on sensitive files: `chmod 600 config.yaml alerts.db`
- The API has no authentication by default — bind to `127.0.0.1` or put it behind a reverse proxy with auth if exposing beyond localhost
- Run with the least privilege necessary; root is not required for most log sources

---

## License

MIT
