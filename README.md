# Log analyzer

A host-based intrusion detection system (HIDS) with EDR agent capabilities that monitors system logs in real-time, detects security threats using Sigma rules and pattern matching, and delivers alerts via console, Discord, and scalable database storage.

## Features

### Core Detection
- **Live log monitoring** — streams from journalctl, syslog, and application log files
- **Legacy file monitoring** — tails log files with rotation detection
- **Sigma rule engine** — YAML-based threat detection with MITRE ATT&CK mapping
- **Threat detection** — brute force, SQL injection, XSS, path traversal, privilege escalation, port scanning, suspicious processes
- **Multi-channel alerts** — color-coded console output, Discord webhooks, database storage
- **AbuseIPDB integration** — optional IP reputation scoring
- **IP whitelisting** — skip alerts for trusted addresses and CIDR ranges

### EDR & Scalability (NEW)
- **EDR agents** — deploy lightweight agents to endpoints for centralized log collection
- **Multi-endpoint support** — collect logs from hundreds of endpoints simultaneously
- **Agent authentication** — API key-based security for agent communications
- **Agent management** — registration, tracking, and health monitoring
- **Scalable database** — SQLite for development, PostgreSQL for production
- **High availability** — database replication and connection pooling support

## Project Structure

```
Log-analyzer/
├── agent/                 # EDR agent for endpoints
│   ├── edr_agent.py      # Agent implementation
│   ├── agent.yaml        # Sample configuration
│   ├── install.sh        # Deployment script
│   └── README.md         # Agent documentation
├── backend/
│   ├── main.py           # HIDS entry point & orchestrator
│   ├── live_monitor.py   # Live log source streaming (journalctl, syslog)
│   ├── monitor.py        # Legacy file tail monitoring
│   ├── analyzer.py       # Threat detection engine
│   ├── alerts.py         # Alert manager (console, Discord, database)
│   ├── database.py       # Database abstraction layer (SQLite/PostgreSQL)
│   ├── sigma_engine.py   # Sigma rule processor
│   └── api.py            # FastAPI REST API (feeds the dashboard)
├── frontend/
│   ├── src/
│   │   ├── components/   # React components
│   │   ├── hooks/        # Custom React hooks
│   │   ├── App.jsx       # Root layout with tab routing
│   │   └── main.jsx      # Entry point
│   ├── package.json
│   └── vite.config.js
├── sigma/                 # Sigma detection rules
│   ├── rules/            # Custom rules
│   └── sigmahq/          # Community rules
├── config.yaml            # Configuration file
├── requirements.txt       # Python dependencies
├── start.sh               # One-command setup & launch
├── DATABASE_MIGRATION.md  # PostgreSQL migration guide
└── .gitignore
```

## Requirements

- Python 3.10+
- Node.js 18+
- Linux (journalctl/syslog for live mode)

## Installation

**Quick start (recommended):**

```bash
git clone https://github.com/your-username/log-analyzer.git
cd log-analyzer
./start.sh
```

`start.sh` automatically:
1. Checks Python (3.10+) and Node.js versions
2. Creates a Python virtual environment
3. Installs Python dependencies (`requirements.txt`)
4. Installs frontend npm packages
5. Runs a syntax check on all Python modules
6. Launches the FastAPI server on **port 8000** and the React dashboard on **port 3000**

| Service | URL |
|---------|-----|
| React Dashboard | http://localhost:5006 |
| REST API | http://localhost:5005 |
| API Docs | http://localhost:5005/docs |

Press **Ctrl+C** to stop both servers.

**Manual setup:**

```bash
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
cd frontend && npm install && cd ..
```

## Usage

```bash
# Start everything (API + React dashboard + monitor)
./start.sh
```

The dashboard has three tabs:
- **Dashboard** — summary cards, severity donut, attack-type bar chart, 24h timeline, top attacker IPs, and a start/stop monitor button
- **Alerts** — paginated, filterable, searchable alerts table
- **Live Feed** — auto-refreshing (every 3s) stream of the latest 20 alerts

To run the HIDS monitor directly without the dashboard:

```bash
source venv/bin/activate
python backend/main.py           # live mode
python backend/main.py --legacy  # legacy file monitoring
python backend/main.py --stats   # view stats and exit
```

## Configuration

All settings are in `config.yaml`:

| Section | Purpose |
|---------|---------|
| `live_sources` | journalctl units, syslog facility, app log paths |
| `logs` | Legacy mode log file paths |
| `thresholds` | Brute force limits (count & time window) |
| `patterns` | Regex rules for each attack type |
| `discord` | Webhook URL for Discord alerts |
| `apis` | AbuseIPDB API key |
| `whitelist` | Trusted IPs/CIDRs to exclude |
| `database` | SQLite path and retention policy |

### Discord Setup

1. Create a webhook in your Discord channel (Settings → Integrations → Webhooks)
2. Copy the URL into `config.yaml`:

```yaml
discord:
  enabled: true
  webhook_url: "https://discord.com/api/webhooks/YOUR_ID/YOUR_TOKEN"
```

### AbuseIPDB Setup

1. Register at [abuseipdb.com](https://www.abuseipdb.com/) and get an API key
2. Update `config.yaml`:

```yaml
apis:
  abuseipdb:
    enabled: true
    api_key: "YOUR_KEY"
```

## How It Works

```
Log Sources (journalctl / syslog / files)
    │
    ▼
LiveMonitor / LogMonitor — streams log lines
    │
    ▼
LogAnalyzer.analyze() — pattern matching + brute force tracking
    │
    ▼
AlertManager.process_alert()
    ├── Console (color-coded)
    ├── Discord (rich embed)
    └── SQLite alerts.db
              │
              ▼
         FastAPI (backend/api.py)
              │
              ▼
     React Dashboard (frontend/)
         ├── Dashboard — charts & stats
         ├── Alerts — searchable table
         └── Live Feed — real-time stream
```

## Detected Threats

| Type | Detection Method |
|------|-----------------|
| Brute Force | Failed login count exceeds threshold within time window |
| SQL Injection | Regex: `UNION SELECT`, `DROP TABLE`, `EXEC()`, etc. |
| XSS | Regex: `<script>`, `javascript:`, `onerror=`, etc. |
| Path Traversal | Regex: `../`, `%2e%2e`, etc. |
| Privilege Escalation | Regex: `sudo` anomalies, `NOPASSWD` |
| Port Scanning | Regex: `nmap`, `masscan`, `zmap` |
| Suspicious Process | Regex: `nc -l`, `bash -i`, `powershell` |

## Querying Alerts

```bash
sqlite3 alerts.db
```

```sql
-- All critical alerts
SELECT timestamp, source_ip, description FROM alerts
WHERE severity = 'CRITICAL' ORDER BY timestamp DESC;

-- Top attacker IPs
SELECT source_ip, COUNT(*) as count FROM alerts
GROUP BY source_ip ORDER BY count DESC;

-- Alerts in the last hour
SELECT * FROM alerts WHERE timestamp > datetime('now', '-1 hour');
```

## EDR Agent Deployment

Deploy lightweight agents to endpoints for centralized log collection:

### Quick Deploy to Endpoint

```bash
# 1. Generate API key on server
openssl rand -hex 32

# 2. Add to server config.yaml
# agent_api_keys:
#   - "your-generated-key-here"

# 3. Copy agent to endpoint
scp -r agent/ user@endpoint:/tmp/

# 4. Install on endpoint
ssh user@endpoint
cd /tmp/agent
sudo ./install.sh

# 5. Configure agent
sudo nano /etc/log-analyzer/agent.yaml
# Set server URL and API key

# 6. Start agent
sudo systemctl start log-analyzer-agent
sudo systemctl status log-analyzer-agent
```

### Agent Management

```bash
# List all registered agents
curl http://localhost:5005/api/agent/list

# View agent logs
ssh endpoint
sudo journalctl -u log-analyzer-agent -f
```

### Agent Architecture

```
Endpoint 1 (Agent)          Central Server
    │                            │
    ├─ journalctl ──┐           │
    ├─ auth.log ────┤           │
    └─ syslog ──────┴─► [Buffer] ─────► HTTP POST ──► /api/agent/ingest
                        (1000 logs)                         │
                                                           ▼
Endpoint 2 (Agent)                                   [Analyzer]
    │                                                     │
    ├─ journalctl ──┐                                    ▼
    ├─ nginx.log ───┤                               [Database]
    └─ syslog ──────┴─► [Buffer] ─────► HTTP POST        │
                        (1000 logs)                       ▼
                                                    [Dashboard]
```

**See [agent/README.md](agent/README.md) for detailed deployment guide**

## Database Scaling

### Production: Migrate to PostgreSQL

For high-volume deployments (multiple agents, millions of alerts):

```bash
# 1. Install PostgreSQL
sudo apt install postgresql postgresql-contrib

# 2. Create database
sudo -u postgres psql
CREATE DATABASE log_analyzer;
CREATE USER log_analyzer_user WITH PASSWORD 'secure-password';
GRANT ALL PRIVILEGES ON DATABASE log_analyzer TO log_analyzer_user;
\q

# 3. Install Python driver
pip install psycopg2-binary

# 4. Update config.yaml
database:
  type: "postgresql"
  postgres:
    host: "localhost"
    port: 5432
    database: "log_analyzer"
    user: "log_analyzer_user"
    password: "secure-password"

# 5. Restart server
./start.sh
```

### Benefits of PostgreSQL

- **Concurrency**: Multiple agents writing simultaneously
- **Scalability**: Handle millions of alerts efficiently
- **JSONB indexes**: Fast MITRE ATT&CK tactic/technique queries
- **Replication**: High availability setup
- **Connection pooling**: Better resource management

**See [DATABASE_MIGRATION.md](DATABASE_MIGRATION.md) for complete migration guide**

### Database Performance

```sql
-- Create optimized indexes (PostgreSQL)
CREATE INDEX idx_alerts_severity_time ON alerts(severity, timestamp DESC);
CREATE INDEX idx_alerts_mitre_tactics ON alerts USING GIN(mitre_tactics);

-- Monitor table size
SELECT 
    pg_size_pretty(pg_total_relation_size('alerts')) AS table_size,
    count(*) AS row_count
FROM alerts;
```

## Production Deployment

Create a systemd service at `/etc/systemd/system/log-analyzer.service`:

```ini
[Unit]
Description=Log analyzer HIDS
After=network.target

[Service]
Type=simple
User=nobody
WorkingDirectory=/opt/log-analyzer
ExecStart=/usr/bin/python3 main.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable --now log-analyzer
```

## Security Notes

- Do not commit `config.yaml` with real API keys or webhook URLs
- Restrict file permissions: `chmod 600 config.yaml alerts.db`
- Run with minimal privileges (non-root when possible)

## License

MIT
