"""
SentinelLog REST API
Exposes alert data and monitoring controls to the React frontend.
"""

import sqlite3
import subprocess
import signal
import os
import sys
import json
import yaml
from datetime import datetime
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, Query, HTTPException, UploadFile, File, Header, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse
from pydantic import BaseModel
from typing import List

# ── Config ──────────────────────────────────────────────────────
DB_PATH = Path(__file__).parent.parent / "alerts.db"
CONFIG_PATH = Path(__file__).parent.parent / "config.yaml"

# Make backend importable for LogAnalyzer and SigmaEngine
sys.path.insert(0, str(Path(__file__).parent))

app = FastAPI(title="Log analyzer API", version="1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Holds reference to the monitor subprocess when started via API
_monitor_proc: Optional[subprocess.Popen] = None

# ── Lazy Sigma Engine singleton ──────────────────────────────────
_sigma_engine = None

def _get_sigma_engine():
    """Load SigmaEngine once (lazy singleton) from config paths."""
    global _sigma_engine
    if _sigma_engine is not None:
        return _sigma_engine
    try:
        from sigma_engine import SigmaEngine
        project_root = Path(__file__).parent.parent
        with open(CONFIG_PATH) as f:
            cfg = yaml.safe_load(f)
        raw_paths = cfg.get("sigma_rules", {}).get("paths", ["./sigma/rules/"])
        resolved = [str((project_root / p).resolve()) for p in raw_paths]
        _sigma_engine = SigmaEngine(resolved)
    except Exception as e:
        print(f"[!] Could not initialise SigmaEngine in API: {e}")
        _sigma_engine = None
    return _sigma_engine



# ── Helpers ─────────────────────────────────────────────────────
def get_conn():
    if not DB_PATH.exists():
        raise HTTPException(status_code=503, detail="alerts.db not found. Start monitoring first.")
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn

_JSON_COLS = {"matched_keywords", "false_positives", "mitre_tactics", "mitre_techniques"}

def _row_to_dict(row) -> dict:
    """Convert a sqlite3.Row to a dict, deserializing JSON array columns."""
    d = dict(row)
    for col in _JSON_COLS:
        if col in d and isinstance(d[col], str):
            try:
                d[col] = json.loads(d[col])
            except (json.JSONDecodeError, TypeError):
                d[col] = []
        elif col not in d:
            d[col] = []
    return d


# ── Models ──────────────────────────────────────────────────────
class ControlResponse(BaseModel):
    status: str
    message: str


class AgentLogEntry(BaseModel):
    """Single log entry from an agent"""
    timestamp: str
    hostname: str
    source: str
    message: str
    priority: Optional[str] = None
    unit: Optional[str] = None
    raw: str


class AgentIngestRequest(BaseModel):
    """Batch of logs from an agent"""
    agent_id: str
    hostname: str
    timestamp: str
    logs: List[AgentLogEntry]


class AgentRegistration(BaseModel):
    """Agent registration data"""
    hostname: str
    agent_id: str
    metadata: Optional[dict] = None


# ── Agent Authentication ────────────────────────────────────────
def verify_agent_key(x_agent_key: str = Header(None)) -> str:
    """Verify agent API key from header"""
    with open(CONFIG_PATH) as f:
        config = yaml.safe_load(f)
    
    valid_keys = config.get("agent_api_keys", [])
    
    if not valid_keys:
        # If no keys configured, allow any key (development mode)
        return x_agent_key or "development"
    
    if not x_agent_key or x_agent_key not in valid_keys:
        raise HTTPException(status_code=401, detail="Invalid or missing agent API key")
    
    return x_agent_key


# ── Routes ──────────────────────────────────────────────────────

@app.get("/", include_in_schema=False)
def root():
    return RedirectResponse(url="/docs")


@app.get("/api/stats")
def get_stats():
    """Overall statistics summary."""
    conn = get_conn()
    cur = conn.cursor()

    total = cur.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
    by_severity = cur.execute(
        "SELECT severity, COUNT(*) as count FROM alerts GROUP BY severity ORDER BY count DESC"
    ).fetchall()
    by_type = cur.execute(
        "SELECT event_type, COUNT(*) as count FROM alerts GROUP BY event_type ORDER BY count DESC"
    ).fetchall()
    top_ips = cur.execute(
        "SELECT source_ip, COUNT(*) as count FROM alerts GROUP BY source_ip ORDER BY count DESC LIMIT 5"
    ).fetchall()
    last_alert = cur.execute(
        "SELECT timestamp FROM alerts ORDER BY id DESC LIMIT 1"
    ).fetchone()
    recent_count = cur.execute(
        "SELECT COUNT(*) FROM alerts WHERE created_at >= datetime('now', '-1 hour')"
    ).fetchone()[0]

    conn.close()
    return {
        "total_alerts": total,
        "alerts_last_hour": recent_count,
        "by_severity": [dict(r) for r in by_severity],
        "by_type": [dict(r) for r in by_type],
        "top_ips": [dict(r) for r in top_ips],
        "last_alert": last_alert[0] if last_alert else None,
    }


@app.get("/api/sigma/rules")
def list_sigma_rules():
    """Return metadata for all loaded Sigma rules and per-path stats."""
    engine = _get_sigma_engine()
    if engine is None:
        return {"count": 0, "rules": [], "stats": {}}
    rules = engine.list_rules_metadata()
    return {
        "count": len(rules),
        "rules": rules,
        "stats": engine.load_stats,
    }


@app.get("/api/alerts")
def get_alerts(
    page: int = Query(1, ge=1),
    limit: int = Query(20, ge=1, le=100),
    severity: Optional[str] = None,
    event_type: Optional[str] = None,
    source_ip: Optional[str] = None,
    search: Optional[str] = None,
):
    """Paginated, filterable alert list."""
    conn = get_conn()
    cur = conn.cursor()

    conditions = []
    params = []

    if severity:
        conditions.append("severity = ?")
        params.append(severity.upper())
    if event_type:
        conditions.append("event_type = ?")
        params.append(event_type.upper())
    if source_ip:
        conditions.append("source_ip LIKE ?")
        params.append(f"%{source_ip}%")
    if search:
        conditions.append("(description LIKE ? OR raw_log LIKE ? OR source_ip LIKE ?)")
        params.extend([f"%{search}%"] * 3)

    where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
    total = cur.execute(f"SELECT COUNT(*) FROM alerts {where}", params).fetchone()[0]

    offset = (page - 1) * limit
    rows = cur.execute(
        f"SELECT * FROM alerts {where} ORDER BY id DESC LIMIT ? OFFSET ?",
        params + [limit, offset],
    ).fetchall()

    conn.close()
    return {
        "total": total,
        "page": page,
        "limit": limit,
        "pages": max(1, (total + limit - 1) // limit),
        "alerts": [_row_to_dict(r) for r in rows],
    }


@app.get("/api/alerts/recent")
def get_recent_alerts(n: int = Query(10, ge=1, le=50)):
    """Last N alerts (for live feed)."""
    conn = get_conn()
    rows = conn.execute(
        "SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (n,)
    ).fetchall()
    conn.close()
    return [_row_to_dict(r) for r in rows]


@app.get("/api/attacks/timeline")
def get_timeline():
    """Alert counts grouped by hour for the last 24 hours."""
    conn = get_conn()
    rows = conn.execute(
        """
        SELECT strftime('%Y-%m-%dT%H:00:00', timestamp) as hour,
               COUNT(*) as count
        FROM alerts
        WHERE timestamp >= datetime('now', '-24 hours')
        GROUP BY hour
        ORDER BY hour
        """
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


@app.get("/api/status")
def get_status():
    """Returns monitoring process status."""
    global _monitor_proc
    running = _monitor_proc is not None and _monitor_proc.poll() is None
    return {"monitoring": running, "db_exists": DB_PATH.exists(), "db_path": str(DB_PATH)}


@app.post("/api/control/start", response_model=ControlResponse)
def start_monitoring(legacy: bool = False):
    """Start the Log analyzer monitor as a background process."""
    global _monitor_proc
    if _monitor_proc and _monitor_proc.poll() is None:
        return ControlResponse(status="already_running", message="Monitor is already running.")

    script = Path(__file__).parent / "main.py"
    if not script.exists():
        raise HTTPException(status_code=500, detail=f"Monitor script not found: {script}")

    # Use the same interpreter running the API process (venv-safe, no python shim dependency).
    cmd = [sys.executable, str(script)]
    if legacy:
        cmd.append("--legacy")

    try:
        _monitor_proc = subprocess.Popen(cmd, cwd=str(script.parent.parent))
        return ControlResponse(status="started", message="Monitor started successfully.")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/control/stop", response_model=ControlResponse)
def stop_monitoring():
    """Stop the Log analyzer monitor."""
    global _monitor_proc
    if _monitor_proc is None or _monitor_proc.poll() is not None:
        return ControlResponse(status="not_running", message="Monitor is not running.")

    try:
        _monitor_proc.send_signal(signal.SIGINT)
        _monitor_proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        _monitor_proc.kill()
    _monitor_proc = None
    return ControlResponse(status="stopped", message="Monitor stopped.")


# ── Agent Endpoints ─────────────────────────────────────────────

@app.post("/api/agent/ingest")
async def ingest_agent_logs(
    request: AgentIngestRequest,
    api_key: str = Depends(verify_agent_key)
):
    """
    Receive and process logs from EDR agents.
    Each log is analyzed and alerts are saved to the database.
    """
    from analyzer import LogAnalyzer as EventAnalyzer
    from alerts import AlertManager
    
    # Load config
    if CONFIG_PATH.exists():
        with open(CONFIG_PATH) as f:
            config = yaml.safe_load(f)
    else:
        config = {}
    
    analyzer = EventAnalyzer(config)
    alert_manager = AlertManager(config)
    
    processed = 0
    alerts_created = 0
    
    for log_entry in request.logs:
        # Analyze the log message
        alert = analyzer.analyze(log_entry.message)
        
        if alert:
            # Enrich alert with agent metadata
            alert.source_ip = log_entry.hostname
            if not alert.raw_log:
                alert.raw_log = log_entry.raw
            
            alert_manager.save_alert(alert)
            alerts_created += 1
        
        processed += 1
    
    # Update agent last seen timestamp
    _update_agent_status(request.agent_id, request.hostname, processed)
    
    return {
        "status": "success",
        "logs_processed": processed,
        "alerts_created": alerts_created,
        "agent_id": request.agent_id
    }


@app.post("/api/agent/register")
async def register_agent(
    registration: AgentRegistration,
    api_key: str = Depends(verify_agent_key)
):
    """Register a new agent or update existing agent information"""
    agent_db = Path(__file__).parent.parent / "agents.db"
    
    # Create agents table if not exists
    conn = sqlite3.connect(str(agent_db))
    conn.execute("""
        CREATE TABLE IF NOT EXISTS agents (
            agent_id TEXT PRIMARY KEY,
            hostname TEXT NOT NULL,
            first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            logs_received INTEGER DEFAULT 0,
            metadata TEXT
        )
    """)
    
    # Insert or update agent
    conn.execute("""
        INSERT INTO agents (agent_id, hostname, metadata)
        VALUES (?, ?, ?)
        ON CONFLICT(agent_id) DO UPDATE SET
            hostname = excluded.hostname,
            last_seen = CURRENT_TIMESTAMP,
            metadata = excluded.metadata
    """, (registration.agent_id, registration.hostname, json.dumps(registration.metadata or {})))
    
    conn.commit()
    conn.close()
    
    return {
        "status": "registered",
        "agent_id": registration.agent_id,
        "hostname": registration.hostname
    }


@app.get("/api/agent/list")
def list_agents():
    """List all registered agents"""
    agent_db = Path(__file__).parent.parent / "agents.db"
    
    if not agent_db.exists():
        return {"agents": []}
    
    conn = sqlite3.connect(str(agent_db))
    conn.row_factory = sqlite3.Row
    
    rows = conn.execute("""
        SELECT agent_id, hostname, first_seen, last_seen, logs_received, metadata
        FROM agents
        ORDER BY last_seen DESC
    """).fetchall()
    
    conn.close()
    
    agents = []
    for row in rows:
        agent = dict(row)
        if agent['metadata']:
            try:
                agent['metadata'] = json.loads(agent['metadata'])
            except:
                agent['metadata'] = {}
        agents.append(agent)
    
    return {"agents": agents, "count": len(agents)}


def _update_agent_status(agent_id: str, hostname: str, logs_count: int):
    """Update agent last seen timestamp and log count"""
    agent_db = Path(__file__).parent.parent / "agents.db"
    
    conn = sqlite3.connect(str(agent_db))
    
    # Create table if not exists
    conn.execute("""
        CREATE TABLE IF NOT EXISTS agents (
            agent_id TEXT PRIMARY KEY,
            hostname TEXT NOT NULL,
            first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            logs_received INTEGER DEFAULT 0,
            metadata TEXT
        )
    """)
    
    # Update or insert
    conn.execute("""
        INSERT INTO agents (agent_id, hostname, logs_received)
        VALUES (?, ?, ?)
        ON CONFLICT(agent_id) DO UPDATE SET
            last_seen = CURRENT_TIMESTAMP,
            logs_received = logs_received + excluded.logs_received
    """, (agent_id, hostname, logs_count))
    
    conn.commit()
    conn.close()


# ── Log File Upload & Analysis ───────────────────────────────────

@app.post("/api/analyze")
async def analyze_log_file(file: UploadFile = File(...)):
    """
    Accept an uploaded log file, run every line through the analyzer,
    persist findings to alerts.db, and return a summary + all alerts found.
    """
    from analyzer import LogAnalyzer
    from alerts import AlertManager

    # Load config
    if CONFIG_PATH.exists():
        with open(CONFIG_PATH) as f:
            config = yaml.safe_load(f)
    else:
        config = {}

    analyzer = LogAnalyzer(config)
    alert_manager = AlertManager(config)

    raw = await file.read()
    try:
        text = raw.decode("utf-8", errors="ignore")
    except Exception:
        raise HTTPException(status_code=400, detail="Could not decode file as text.")

    lines = text.splitlines()
    found = []
    lines_processed = 0

    for line in lines:
        line = line.strip()
        if not line:
            continue
        lines_processed += 1
        alert = analyzer.analyze(line)
        if alert:
            alert_manager.save_alert(alert)
            found.append(alert.to_dict())

    # Summary breakdown
    by_type: dict = {}
    by_severity: dict = {}
    for a in found:
        by_type[a["event_type"]]     = by_type.get(a["event_type"], 0) + 1
        by_severity[a["severity"]]   = by_severity.get(a["severity"], 0) + 1

    # MITRE breakdown
    by_tactic: dict = {}
    by_technique: dict = {}
    for a in found:
        for tactic in a.get("mitre_tactics", []):
            by_tactic[tactic] = by_tactic.get(tactic, 0) + 1
        for tech in a.get("mitre_techniques", []):
            by_technique[tech] = by_technique.get(tech, 0) + 1

    return {
        "filename":        file.filename,
        "lines_processed": lines_processed,
        "alerts_found":    len(found),
        "by_type":         [{"event_type": k, "count": v} for k, v in sorted(by_type.items(), key=lambda x: -x[1])],
        "by_severity":     [{"severity": k, "count": v} for k, v in sorted(by_severity.items(), key=lambda x: -x[1])],
        "by_tactic":       [{"tactic": k, "count": v} for k, v in sorted(by_tactic.items(), key=lambda x: -x[1])],
        "by_technique":    [{"technique": k, "count": v} for k, v in sorted(by_technique.items(), key=lambda x: -x[1])],
        "alerts":          found,
    }
