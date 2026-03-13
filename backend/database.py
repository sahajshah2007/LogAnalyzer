"""
Database Abstraction Layer for Log Analyzer
Supports both SQLite (development) and PostgreSQL (production)
"""

import os
import json
import sqlite3
from abc import ABC, abstractmethod
from typing import Optional, List, Dict, Any, Tuple
from pathlib import Path
from datetime import datetime, timedelta
from contextlib import contextmanager


class DatabaseBackend(ABC):
    """Abstract base class for database backends"""
    
    @abstractmethod
    def connect(self):
        """Create and return a database connection"""
        pass
    
    @abstractmethod
    def init_schema(self):
        """Initialize database schema"""
        pass
    
    @abstractmethod
    def insert_alert(self, alert_data: dict) -> int:
        """Insert an alert and return the ID"""
        pass
    
    @abstractmethod
    def get_alerts(self, filters: dict, limit: int, offset: int) -> Tuple[List[dict], int]:
        """Get filtered alerts with pagination. Returns (alerts, total_count)"""
        pass
    
    @abstractmethod
    def get_stats(self) -> dict:
        """Get alert statistics"""
        pass
    
    @abstractmethod
    def delete_old_alerts(self, days: int) -> int:
        """Delete alerts older than specified days. Returns count deleted."""
        pass
    
    @contextmanager
    def get_connection(self):
        """Context manager for database connections"""
        conn = self.connect()
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()


class SQLiteBackend(DatabaseBackend):
    """SQLite database backend for development/small deployments"""
    
    def __init__(self, db_path: str):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.init_schema()
    
    def connect(self):
        """Create SQLite connection"""
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn
    
    def init_schema(self):
        """Initialize SQLite schema"""
        with self.get_connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    source_ip TEXT,
                    description TEXT,
                    raw_log TEXT,
                    matched_keywords TEXT,
                    false_positives TEXT,
                    mitre_tactics TEXT,
                    mitre_techniques TEXT,
                    sigma_rule_id TEXT,
                    sigma_rule_title TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Create indexes
            conn.execute("CREATE INDEX IF NOT EXISTS idx_timestamp ON alerts(timestamp)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_severity ON alerts(severity)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_event_type ON alerts(event_type)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_source_ip ON alerts(source_ip)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_created_at ON alerts(created_at)")
    
    def insert_alert(self, alert_data: dict) -> int:
        """Insert an alert"""
        with self.get_connection() as conn:
            cursor = conn.execute("""
                INSERT INTO alerts (
                    timestamp, event_type, severity, source_ip, description,
                    raw_log, matched_keywords, false_positives,
                    mitre_tactics, mitre_techniques, sigma_rule_id, sigma_rule_title
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                alert_data.get('timestamp'),
                alert_data.get('event_type'),
                alert_data.get('severity'),
                alert_data.get('source_ip'),
                alert_data.get('description'),
                alert_data.get('raw_log'),
                json.dumps(alert_data.get('matched_keywords', [])),
                json.dumps(alert_data.get('false_positives', [])),
                json.dumps(alert_data.get('mitre_tactics', [])),
                json.dumps(alert_data.get('mitre_techniques', [])),
                alert_data.get('sigma_rule_id'),
                alert_data.get('sigma_rule_title')
            ))
            return cursor.lastrowid
    
    def get_alerts(self, filters: dict, limit: int, offset: int) -> Tuple[List[dict], int]:
        """Get filtered alerts with pagination"""
        conditions = []
        params = []
        
        if filters.get('severity'):
            conditions.append("severity = ?")
            params.append(filters['severity'].upper())
        
        if filters.get('event_type'):
            conditions.append("event_type = ?")
            params.append(filters['event_type'].upper())
        
        if filters.get('source_ip'):
            conditions.append("source_ip LIKE ?")
            params.append(f"%{filters['source_ip']}%")
        
        if filters.get('search'):
            conditions.append("(description LIKE ? OR raw_log LIKE ? OR source_ip LIKE ?)")
            search_term = f"%{filters['search']}%"
            params.extend([search_term, search_term, search_term])
        
        where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        
        with self.get_connection() as conn:
            # Get total count
            total = conn.execute(
                f"SELECT COUNT(*) as count FROM alerts {where_clause}",
                params
            ).fetchone()['count']
            
            # Get paginated results
            rows = conn.execute(
                f"SELECT * FROM alerts {where_clause} ORDER BY id DESC LIMIT ? OFFSET ?",
                params + [limit, offset]
            ).fetchall()
            
            alerts = [self._row_to_dict(row) for row in rows]
            
        return alerts, total
    
    def get_stats(self) -> dict:
        """Get alert statistics"""
        with self.get_connection() as conn:
            total = conn.execute("SELECT COUNT(*) as count FROM alerts").fetchone()['count']
            
            by_severity = conn.execute("""
                SELECT severity, COUNT(*) as count
                FROM alerts
                GROUP BY severity
                ORDER BY count DESC
            """).fetchall()
            
            by_type = conn.execute("""
                SELECT event_type, COUNT(*) as count
                FROM alerts
                GROUP BY event_type
                ORDER BY count DESC
            """).fetchall()
            
            top_ips = conn.execute("""
                SELECT source_ip, COUNT(*) as count
                FROM alerts
                WHERE source_ip IS NOT NULL
                GROUP BY source_ip
                ORDER BY count DESC
                LIMIT 10
            """).fetchall()
            
            recent_count = conn.execute("""
                SELECT COUNT(*) as count
                FROM alerts
                WHERE created_at >= datetime('now', '-1 hour')
            """).fetchone()['count']
            
            timeline = conn.execute("""
                SELECT strftime('%Y-%m-%dT%H:00:00', timestamp) as hour,
                       COUNT(*) as count
                FROM alerts
                WHERE timestamp >= datetime('now', '-24 hours')
                GROUP BY hour
                ORDER BY hour
            """).fetchall()
        
        return {
            'total_alerts': total,
            'alerts_last_hour': recent_count,
            'by_severity': [dict(r) for r in by_severity],
            'by_type': [dict(r) for r in by_type],
            'top_ips': [dict(r) for r in top_ips],
            'timeline': [dict(r) for r in timeline]
        }
    
    def delete_old_alerts(self, days: int) -> int:
        """Delete alerts older than specified days"""
        with self.get_connection() as conn:
            cursor = conn.execute("""
                DELETE FROM alerts
                WHERE created_at < datetime('now', ? || ' days')
            """, (f'-{days}',))
            return cursor.rowcount
    
    def _row_to_dict(self, row) -> dict:
        """Convert a row to dict, deserializing JSON columns"""
        d = dict(row)
        json_cols = {'matched_keywords', 'false_positives', 'mitre_tactics', 'mitre_techniques'}
        
        for col in json_cols:
            if col in d and isinstance(d[col], str):
                try:
                    d[col] = json.loads(d[col])
                except (json.JSONDecodeError, TypeError):
                    d[col] = []
            elif col not in d:
                d[col] = []
        
        return d


class PostgreSQLBackend(DatabaseBackend):
    """PostgreSQL database backend for production/scalable deployments"""
    
    def __init__(self, config: dict):
        self.config = config
        self.host = config.get('host', 'localhost')
        self.port = config.get('port', 5432)
        self.database = config.get('database', 'log_analyzer')
        self.user = config.get('user', 'postgres')
        self.password = config.get('password', '')
        
        try:
            import psycopg2
            import psycopg2.extras
            self.psycopg2 = psycopg2
            self.extras = psycopg2.extras
        except ImportError:
            raise ImportError("psycopg2 not installed. Run: pip install psycopg2-binary")
        
        self.init_schema()
    
    def connect(self):
        """Create PostgreSQL connection"""
        return self.psycopg2.connect(
            host=self.host,
            port=self.port,
            database=self.database,
            user=self.user,
            password=self.password
        )
    
    def init_schema(self):
        """Initialize PostgreSQL schema"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS alerts (
                    id SERIAL PRIMARY KEY,
                    timestamp TIMESTAMP NOT NULL,
                    event_type VARCHAR(100) NOT NULL,
                    severity VARCHAR(20) NOT NULL,
                    source_ip VARCHAR(45),
                    description TEXT,
                    raw_log TEXT,
                    matched_keywords JSONB DEFAULT '[]',
                    false_positives JSONB DEFAULT '[]',
                    mitre_tactics JSONB DEFAULT '[]',
                    mitre_techniques JSONB DEFAULT '[]',
                    sigma_rule_id VARCHAR(100),
                    sigma_rule_title TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Create indexes
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_event_type ON alerts(event_type)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_source_ip ON alerts(source_ip)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_created_at ON alerts(created_at)")
            
            # JSONB indexes for better array query performance
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_mitre_tactics ON alerts USING GIN(mitre_tactics)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_mitre_techniques ON alerts USING GIN(mitre_techniques)")
    
    def insert_alert(self, alert_data: dict) -> int:
        """Insert an alert"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO alerts (
                    timestamp, event_type, severity, source_ip, description,
                    raw_log, matched_keywords, false_positives,
                    mitre_tactics, mitre_techniques, sigma_rule_id, sigma_rule_title
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING id
            """, (
                alert_data.get('timestamp'),
                alert_data.get('event_type'),
                alert_data.get('severity'),
                alert_data.get('source_ip'),
                alert_data.get('description'),
                alert_data.get('raw_log'),
                json.dumps(alert_data.get('matched_keywords', [])),
                json.dumps(alert_data.get('false_positives', [])),
                json.dumps(alert_data.get('mitre_tactics', [])),
                json.dumps(alert_data.get('mitre_techniques', [])),
                alert_data.get('sigma_rule_id'),
                alert_data.get('sigma_rule_title')
            ))
            return cursor.fetchone()[0]
    
    def get_alerts(self, filters: dict, limit: int, offset: int) -> Tuple[List[dict], int]:
        """Get filtered alerts with pagination"""
        conditions = []
        params = []
        param_num = 1
        
        if filters.get('severity'):
            conditions.append(f"severity = ${param_num}")
            params.append(filters['severity'].upper())
            param_num += 1
        
        if filters.get('event_type'):
            conditions.append(f"event_type = ${param_num}")
            params.append(filters['event_type'].upper())
            param_num += 1
        
        if filters.get('source_ip'):
            conditions.append(f"source_ip LIKE ${param_num}")
            params.append(f"%{filters['source_ip']}%")
            param_num += 1
        
        if filters.get('search'):
            conditions.append(f"(description LIKE ${param_num} OR raw_log LIKE ${param_num+1} OR source_ip LIKE ${param_num+2})")
            search_term = f"%{filters['search']}%"
            params.extend([search_term, search_term, search_term])
            param_num += 3
        
        where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        
        with self.get_connection() as conn:
            cursor = conn.cursor(cursor_factory=self.extras.RealDictCursor)
            
            # Get total count
            cursor.execute(
                f"SELECT COUNT(*) as count FROM alerts {where_clause}",
                params
            )
            total = cursor.fetchone()['count']
            
            # Get paginated results
            params.extend([limit, offset])
            cursor.execute(
                f"SELECT * FROM alerts {where_clause} ORDER BY id DESC LIMIT ${param_num} OFFSET ${param_num+1}",
                params
            )
            
            alerts = [dict(row) for row in cursor.fetchall()]
            
        return alerts, total
    
    def get_stats(self) -> dict:
        """Get alert statistics"""
        with self.get_connection() as conn:
            cursor = conn.cursor(cursor_factory=self.extras.RealDictCursor)
            
            cursor.execute("SELECT COUNT(*) as count FROM alerts")
            total = cursor.fetchone()['count']
            
            cursor.execute("""
                SELECT severity, COUNT(*) as count
                FROM alerts
                GROUP BY severity
                ORDER BY count DESC
            """)
            by_severity = [dict(r) for r in cursor.fetchall()]
            
            cursor.execute("""
                SELECT event_type, COUNT(*) as count
                FROM alerts
                GROUP BY event_type
                ORDER BY count DESC
            """)
            by_type = [dict(r) for r in cursor.fetchall()]
            
            cursor.execute("""
                SELECT source_ip, COUNT(*) as count
                FROM alerts
                WHERE source_ip IS NOT NULL
                GROUP BY source_ip
                ORDER BY count DESC
                LIMIT 10
            """)
            top_ips = [dict(r) for r in cursor.fetchall()]
            
            cursor.execute("""
                SELECT COUNT(*) as count
                FROM alerts
                WHERE created_at >= NOW() - INTERVAL '1 hour'
            """)
            recent_count = cursor.fetchone()['count']
            
            cursor.execute("""
                SELECT date_trunc('hour', timestamp) as hour,
                       COUNT(*) as count
                FROM alerts
                WHERE timestamp >= NOW() - INTERVAL '24 hours'
                GROUP BY hour
               ORDER BY hour
            """)
            timeline = [dict(r) for r in cursor.fetchall()]
        
        return {
            'total_alerts': total,
            'alerts_last_hour': recent_count,
            'by_severity': by_severity,
            'by_type': by_type,
            'top_ips': top_ips,
            'timeline': timeline
        }
    
    def delete_old_alerts(self, days: int) -> int:
        """Delete alerts older than specified days"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                DELETE FROM alerts
                WHERE created_at < NOW() - INTERVAL '%s days'
            """, (days,))
            return cursor.rowcount


class DatabaseManager:
    """High-level database manager that selects the appropriate backend"""
    
    def __init__(self, config: dict):
        self.config = config
        db_config = config.get('database', {})
        db_type = db_config.get('type', 'sqlite').lower()
        
        if db_type == 'postgres' or db_type == 'postgresql':
            self.backend = PostgreSQLBackend(db_config.get('postgres', {}))
        else:
            # Default to SQLite
            db_path = db_config.get('path', './alerts.db')
            self.backend = SQLiteBackend(db_path)
    
    def insert_alert(self, alert_data: dict) -> int:
        """Insert an alert"""
        return self.backend.insert_alert(alert_data)
    
    def get_alerts(self, filters: dict = None, limit: int = 20, offset: int = 0) -> Tuple[List[dict], int]:
        """Get alerts with filters and pagination"""
        return self.backend.get_alerts(filters or {}, limit, offset)
    
    def get_stats(self) -> dict:
        """Get statistics"""
        return self.backend.get_stats()
    
    def delete_old_alerts(self, days: int) -> int:
        """Delete old alerts"""
        return self.backend.delete_old_alerts(days)
    
    @contextmanager
    def get_connection(self):
        """Get a database connection"""
        with self.backend.get_connection() as conn:
            yield conn
