"""
ioc_db.py
---------
SQLite schema, connection management, and base query helpers for the IOC database.

Tables:
  - ioc_entries        : Known malicious IPs, domains, file hashes
  - cis_rules          : 500 CIS Benchmark network rules (loaded by cis_loader.py)
  - iot_thresholds     : Per-device-type IoT behavioural limits
  - mitre_mappings     : MITRE ATT&CK tactic/technique reference
  - auto_enriched_candidates : Staging table for auto-enricher; analyst promotes to ioc_entries
"""

import sqlite3
import os
import logging
from contextlib import contextmanager
from typing import Optional

logger = logging.getLogger(__name__)

# Default DB path — override via env IOC_DB_PATH or config.py
DEFAULT_DB_PATH = os.environ.get(
    "IOC_DB_PATH",
    os.path.join(os.path.dirname(__file__), "ioc_store.db")
)


@contextmanager
def get_connection(db_path: str = DEFAULT_DB_PATH):
    """Thread-safe context manager for SQLite connections."""
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.row_factory = sqlite3.Row          # rows behave like dicts
    conn.execute("PRAGMA journal_mode=WAL") # concurrent reads during writes
    conn.execute("PRAGMA foreign_keys=ON")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Schema creation
# ---------------------------------------------------------------------------

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS ioc_entries (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    ioc_type        TEXT    NOT NULL CHECK(ioc_type IN ('ip','domain','file_hash','url','email')),
    value           TEXT    NOT NULL,
    threat_type     TEXT,                       -- e.g. 'malicious_ip', 'c2_domain', 'ransomware_hash'
    severity        TEXT    DEFAULT 'medium'    CHECK(severity IN ('low','medium','high','critical')),
    confidence      TEXT    DEFAULT 'high'      CHECK(confidence IN ('low','medium','high')),
    source          TEXT    DEFAULT 'manual',   -- 'manual' | 'auto' | 'cis' | 'mitre'
    mitre_tactic    TEXT,
    mitre_technique TEXT,
    description     TEXT,
    added_by        TEXT    DEFAULT 'system',
    created_at      TEXT    DEFAULT (datetime('now')),
    updated_at      TEXT    DEFAULT (datetime('now')),
    is_active       INTEGER DEFAULT 1,
    UNIQUE(ioc_type, value)
);

CREATE TABLE IF NOT EXISTS cis_rules (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    benchmark_id    TEXT    NOT NULL UNIQUE,    -- e.g. "3.1.1.3"
    title           TEXT    NOT NULL,
    profile_level   TEXT,                       -- "Level 1" | "Level 2"
    section         TEXT,                       -- e.g. "Data Plane"
    assessment_type TEXT,                       -- "Manual" | "Automated"
    description     TEXT,
    rationale       TEXT,
    impact          TEXT,
    cis_controls    TEXT,
    keywords        TEXT,                       -- pipe-separated, auto-extracted for fast matching
    raw_json        TEXT,                       -- full original JSON blob
    is_active       INTEGER DEFAULT 1,
    created_at      TEXT    DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS iot_thresholds (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    device_type     TEXT    NOT NULL,           -- e.g. 'smart_meter', 'hvac', 'camera'
    metric          TEXT    NOT NULL,           -- e.g. 'packets_per_minute', 'auth_failures'
    threshold_min   REAL,
    threshold_max   REAL,
    severity        TEXT    DEFAULT 'medium'    CHECK(severity IN ('low','medium','high','critical')),
    description     TEXT,
    mitre_technique TEXT,
    is_active       INTEGER DEFAULT 1,
    UNIQUE(device_type, metric)
);

CREATE TABLE IF NOT EXISTS mitre_mappings (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    technique_id    TEXT    NOT NULL UNIQUE,    -- e.g. "T1110"
    technique_name  TEXT    NOT NULL,           -- e.g. "Brute Force"
    tactic          TEXT    NOT NULL,           -- e.g. "Credential Access"
    description     TEXT,
    detection_hint  TEXT,
    keywords        TEXT                        -- pipe-separated keywords for log matching
);

CREATE TABLE IF NOT EXISTS auto_enriched_candidates (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    ioc_type        TEXT    NOT NULL,
    value           TEXT    NOT NULL,
    trigger         TEXT    NOT NULL,           -- which enrichment trigger fired
    trigger_detail  TEXT,                       -- e.g. "seen 12 times in 5 minutes"
    anomaly_score   REAL,
    log_type        TEXT,
    raw_event       TEXT,                       -- JSON snapshot of the event that triggered it
    status          TEXT    DEFAULT 'pending'   CHECK(status IN ('pending','promoted','rejected')),
    reviewed_by     TEXT,
    created_at      TEXT    DEFAULT (datetime('now')),
    reviewed_at     TEXT,
    UNIQUE(ioc_type, value, trigger)            -- prevent duplicate candidates
);

CREATE INDEX IF NOT EXISTS idx_ioc_value     ON ioc_entries(value);
CREATE INDEX IF NOT EXISTS idx_ioc_type      ON ioc_entries(ioc_type);
CREATE INDEX IF NOT EXISTS idx_ioc_active    ON ioc_entries(is_active);
CREATE INDEX IF NOT EXISTS idx_cis_section   ON cis_rules(section);
CREATE INDEX IF NOT EXISTS idx_cis_active    ON cis_rules(is_active);
CREATE INDEX IF NOT EXISTS idx_iot_device    ON iot_thresholds(device_type);
CREATE INDEX IF NOT EXISTS idx_mitre_tactic  ON mitre_mappings(tactic);
CREATE INDEX IF NOT EXISTS idx_candidates    ON auto_enriched_candidates(status);
"""


def init_db(db_path: str = DEFAULT_DB_PATH) -> None:
    """Create all tables and indexes. Safe to call multiple times (CREATE IF NOT EXISTS)."""
    with get_connection(db_path) as conn:
        conn.executescript(SCHEMA_SQL)
    logger.info(f"IOC database initialised at {db_path}")


# ---------------------------------------------------------------------------
# Base query helpers used by ioc_matcher.py and auto_enricher.py
# ---------------------------------------------------------------------------

def lookup_ioc(value: str, ioc_type: Optional[str] = None,
               db_path: str = DEFAULT_DB_PATH) -> list[dict]:
    """
    Look up a single value in ioc_entries.
    Returns list of matching rows as dicts (empty list = not found).
    """
    with get_connection(db_path) as conn:
        if ioc_type:
            rows = conn.execute(
                "SELECT * FROM ioc_entries WHERE value=? AND ioc_type=? AND is_active=1",
                (value, ioc_type)
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM ioc_entries WHERE value=? AND is_active=1",
                (value,)
            ).fetchall()
        return [dict(r) for r in rows]


def lookup_cis_rules(section: Optional[str] = None,
                     profile_level: str = "Level 1",
                     db_path: str = DEFAULT_DB_PATH) -> list[dict]:
    """Retrieve active CIS rules, optionally filtered by section."""
    with get_connection(db_path) as conn:
        if section:
            rows = conn.execute(
                "SELECT * FROM cis_rules WHERE section=? AND profile_level=? AND is_active=1",
                (section, profile_level)
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM cis_rules WHERE profile_level=? AND is_active=1",
                (profile_level,)
            ).fetchall()
        return [dict(r) for r in rows]


def lookup_iot_thresholds(device_type: str,
                          db_path: str = DEFAULT_DB_PATH) -> list[dict]:
    """Retrieve all active thresholds for a given IoT device type."""
    with get_connection(db_path) as conn:
        rows = conn.execute(
            "SELECT * FROM iot_thresholds WHERE device_type=? AND is_active=1",
            (device_type,)
        ).fetchall()
        return [dict(r) for r in rows]


def lookup_mitre(technique_id: Optional[str] = None,
                 keyword: Optional[str] = None,
                 db_path: str = DEFAULT_DB_PATH) -> list[dict]:
    """Look up MITRE techniques by ID or keyword match."""
    with get_connection(db_path) as conn:
        if technique_id:
            rows = conn.execute(
                "SELECT * FROM mitre_mappings WHERE technique_id=?",
                (technique_id,)
            ).fetchall()
        elif keyword:
            rows = conn.execute(
                "SELECT * FROM mitre_mappings WHERE keywords LIKE ?",
                (f"%{keyword}%",)
            ).fetchall()
        else:
            rows = conn.execute("SELECT * FROM mitre_mappings").fetchall()
        return [dict(r) for r in rows]


def insert_ioc(ioc_type: str, value: str, threat_type: str = None,
               severity: str = "medium", confidence: str = "high",
               source: str = "manual", mitre_tactic: str = None,
               mitre_technique: str = None, description: str = None,
               added_by: str = "analyst",
               db_path: str = DEFAULT_DB_PATH) -> int:
    """
    Insert or update an IOC entry.
    Returns the row id.
    """
    with get_connection(db_path) as conn:
        conn.execute("""
            INSERT INTO ioc_entries
                (ioc_type, value, threat_type, severity, confidence, source,
                 mitre_tactic, mitre_technique, description, added_by)
            VALUES (?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(ioc_type, value) DO UPDATE SET
                threat_type     = excluded.threat_type,
                severity        = excluded.severity,
                confidence      = excluded.confidence,
                mitre_tactic    = excluded.mitre_tactic,
                mitre_technique = excluded.mitre_technique,
                description     = excluded.description,
                updated_at      = datetime('now'),
                is_active       = 1
        """, (ioc_type, value, threat_type, severity, confidence, source,
              mitre_tactic, mitre_technique, description, added_by))
        row = conn.execute(
            "SELECT id FROM ioc_entries WHERE ioc_type=? AND value=?",
            (ioc_type, value)
        ).fetchone()
        return row["id"]


def delete_ioc(ioc_id: int, db_path: str = DEFAULT_DB_PATH) -> bool:
    """Soft-delete an IOC entry by id."""
    with get_connection(db_path) as conn:
        conn.execute(
            "UPDATE ioc_entries SET is_active=0, updated_at=datetime('now') WHERE id=?",
            (ioc_id,)
        )
        return True


def get_all_iocs(active_only: bool = True,
                 db_path: str = DEFAULT_DB_PATH) -> list[dict]:
    """Retrieve all IOC entries (for dashboard listing)."""
    with get_connection(db_path) as conn:
        if active_only:
            rows = conn.execute(
                "SELECT * FROM ioc_entries WHERE is_active=1 ORDER BY created_at DESC"
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM ioc_entries ORDER BY created_at DESC"
            ).fetchall()
        return [dict(r) for r in rows]


def get_pending_candidates(db_path: str = DEFAULT_DB_PATH) -> list[dict]:
    """Return all auto-enriched candidates awaiting analyst review."""
    with get_connection(db_path) as conn:
        rows = conn.execute(
            "SELECT * FROM auto_enriched_candidates WHERE status='pending' ORDER BY created_at DESC"
        ).fetchall()
        return [dict(r) for r in rows]