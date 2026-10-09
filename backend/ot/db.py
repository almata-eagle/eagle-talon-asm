"""Talon OT storage: one SQLite file (never the Talon DB) plus an evidence folder."""
from __future__ import annotations

import datetime as dt
import json
import os
import sqlite3
from pathlib import Path
from typing import Any, Optional

# Vocabulary taken from UFC 4-010-06 (10 Oct 2023).
STATUSES = ("not_assessed", "implemented", "partial", "not_implemented", "inherited", "na", "impractical")
OPEN_STATUSES = ("not_implemented", "partial")          # what goes on the POA&M
CCI_CATEGORIES = ("dod_defined", "designer", "non_designer", "platform_enclave", "impractical")
IMPACT = ("low", "moderate", "high")
LEVELS = ("0", "1", "2", "3", "4", "5")                  # UFC architecture levels
PHASES = ("basis_of_design", "concept", "interim", "final", "ifc", "construction", "commissioning", "operations")
SYSTEM_TYPES = ("hvac_bas", "electrical_power", "generator", "fire_suppression", "fire_alarm", "umcs", "lighting",
                "elevator", "access_control", "water_wastewater", "utility_metering", "other")
SEVERITIES = ("low", "moderate", "high", "critical")
ROLES = ("admin", "assessor", "viewer")


def data_dir() -> Path:
    default = Path(os.environ.get("EAGLE_TALON_DB_PATH", str(Path(__file__).resolve().parent.parent / "eagle_talon.db"))).parent / "ot"
    return Path(os.environ.get("OT_DATA_DIR", str(default)))


def db_path() -> Path:
    return data_dir() / "ot.db"


def evidence_dir() -> Path:
    return data_dir() / "evidence"


def connect() -> sqlite3.Connection:
    data_dir().mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(db_path(), timeout=15)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys = ON")
    return con


def now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


SCHEMA = """
CREATE TABLE IF NOT EXISTS ot_users (
    username TEXT PRIMARY KEY, pw_hash TEXT NOT NULL, role TEXT NOT NULL,
    created_at TEXT, disabled INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS ot_sessions (
    token_hash TEXT PRIMARY KEY, username TEXT NOT NULL, created_at TEXT, expires_at TEXT
);
CREATE TABLE IF NOT EXISTS ot_engagements (
    id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, client TEXT, site TEXT,
    contract_ref TEXT, marking TEXT, ai_allowed INTEGER DEFAULT 0, notes TEXT,
    created_at TEXT, updated_at TEXT, created_by TEXT
);
CREATE TABLE IF NOT EXISTS ot_systems (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id INTEGER NOT NULL REFERENCES ot_engagements(id) ON DELETE CASCADE,
    name TEXT NOT NULL, system_type TEXT, phase TEXT,
    impact_c TEXT, impact_i TEXT, impact_a TEXT, impact_set_by TEXT, impact_set_at TEXT,
    notes TEXT, template TEXT, created_at TEXT, updated_at TEXT
);
CREATE TABLE IF NOT EXISTS ot_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    system_id INTEGER NOT NULL REFERENCES ot_systems(id) ON DELETE CASCADE,
    sort INTEGER, ref TEXT, control TEXT, requirement TEXT, category TEXT, responsible TEXT, level TEXT,
    status TEXT NOT NULL DEFAULT 'not_assessed', owner TEXT, notes TEXT, finding TEXT, remediation TEXT,
    severity TEXT, due_date TEXT, source_row TEXT, updated_at TEXT, updated_by TEXT
);
CREATE INDEX IF NOT EXISTS idx_ot_items_system ON ot_items (system_id, sort);
CREATE TABLE IF NOT EXISTS ot_evidence (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    item_id INTEGER NOT NULL REFERENCES ot_items(id) ON DELETE CASCADE,
    filename TEXT NOT NULL, sha256 TEXT NOT NULL, size INTEGER, mime TEXT, note TEXT,
    uploaded_at TEXT, uploaded_by TEXT
);
CREATE TABLE IF NOT EXISTS ot_audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT, at TEXT NOT NULL, actor TEXT, action TEXT NOT NULL,
    object_type TEXT, object_id TEXT, detail TEXT
);
"""


def init_db() -> None:
    con = connect()
    try:
        con.executescript(SCHEMA)
        con.commit()
    finally:
        con.close()


def audit(con: sqlite3.Connection, actor: Optional[str], action: str, object_type: str = "", object_id: Any = "",
          detail: Optional[dict] = None) -> None:
    con.execute("INSERT INTO ot_audit (at, actor, action, object_type, object_id, detail) VALUES (?,?,?,?,?,?)",
                (now_iso(), actor, action, object_type, str(object_id), json.dumps(detail or {}, ensure_ascii=False)[:4000]))


def row(r: Optional[sqlite3.Row]) -> Optional[dict]:
    return {k: r[k] for k in r.keys()} if r else None


def clean(s: Any, n: int = 2000) -> Optional[str]:
    """Text from people or spreadsheets: strip control characters, cap length."""
    if s is None:
        return None
    s = "".join(ch if ch in "\n\t" or (ord(ch) >= 32 and ord(ch) != 127) else " " for ch in str(s)).strip()
    return s[:n] or None
