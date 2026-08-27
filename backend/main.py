"""
Eagle Talon — API
=================
Run locally for the wifi demo:

    pip install -r requirements.txt
    uvicorn main:app --host 0.0.0.0 --port 8000 --reload

Then open frontend/index.html (it talks to http://localhost:8000 by default —
change API_BASE at the top of the <script> if you deploy the backend elsewhere).
"""
import csv
import io
import json
import os
import random
import re
import sqlite3
import threading
import calendar
import time
import uuid
import datetime
import concurrent.futures as cf
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException, BackgroundTasks, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from scanner import scan_domain, tier_for_score

# Shared sector list — used both by the demo-data generator and by real scans
# (so a real domain's sector places it correctly on the Talon Scope radar,
# alongside the same compass positions the demo data uses).
SECTORS = ["Payments", "Logistics", "Cloud/SaaS Vendors", "Marketing & Ad Tech",
           "Manufacturing Suppliers", "Professional Services", "Marketplace Sellers",
           "Financial Institutions", "Healthcare Vendors", "Regional Resellers", "Unassigned"]

app = FastAPI(title="Eagle Talon ASM API", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],   # demo only — lock this down before anything resembling prod
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Persistence: every real scan is written here, not just held in memory.
# SQLite is intentional for this stage — zero extra infra, a single file you
# can back up/inspect directly, good enough until this needs multi-writer
# concurrency (at which point: Postgres/RDS, see the AWS deploy notes).
#
# Multi-client model: clients are workspaces inside this one instance/DB —
# each client's scans are isolated by client_id, switchable in the UI
# without needing a separate deployment. For clients who need full physical
# isolation (compliance, dedicated infra) the alternative is a fully
# separate deployment of this same stack with its own .env — see README.
# ---------------------------------------------------------------------------
DB_PATH = Path(os.environ.get("EAGLE_TALON_DB_PATH", str(Path(__file__).parent / "eagle_talon.db")))
DB_PATH.parent.mkdir(parents=True, exist_ok=True)

DEFAULT_CLIENT_ID = "default"
DEFAULT_CLIENT_NAME = "Default Workspace"


def _db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS clients (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)

    # Migrate from the old single-tenant schema (domain as sole primary key)
    # if this DB predates the multi-client model.
    cols = [r[1] for r in conn.execute("PRAGMA table_info(scans)").fetchall()]
    if cols and "client_id" not in cols:
        conn.execute("ALTER TABLE scans RENAME TO scans_legacy")
        conn.execute("""
            CREATE TABLE scans (
                client_id TEXT NOT NULL DEFAULT 'default',
                domain TEXT NOT NULL,
                data TEXT NOT NULL,
                scanned_at TEXT NOT NULL,
                PRIMARY KEY (client_id, domain)
            )
        """)
        conn.execute("""
            INSERT INTO scans (client_id, domain, data, scanned_at)
            SELECT 'default', domain, data, scanned_at FROM scans_legacy
        """)
        conn.execute("DROP TABLE scans_legacy")
    else:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                client_id TEXT NOT NULL DEFAULT 'default',
                domain TEXT NOT NULL,
                data TEXT NOT NULL,
                scanned_at TEXT NOT NULL,
                PRIMARY KEY (client_id, domain)
            )
        """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS monitors (
            client_id TEXT NOT NULL,
            domain TEXT NOT NULL,
            frequency_hours INTEGER NOT NULL DEFAULT 24,
            enabled INTEGER NOT NULL DEFAULT 1,
            last_checked_at TEXT,
            created_at TEXT NOT NULL,
            PRIMARY KEY (client_id, domain)
        )
    """)
    # Safe additive migration (never rewrites/drops existing rows) for the
    # Daily/Weekly/Monthly scheduling model — replaces the old fixed-hours
    # cadence. Existing monitors default to "daily" so nothing breaks.
    mon_cols = [r[1] for r in conn.execute("PRAGMA table_info(monitors)").fetchall()]
    if "freq_type" not in mon_cols:
        conn.execute("ALTER TABLE monitors ADD COLUMN freq_type TEXT NOT NULL DEFAULT 'daily'")
        conn.execute("ALTER TABLE monitors ADD COLUMN day_of_week INTEGER")
        conn.execute("ALTER TABLE monitors ADD COLUMN day_of_month INTEGER")

    conn.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            client_id TEXT NOT NULL,
            domain TEXT NOT NULL,
            severity TEXT NOT NULL,
            code TEXT NOT NULL,
            data TEXT NOT NULL,
            created_at TEXT NOT NULL,
            is_read INTEGER NOT NULL DEFAULT 0
        )
    """)

    if not conn.execute("SELECT 1 FROM clients WHERE id=?", (DEFAULT_CLIENT_ID,)).fetchone():
        conn.execute("INSERT INTO clients (id, name, created_at) VALUES (?, ?, ?)",
                     (DEFAULT_CLIENT_ID, DEFAULT_CLIENT_NAME, datetime.datetime.utcnow().isoformat()))
    conn.commit()
    return conn


def _save_scan(result: dict, client_id: str = DEFAULT_CLIENT_ID):
    conn = _db()
    conn.execute(
        "INSERT OR REPLACE INTO scans (client_id, domain, data, scanned_at) VALUES (?, ?, ?, ?)",
        (client_id, result["domain"], json.dumps(result), result["scanned_at"]),
    )
    conn.commit()
    conn.close()


def _all_saved_scans(client_id: Optional[str] = None) -> list[dict]:
    conn = _db()
    if client_id:
        rows = conn.execute("SELECT data FROM scans WHERE client_id=? ORDER BY scanned_at DESC", (client_id,)).fetchall()
    else:
        rows = conn.execute("SELECT data FROM scans ORDER BY scanned_at DESC").fetchall()
    conn.close()
    return [json.loads(r[0]) for r in rows]


def _list_clients() -> list[dict]:
    conn = _db()
    rows = conn.execute("SELECT id, name, created_at FROM clients ORDER BY created_at ASC").fetchall()
    conn.close()
    return [{"id": r[0], "name": r[1], "created_at": r[2]} for r in rows]


def _create_client(name: str) -> dict:
    client_id = re.sub(r"[^a-z0-9-]", "-", name.strip().lower())[:40] or str(uuid.uuid4())[:8]
    conn = _db()
    # avoid id collisions if two clients would normalize to the same slug
    base_id, n = client_id, 1
    while conn.execute("SELECT 1 FROM clients WHERE id=?", (client_id,)).fetchone():
        n += 1
        client_id = f"{base_id}-{n}"
    created_at = datetime.datetime.utcnow().isoformat()
    conn.execute("INSERT INTO clients (id, name, created_at) VALUES (?, ?, ?)", (client_id, name.strip(), created_at))
    conn.commit()
    conn.close()
    return {"id": client_id, "name": name.strip(), "created_at": created_at}


def _delete_client(client_id: str):
    conn = _db()
    conn.execute("DELETE FROM scans WHERE client_id=?", (client_id,))
    conn.execute("DELETE FROM clients WHERE id=?", (client_id,))
    conn.execute("DELETE FROM monitors WHERE client_id=?", (client_id,))
    conn.execute("DELETE FROM alerts WHERE client_id=?", (client_id,))
    conn.commit()
    conn.close()


# ---------------------------------------------------------------------------
# Monitoring: scheduled re-scans + change-detection alerts.
#
# Deliberately alerts only on *meaningful* change, not "scanned again, same
# result" — a monitoring feed that fires every cycle regardless of content
# trains people to ignore it. Score-drop threshold and the specific finding
# codes checked below are the actual judgment calls this feature makes.
# ---------------------------------------------------------------------------
SCORE_DROP_ALERT_THRESHOLD = 10  # points
TIER_RANK = {"clear": 3, "watch": 2, "high": 1, "critical": 0}  # higher = safer


def _finding_codes(scan: dict) -> set:
    return {f.get("code") for c in scan.get("categories", []) for f in c.get("findings", []) if isinstance(f, dict)}


def _detect_changes(old: dict, new: dict) -> list[dict]:
    """Compares two scans of the same domain, returns a list of
    {severity, code, data} alert records — empty if nothing meaningful changed."""
    alerts = []
    old_score, new_score = old.get("overall_score", 100), new.get("overall_score", 100)
    old_tier, new_tier = old.get("tier", "clear"), new.get("tier", "clear")

    if old_score - new_score >= SCORE_DROP_ALERT_THRESHOLD:
        severity = "critical" if new_tier in ("high", "critical") else "warning"
        alerts.append({"severity": severity, "code": "score_drop",
                        "data": {"old_score": old_score, "new_score": new_score}})

    if TIER_RANK.get(new_tier, 3) < TIER_RANK.get(old_tier, 3):
        alerts.append({"severity": "critical" if new_tier == "critical" else "warning",
                        "code": "tier_worsened", "data": {"old_tier": old_tier, "new_tier": new_tier}})

    old_codes, new_codes = _finding_codes(old), _finding_codes(new)
    if "urlhaus_hit" in new_codes and "urlhaus_hit" not in old_codes:
        alerts.append({"severity": "critical", "code": "new_threat_intel_hit", "data": {}})
    if "cve_detected" in new_codes and "cve_detected" not in old_codes:
        alerts.append({"severity": "critical", "code": "new_cve", "data": {}})
    if "cert_expired" in new_codes and "cert_expired" not in old_codes:
        alerts.append({"severity": "critical", "code": "cert_now_expired", "data": {}})

    return alerts


def _save_alert(client_id: str, domain: str, severity: str, code: str, data: dict):
    conn = _db()
    conn.execute("INSERT INTO alerts (client_id, domain, severity, code, data, created_at, is_read) VALUES (?,?,?,?,?,?,0)",
                 (client_id, domain, severity, code, json.dumps(data), datetime.datetime.utcnow().isoformat()))
    conn.commit()
    conn.close()


def _check_monitor(client_id: str, domain: str):
    """Runs one monitored domain: fetch the previous scan, run a fresh one,
    diff them, save the new scan, record any alerts, update last_checked_at."""
    conn = _db()
    row = conn.execute("SELECT data FROM scans WHERE client_id=? AND domain=?", (client_id, domain)).fetchone()
    old_scan = json.loads(row[0]) if row else None
    conn.close()

    try:
        new_scan = scan_domain(domain)
    except Exception as e:
        conn = _db()
        conn.execute("UPDATE monitors SET last_checked_at=? WHERE client_id=? AND domain=?",
                     (datetime.datetime.utcnow().isoformat(), client_id, domain))
        conn.commit()
        conn.close()
        return

    _save_scan(new_scan, client_id)

    if old_scan:
        for a in _detect_changes(old_scan, new_scan):
            _save_alert(client_id, domain, a["severity"], a["code"], a["data"])

    conn = _db()
    conn.execute("UPDATE monitors SET last_checked_at=? WHERE client_id=? AND domain=?",
                 (datetime.datetime.utcnow().isoformat(), client_id, domain))
    conn.commit()
    conn.close()


def _monitor_is_due(freq_type: str, day_of_week: Optional[int], day_of_month: Optional[int],
                     last_checked_at: Optional[str], now: Optional[datetime.datetime] = None) -> bool:
    """Daily: due once per calendar day. Weekly: due on the chosen weekday
    (0=Monday), once per week. Monthly: due on the chosen day-of-month,
    clamped to that month's actual length (e.g. day 31 in February -> 28th).
    Never fires twice on the same calendar day regardless of frequency."""
    now = now or datetime.datetime.utcnow()
    if not last_checked_at:
        return True
    last = datetime.datetime.fromisoformat(last_checked_at)
    if last.date() == now.date():
        return False
    if freq_type == "weekly":
        return now.weekday() == (day_of_week if day_of_week is not None else 0)
    if freq_type == "monthly":
        days_in_month = calendar.monthrange(now.year, now.month)[1]
        target_day = min(day_of_month or 1, days_in_month)
        return now.day == target_day
    return True  # daily


def _monitoring_scheduler_loop():
    """Runs forever in a background thread, checking every 60s for any
    monitor that's due today per its Daily/Weekly/Monthly schedule. The 60s
    poll interval is just the scheduler's granularity, not the check cadence."""
    while True:
        try:
            conn = _db()
            monitors = conn.execute("""SELECT client_id, domain, freq_type, day_of_week, day_of_month, last_checked_at
                                        FROM monitors WHERE enabled=1""").fetchall()
            conn.close()
            for client_id, domain, freq_type, day_of_week, day_of_month, last_checked_at in monitors:
                if _monitor_is_due(freq_type, day_of_week, day_of_month, last_checked_at):
                    _check_monitor(client_id, domain)
        except Exception:
            pass  # scheduler must never die — one bad domain shouldn't stop monitoring for the rest
        time.sleep(60)


threading.Thread(target=_monitoring_scheduler_loop, daemon=True).start()


class ScanRequest(BaseModel):
    domain: str
    watchlist: Optional[str] = "Live Scans"
    client_id: Optional[str] = DEFAULT_CLIENT_ID
    sector: Optional[str] = "Unassigned"


@app.get("/api/debug/cve-lookup")
def debug_cve_lookup(tech: str, version: str):
    """Isolated test of the CVE lookup, bypassing the full scan pipeline.
    e.g. /api/debug/cve-lookup?tech=Apache&version=2.4.49"""
    import techstack
    return techstack.debug_lookup(tech, version)


@app.get("/api/health")
def health():
    return {"status": "ok", "time": datetime.datetime.utcnow().isoformat()}


@app.get("/api/clients")
def list_clients():
    """Client workspaces inside this single instance — switch between them
    in the UI without needing a separate deployment. For clients who need
    full physical isolation instead, deploy this same stack again with its
    own .env (separate DB path/port) — see README."""
    return {"clients": _list_clients()}


class ClientCreate(BaseModel):
    name: str


@app.post("/api/clients")
def create_client(req: ClientCreate):
    if not req.name or not req.name.strip():
        raise HTTPException(400, "Client name can't be empty.")
    return _create_client(req.name)


@app.delete("/api/clients/{client_id}")
def delete_client(client_id: str):
    if client_id == DEFAULT_CLIENT_ID:
        raise HTTPException(400, "Can't delete the Default Workspace — it's the fallback everything else relies on.")
    clients = {c["id"] for c in _list_clients()}
    if client_id not in clients:
        raise HTTPException(404, "No such client.")
    _delete_client(client_id)
    return {"deleted": client_id}


@app.post("/api/scan")
def scan(req: ScanRequest):
    """Synchronous scan of a single real domain — passive OSINT only.
    Typically completes in 3-10s depending on the target's DNS/TLS latency."""
    if not req.domain or "." not in req.domain:
        raise HTTPException(400, "Provide a valid domain, e.g. example.com")
    try:
        result = scan_domain(req.domain)
        result["watchlist"] = req.watchlist
        result["sector"] = req.sector or "Unassigned"
        client_id = req.client_id or DEFAULT_CLIENT_ID
        _save_scan(result, client_id)
        return result
    except Exception as e:
        raise HTTPException(500, f"Scan failed: {e}")


@app.get("/api/sectors")
def list_sectors():
    """The fixed sector list, so the frontend's dropdowns always match what
    the Talon Scope radar actually plots by."""
    return {"sectors": SECTORS}


@app.get("/api/scan/{domain}")
def get_scan(domain: str, client_id: str = DEFAULT_CLIENT_ID):
    """Most recent persisted scan for this domain, within a given client
    workspace. Not currently called by the frontend (which uses /api/scans
    for the full list) but kept as a direct lookup for scripting/debugging."""
    conn = _db()
    row = conn.execute("SELECT data FROM scans WHERE client_id=? AND domain=?", (client_id, domain)).fetchone()
    conn.close()
    if not row:
        raise HTTPException(404, "No cached scan for that domain/client yet — POST /api/scan first.")
    return json.loads(row[0])


class ScanEdit(BaseModel):
    sector: Optional[str] = None
    watchlist: Optional[str] = None


@app.patch("/api/scans/{domain}")
def edit_scan(domain: str, edit: ScanEdit, client_id: str = DEFAULT_CLIENT_ID):
    """Adjust a real scan's sector/watchlist without re-running the scan —
    for when a domain landed in the wrong category or you want to reassign
    it to a different watchlist."""
    conn = _db()
    row = conn.execute("SELECT data FROM scans WHERE client_id=? AND domain=?", (client_id, domain)).fetchone()
    if not row:
        conn.close()
        raise HTTPException(404, "No such scan for that domain/client.")
    data = json.loads(row[0])
    if edit.sector is not None:
        data["sector"] = edit.sector
    if edit.watchlist is not None:
        data["watchlist"] = edit.watchlist
    conn.execute("UPDATE scans SET data=? WHERE client_id=? AND domain=?", (json.dumps(data), client_id, domain))
    conn.commit()
    conn.close()
    return data


@app.get("/api/scans")
def list_scans(client_id: Optional[str] = None):
    """Every real scan run against this backend for a given client workspace
    (or all of them, if client_id is omitted), in the shape the UI's
    portfolio views expect — this is the actual, non-mock data."""
    saved = _all_saved_scans(client_id)
    out = []
    for i, s in enumerate(saved):
        raw = s.get("raw", {})
        out.append({
            "id": f"real-{i}",
            "domain": s["domain"],
            "sector": s.get("sector", "Unassigned"),
            "watchlist": s.get("watchlist", "Live Scans"),
            "overall_score": s["overall_score"],
            "tier": s["tier"],
            "categories": s["categories"],
            "subdomain_count": raw.get("subdomains", {}).get("count", 0),
            "trend": 0,
            "last_scanned": s["scanned_at"],
            "country": "—",
            "ti_flagged": raw.get("threat_intel", {}).get("malicious_host_reports", 0) > 0,
            "findings_flat": [f for c in s["categories"] for f in c.get("findings", [])],
            "is_demo": False,
            "last_scan_source": s.get("last_scan_source", "talon"),
        })
    return {"count": len(out), "domains": out}


# ---------------------------------------------------------------------------
# Monitoring API
# ---------------------------------------------------------------------------
class MonitorCreate(BaseModel):
    domain: str
    freq_type: str = "daily"  # "daily" | "weekly" | "monthly"
    day_of_week: Optional[int] = None   # 0=Monday..6=Sunday, used when freq_type="weekly"
    day_of_month: Optional[int] = None  # 1-31, used when freq_type="monthly" (clamped to actual month length)
    client_id: str = DEFAULT_CLIENT_ID


@app.post("/api/monitors")
def create_monitor(req: MonitorCreate):
    if req.freq_type not in ("daily", "weekly", "monthly"):
        raise HTTPException(400, "freq_type must be 'daily', 'weekly', or 'monthly'.")
    conn = _db()
    if not conn.execute("SELECT 1 FROM scans WHERE client_id=? AND domain=?", (req.client_id, req.domain)).fetchone():
        conn.close()
        raise HTTPException(400, "Scan this domain at least once before enabling monitoring.")
    conn.execute("""INSERT INTO monitors (client_id, domain, freq_type, day_of_week, day_of_month, enabled, created_at)
                     VALUES (?,?,?,?,?,1,?)
                     ON CONFLICT(client_id, domain) DO UPDATE SET
                         freq_type=excluded.freq_type, day_of_week=excluded.day_of_week,
                         day_of_month=excluded.day_of_month, enabled=1""",
                 (req.client_id, req.domain, req.freq_type, req.day_of_week, req.day_of_month,
                  datetime.datetime.utcnow().isoformat()))
    conn.commit()
    conn.close()
    return {"domain": req.domain, "freq_type": req.freq_type, "day_of_week": req.day_of_week,
            "day_of_month": req.day_of_month, "enabled": True}


@app.delete("/api/monitors/{domain}")
def disable_monitor(domain: str, client_id: str = DEFAULT_CLIENT_ID):
    conn = _db()
    conn.execute("UPDATE monitors SET enabled=0 WHERE client_id=? AND domain=?", (client_id, domain))
    conn.commit()
    conn.close()
    return {"domain": domain, "enabled": False}


@app.get("/api/monitors")
def list_monitors(client_id: str = DEFAULT_CLIENT_ID):
    conn = _db()
    rows = conn.execute("""SELECT domain, freq_type, day_of_week, day_of_month, enabled, last_checked_at
                            FROM monitors WHERE client_id=?""", (client_id,)).fetchall()
    conn.close()
    return {"monitors": [{"domain": r[0], "freq_type": r[1], "day_of_week": r[2], "day_of_month": r[3],
                           "enabled": bool(r[4]), "last_checked_at": r[5]} for r in rows]}


@app.post("/api/monitors/{domain}/check-now")
def check_monitor_now(domain: str, client_id: str = DEFAULT_CLIENT_ID):
    """Manual trigger — bypasses the schedule for testing/demoing without
    waiting for the actual frequency_hours interval to elapse."""
    _check_monitor(client_id, domain)
    return {"checked": True, "domain": domain}


@app.get("/api/alerts")
def list_alerts(client_id: str = DEFAULT_CLIENT_ID, unread_only: bool = False):
    conn = _db()
    q = "SELECT id, domain, severity, code, data, created_at, is_read FROM alerts WHERE client_id=?"
    if unread_only:
        q += " AND is_read=0"
    q += " ORDER BY created_at DESC LIMIT 100"
    rows = conn.execute(q, (client_id,)).fetchall()
    conn.close()
    return {"alerts": [{"id": r[0], "domain": r[1], "severity": r[2], "code": r[3],
                         "data": json.loads(r[4]), "created_at": r[5], "is_read": bool(r[6])} for r in rows]}


@app.post("/api/alerts/{alert_id}/read")
def mark_alert_read(alert_id: int):
    conn = _db()
    conn.execute("UPDATE alerts SET is_read=1 WHERE id=?", (alert_id,))
    conn.commit()
    conn.close()
    return {"id": alert_id, "is_read": True}


@app.post("/api/alerts/mark-all-read")
def mark_all_alerts_read(client_id: str = DEFAULT_CLIENT_ID):
    conn = _db()
    conn.execute("UPDATE alerts SET is_read=1 WHERE client_id=?", (client_id,))
    conn.commit()
    conn.close()
    return {"ok": True}


# ---------------------------------------------------------------------------
# Bulk CSV upload: scans many domains at once. Runs as a background job
# rather than a single blocking request — 100 domains at ~3-10s each would
# blow past any sane HTTP timeout, and this also lets the UI show progress.
#
# Concurrency is deliberately modest (3 domains at a time): the individual
# checks inside scan_domain() already run in parallel per-domain, and several
# of the external services this hits (crt.sh, RDAP, URLhaus, NVD) are
# community-run and rate-limit-sensitive — scanning 100 domains "all at once"
# would just trade a slow job for a flaky one.
# ---------------------------------------------------------------------------
_BULK_JOBS: dict[str, dict] = {}
_BULK_LOCK = threading.Lock()
_BULK_CONCURRENCY = 3

DOMAIN_RE = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$")


def _extract_domains_from_csv(raw_bytes: bytes) -> list[dict]:
    """Returns [{domain, sector}] — sector is None when the CSV has no
    'sector' column, in which case the batch-level default sector applies."""
    text = raw_bytes.decode("utf-8-sig", errors="ignore")
    reader = csv.reader(io.StringIO(text))
    rows = [r for r in reader if r]
    if not rows:
        return []

    # Find whichever column looks like it holds domains, defaulting to column 0.
    header = [c.strip().lower() for c in rows[0]]
    col = 0
    if "domain" in header:
        col = header.index("domain")
    sector_col = header.index("sector") if "sector" in header else None

    # Skip the header row only if it doesn't itself look like a domain
    # (covers CSVs with or without a header line).
    start = 1 if not DOMAIN_RE.match(rows[0][col].strip()) else 0

    out, seen = [], set()
    for row in rows[start:]:
        if col >= len(row):
            continue
        candidate = row[col].strip().lower().replace("https://", "").replace("http://", "").rstrip("/")
        if candidate and DOMAIN_RE.match(candidate) and candidate not in seen:
            seen.add(candidate)
            sector = None
            if sector_col is not None and sector_col < len(row) and row[sector_col].strip():
                sector = row[sector_col].strip()
            out.append({"domain": candidate, "sector": sector})
    return out


def _run_bulk_job(job_id: str, rows: list[dict], watchlist: str, client_id: str, default_sector: str):
    job = _BULK_JOBS[job_id]

    def scan_one(row: dict):
        domain = row["domain"]
        try:
            result = scan_domain(domain)
            result["watchlist"] = watchlist
            result["sector"] = row["sector"] or default_sector
            _save_scan(result, client_id)
            with _BULK_LOCK:
                job["completed"] += 1
                job["results"].append({"domain": domain, "ok": True, "score": result["overall_score"]})
        except Exception as e:
            with _BULK_LOCK:
                job["completed"] += 1
                job["results"].append({"domain": domain, "ok": False, "error": str(e)})

    with cf.ThreadPoolExecutor(max_workers=_BULK_CONCURRENCY) as ex:
        list(ex.map(scan_one, rows))

    with _BULK_LOCK:
        job["status"] = "done"


@app.post("/api/scan/bulk")
async def scan_bulk(file: UploadFile = File(...), watchlist: str = "Bulk Upload",
                     client_id: str = DEFAULT_CLIENT_ID, sector: str = "Unassigned"):
    """sector is the batch default — a 'sector' column in the CSV overrides
    it per-row, so a single upload can span multiple categories at once."""
    raw = await file.read()
    rows = _extract_domains_from_csv(raw)
    if not rows:
        raise HTTPException(400, "No valid domains found in that CSV — expected a 'domain' column or one domain per line.")
    if len(rows) > 500:
        raise HTTPException(400, f"{len(rows)} domains found — cap this run at 500 per upload and split the rest into another batch.")

    job_id = str(uuid.uuid4())
    _BULK_JOBS[job_id] = {"total": len(rows), "completed": 0, "results": [], "status": "running"}
    threading.Thread(target=_run_bulk_job, args=(job_id, rows, watchlist, client_id, sector), daemon=True).start()
    return {"job_id": job_id, "total": len(rows)}


@app.get("/api/scan/bulk/{job_id}")
def get_bulk_job(job_id: str):
    job = _BULK_JOBS.get(job_id)
    if not job:
        raise HTTPException(404, "No such bulk job — it may have completed and the server since restarted.")
    return job


# ---------------------------------------------------------------------------
# Demo portfolio: seeded, deterministic mock data representing hundreds of
# already-scanned domains, so the UI's scale/navigation story can be demoed
# without needing to live-scan a thousand real domains in front of a client.
# Clearly flagged is_demo:true — /api/scans above is the real data.
# ---------------------------------------------------------------------------

WATCHLISTS = ["Tier-1 Suppliers", "Insured Portfolio — Q3", "Marketplace Onboarding",
              "Tier-2 Suppliers", "M&A Diligence"]
TLDS = [".com", ".io", ".co", ".net", ".biz", ".shop", ".ai"]
ADJ = ["nova", "summit", "cobalt", "harbor", "vantage", "orbit", "grid", "atlas",
       "forge", "pioneer", "meridian", "lumen", "anchor", "keystone", "beacon",
       "crestline", "ironbridge", "solace", "granite", "wavefront"]
NOUN = ["logistics", "systems", "trade", "works", "labs", "partners", "supply",
        "commerce", "freight", "capital", "materials", "dynamics", "exchange",
        "solutions", "group", "network"]


@app.get("/api/portfolio")
def portfolio(seed: int = 42, count: int = 480):
    rng = random.Random(seed)
    domains = []
    used = set()
    for i in range(count):
        while True:
            name = f"{rng.choice(ADJ)}{rng.choice(NOUN)}{rng.choice(TLDS)}"
            if name not in used:
                used.add(name)
                break
        sector = rng.choice(SECTORS[:-1])  # exclude "Unassigned" — that's only for real, uncategorized scans
        watchlist = rng.choice(WATCHLISTS)

        # Skew distribution so most are fine and a realistic minority are risky —
        # matches what an actual portfolio looks like.
        roll = rng.random()
        if roll < 0.55:
            score = rng.randint(78, 99)
        elif roll < 0.80:
            score = rng.randint(58, 82)
        elif roll < 0.94:
            score = rng.randint(32, 62)
        else:
            score = rng.randint(5, 38)

        cat_defs = [("Email Security", "email_security"), ("TLS / Certificates", "tls"),
                    ("Web Hardening", "web_hardening"), ("Exposure Surface", "exposure"),
                    ("Domain Reputation", "reputation"), ("Threat Intelligence", "threat_intel"),
                    ("Known Vulnerabilities", "cve_exposure")]
        ti_flagged = rng.random() < 0.06
        subdomain_count = rng.randint(1, 340)
        cats = []
        findings_flat = []
        for cn, code in cat_defs:
            jitter = rng.randint(-18, 18)
            base = score
            if code == "threat_intel" and ti_flagged:
                base = rng.randint(5, 35)
            cat_score = max(0, min(100, base + jitter))
            cats.append({"name": cn, "code": code, "score": cat_score})

            # Synthesize one representative finding per weak category so the
            # mock portfolio demonstrates remediation/PDF without a live scan.
            if code == "email_security" and cat_score < 80:
                if cat_score < 40:
                    findings_flat.append({"code": "no_spf", "en": "No SPF record — domain can be spoofed in the From/Return-Path.", "params": {}})
                elif cat_score < 60:
                    findings_flat.append({"code": "no_dmarc", "en": "No DMARC record — spoofed mail has no enforcement path.", "params": {}})
                else:
                    findings_flat.append({"code": "dmarc_none", "en": "DMARC policy is 'none' — monitoring only, not enforced.", "params": {}})
            elif code == "tls" and cat_score < 80:
                if cat_score < 40:
                    findings_flat.append({"code": "cert_expired", "en": "Certificate has already expired.", "params": {}})
                elif cat_score < 60:
                    findings_flat.append({"code": "self_signed", "en": "Certificate is self-signed or otherwise untrusted.", "params": {}})
                else:
                    days = rng.randint(3, 25)
                    findings_flat.append({"code": "cert_expiring", "en": f"Certificate expires in {days} days.", "params": {"days": days}})
            elif code == "web_hardening" and cat_score < 80:
                headers = rng.sample(["Strict-Transport-Security", "Content-Security-Policy",
                                       "X-Frame-Options", "X-Content-Type-Options"], k=rng.randint(1, 3))
                findings_flat.append({"code": "missing_headers",
                                       "en": f"Missing security headers: {', '.join(headers)}.", "params": {"headers": headers}})
            elif code == "exposure" and cat_score < 80:
                if subdomain_count > 200:
                    findings_flat.append({"code": "large_surface",
                                           "en": f"{subdomain_count} certificate-visible subdomains — large discoverable surface.",
                                           "params": {"count": subdomain_count}})
                else:
                    findings_flat.append({"code": "some_surface",
                                           "en": f"{subdomain_count} certificate-visible subdomains.", "params": {"count": subdomain_count}})
            elif code == "reputation" and cat_score < 80:
                if cat_score < 50:
                    age = rng.randint(5, 89)
                    findings_flat.append({"code": "very_new_domain",
                                           "en": f"Domain registered only {age} days ago — common fraud/phishing signal.", "params": {"age": age}})
                else:
                    age = rng.randint(90, 360)
                    findings_flat.append({"code": "new_domain", "en": f"Domain is under a year old ({age} days).", "params": {"age": age}})
            elif code == "threat_intel" and ti_flagged:
                n = rng.randint(1, 6)
                findings_flat.append({"code": "urlhaus_hit",
                                       "en": f"This host has {n} reported malware-hosting URL(s) on record (URLhaus).",
                                       "params": {"count": n}})
            elif code == "cve_exposure" and cat_score < 80:
                # Real, long-patched, well-documented CVEs used purely as illustrative
                # demo data — not fabricated CVE IDs.
                example = rng.choice([
                    ("Apache", "2.4.49", "CVE-2021-41773", "CRITICAL",
                     "Path traversal and remote code execution in Apache HTTP Server 2.4.49."),
                    ("WordPress", "5.8", "CVE-2022-21661", "HIGH",
                     "SQL injection via WP_Query in WordPress core before 5.8.3."),
                    ("jQuery", "1.12.4", "CVE-2020-11022", "MEDIUM",
                     "Cross-site scripting via jQuery.htmlPrefilter in versions before 3.5.0."),
                    ("OpenSSL", "1.0.1", "CVE-2014-0160", "HIGH",
                     "Heartbleed — out-of-bounds read exposing process memory in OpenSSL 1.0.1 through 1.0.1f."),
                ])
                tech, ver, cve_id, sev, summary = example
                findings_flat.append({"code": "cve_detected",
                                       "en": f"{tech} {ver}: {cve_id} ({sev}) — {summary}",
                                       "params": {"tech": tech, "version": ver, "cve_id": cve_id,
                                                  "severity": sev, "summary": summary}})

        trend = rng.choice([-1, -1, 0, 0, 0, 1, 1, 2])  # mostly stable
        last_scan_days_ago = rng.randint(0, 21)

        domains.append({
            "id": i,
            "domain": name,
            "sector": sector,
            "watchlist": watchlist,
            "overall_score": score,
            "tier": tier_for_score(score),
            "categories": cats,
            "subdomain_count": subdomain_count,
            "trend": trend,  # negative = worsening, positive = improving
            "last_scanned": (datetime.datetime.utcnow() -
                              datetime.timedelta(days=last_scan_days_ago)).isoformat(),
            "country": rng.choice(["US", "JP", "DE", "GB", "SG", "BR", "IN", "NL", "CA", "AU"]),
            "ti_flagged": ti_flagged,
            "findings_flat": findings_flat,
            "is_demo": True,
        })
    return {"count": len(domains), "domains": domains}


@app.get("/")
def root():
    return {"service": "Eagle Talon ASM API", "docs": "/docs"}
