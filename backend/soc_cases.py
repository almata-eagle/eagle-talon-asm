"""
Eagle SOC — cases (Phase 2).

A case is one entity doing one suspicious thing over time (e.g. "45.148.10.12
scanning us"). Detection findings (soc_rules.py) are merged into cases:
while a case is open and the same rule+entity fires again within
MERGE_GAP_HOURS, the existing case grows instead of a new one appearing. That
is what turns 40 blocked packets into one item to review.

Cases live in the Talon SQLite DB, in their own table. Migrations are
additive only (CREATE TABLE IF NOT EXISTS / ADD COLUMN): Eagle Eye shares the
DB and older releases must keep working on it.

The engine loop (start_engine) runs only when SOC_DETECT=on (staging):
  every SOC_DETECT_INTERVAL_S seconds → detect → merge into cases → triage a
  few pending cases with Claude (soc_triage.py, rate-limited).
Nothing here ever acts on the network. Response options are suggestions.
"""
from __future__ import annotations

import datetime as dt
import json
import os
import sqlite3
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Optional

import soc_logs
import soc_rules
import soc_triage

DB_PATH = Path(os.environ.get("EAGLE_TALON_DB_PATH", str(Path(__file__).parent / "eagle_talon.db")))
MERGE_GAP_HOURS = 6
RETRIAGE_GROWTH = 2.0      # re-triage when a case has at least doubled…
MAX_TRIAGES_PER_CASE = 3   # …but never more than this many times
STATUSES = ("open", "resolved")
FEEDBACK = ("useful", "noise")

_lock = threading.Lock()   # detection/triage runs never overlap
_engine_started = False
_last_run: dict[str, Any] = {}


def _db() -> sqlite3.Connection:
    con = sqlite3.connect(DB_PATH, timeout=15)
    con.row_factory = sqlite3.Row
    return con


def init_db() -> None:
    con = _db()
    try:
        con.execute("""
            CREATE TABLE IF NOT EXISTS soc_cases (
                id TEXT PRIMARY KEY,
                rule TEXT NOT NULL,
                entity TEXT NOT NULL,
                title_en TEXT, title_ja TEXT,
                rule_severity TEXT,
                status TEXT NOT NULL DEFAULT 'open',
                first_seen_ms INTEGER, last_seen_ms INTEGER,
                event_count INTEGER DEFAULT 0,
                stats TEXT, samples TEXT,
                created_at TEXT, updated_at TEXT,
                triage TEXT,
                triage_status TEXT NOT NULL DEFAULT 'pending',
                triage_error TEXT, triage_model TEXT, triage_at TEXT,
                triage_in_tokens INTEGER DEFAULT 0, triage_out_tokens INTEGER DEFAULT 0,
                triage_count INTEGER DEFAULT 0,
                triaged_event_count INTEGER DEFAULT 0,
                feedback TEXT, feedback_note TEXT, feedback_at TEXT
            )""")
        con.execute("CREATE INDEX IF NOT EXISTS idx_soc_cases_key ON soc_cases (rule, entity, status)")
        con.execute("CREATE INDEX IF NOT EXISTS idx_soc_cases_seen ON soc_cases (last_seen_ms)")
        con.commit()
    finally:
        con.close()


def _now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def _entity_key(entity: list) -> str:
    return json.dumps(entity, ensure_ascii=False)


def merge_findings(findings: list[dict], now: Optional[dt.datetime] = None) -> dict:
    """Merge findings into cases. Returns counts of created/updated cases."""
    now = now or soc_logs._utcnow()
    now_ms = int(now.timestamp() * 1000)
    created = updated = 0
    con = _db()
    try:
        for f in findings:
            key = _entity_key(f["entity"])
            st = f["stats"]
            row = con.execute(
                "SELECT * FROM soc_cases WHERE rule = ? AND entity = ? AND status = 'open' "
                "AND last_seen_ms >= ? ORDER BY last_seen_ms DESC LIMIT 1",
                (f["rule"], key, now_ms - MERGE_GAP_HOURS * 3600_000),
            ).fetchone()
            first_ms = row["first_seen_ms"] if row else (st.get("first_ms") or now_ms)
            # Describe the case by ALL its events since it started, not just this window.
            stats, samples = soc_rules.case_evidence(f["rule"], f["entity"], first_ms, now_ms)
            if not stats or not stats.get("n"):
                stats, samples = st, []
            last_ms = stats.get("last_ms") or st.get("last_ms") or now_ms
            sev = _max_sev(f["severity"], row["rule_severity"] if row else None)
            if row:
                triage_status = row["triage_status"]
                grew = (stats.get("n") or 0) >= RETRIAGE_GROWTH * max(row["triaged_event_count"] or 0, 1)
                escalated = sev != row["rule_severity"]
                if triage_status == "done" and (grew or escalated) and row["triage_count"] < MAX_TRIAGES_PER_CASE:
                    triage_status = "stale"
                con.execute(
                    "UPDATE soc_cases SET title_en=?, title_ja=?, rule_severity=?, last_seen_ms=?, event_count=?, "
                    "stats=?, samples=?, updated_at=?, triage_status=? WHERE id=?",
                    (f["title_en"], f["title_ja"], sev, last_ms, stats.get("n") or 0,
                     json.dumps(stats, default=str), json.dumps(samples, default=str), _now_iso(),
                     triage_status, row["id"]),
                )
                updated += 1
            else:
                cid = "case_" + uuid.uuid4().hex[:12]
                con.execute(
                    "INSERT INTO soc_cases (id, rule, entity, title_en, title_ja, rule_severity, status, "
                    "first_seen_ms, last_seen_ms, event_count, stats, samples, created_at, updated_at, triage_status) "
                    "VALUES (?,?,?,?,?,?, 'open', ?,?,?,?,?,?,?, ?)",
                    (cid, f["rule"], key, f["title_en"], f["title_ja"], sev, first_ms, last_ms,
                     stats.get("n") or 0, json.dumps(stats, default=str), json.dumps(samples, default=str),
                     _now_iso(), _now_iso(), "pending" if soc_triage.enabled() else "skipped"),
                )
                created += 1
        con.commit()
    finally:
        con.close()
    return {"created": created, "updated": updated}


def _max_sev(a: Optional[str], b: Optional[str]) -> str:
    order = soc_rules.SEVERITIES
    ia = order.index(a) if a in order else 0
    ib = order.index(b) if b in order else 0
    return order[max(ia, ib)]


def triage_pending(limit: int = 3) -> dict:
    """Send a few waiting cases to Claude, highest severity first, within the
    hourly budget. Each triage result is stored on the case."""
    if not soc_triage.enabled():
        return {"triaged": 0, "reason": "triage disabled or no API key"}
    budget = soc_triage.budget_left(_triages_last_hour())
    if budget <= 0:
        return {"triaged": 0, "reason": "hourly triage budget used"}
    con = _db()
    try:
        rows = con.execute(
            "SELECT * FROM soc_cases WHERE triage_status IN ('pending', 'stale') "
            "AND triage_count < ? ORDER BY "
            "CASE rule_severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END DESC, "
            "last_seen_ms DESC LIMIT ?",
            (MAX_TRIAGES_PER_CASE, min(limit, budget)),
        ).fetchall()
    finally:
        con.close()
    done = 0
    for row in rows:
        case = _row_to_case(row)
        try:
            result = soc_triage.triage_case(case)
            _store_triage(row["id"], result, case["event_count"])
            done += 1
        except Exception as e:  # noqa: BLE001 — record any failure on the case, keep going
            _store_triage_error(row["id"], str(e)[:500])
    return {"triaged": done}


def _triages_last_hour() -> int:
    since = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=1)).isoformat(timespec="seconds")
    con = _db()
    try:
        return con.execute("SELECT count(*) FROM soc_cases WHERE triage_at >= ?", (since,)).fetchone()[0]
    finally:
        con.close()


def _store_triage(case_id: str, result: dict, event_count: int) -> None:
    con = _db()
    try:
        con.execute(
            "UPDATE soc_cases SET triage=?, triage_status='done', triage_error=NULL, triage_model=?, triage_at=?, "
            "triage_in_tokens = triage_in_tokens + ?, triage_out_tokens = triage_out_tokens + ?, "
            "triage_count = triage_count + 1, triaged_event_count=? WHERE id=?",
            (json.dumps(result["triage"], ensure_ascii=False), result["model"], _now_iso(),
             result["input_tokens"], result["output_tokens"], event_count, case_id),
        )
        con.commit()
    finally:
        con.close()


def _store_triage_error(case_id: str, err: str) -> None:
    con = _db()
    try:
        con.execute(
            "UPDATE soc_cases SET triage_status='error', triage_error=?, triage_at=?, "
            "triage_count = triage_count + 1 WHERE id=?",
            (err, _now_iso(), case_id),
        )
        con.commit()
    finally:
        con.close()


def run_once(now: Optional[dt.datetime] = None, triage: bool = True) -> dict:
    """One full cycle: detect → merge → triage. Safe to call manually."""
    if not _lock.acquire(blocking=False):
        return {"skipped": "a run is already in progress"}
    try:
        t0 = time.time()
        res: dict[str, Any] = {"at": _now_iso()}
        if not soc_logs.available():
            res["error"] = "hot store not connected"
        else:
            findings = soc_rules.detect(now=now)
            res["findings"] = len(findings)
            res.update(merge_findings(findings, now=now))
            if triage:
                res.update(triage_pending())
        res["seconds"] = round(time.time() - t0, 2)
        _last_run.clear()
        _last_run.update(res)
        return res
    finally:
        _lock.release()


def last_run() -> dict:
    return dict(_last_run)


def start_engine() -> bool:
    """Background loop; only when SOC_DETECT=on. Never dies on one bad run."""
    global _engine_started
    if _engine_started or os.environ.get("SOC_DETECT", "off").lower() not in ("on", "1", "true", "yes"):
        return False
    interval = max(60, int(os.environ.get("SOC_DETECT_INTERVAL_S", "300")))

    def loop():
        time.sleep(20)  # let the API finish starting
        while True:
            try:
                run_once()
            except Exception as e:  # noqa: BLE001
                _last_run.update({"at": _now_iso(), "error": str(e)[:300]})
            time.sleep(interval)

    threading.Thread(target=loop, daemon=True, name="soc-engine").start()
    _engine_started = True
    return True


def engine_enabled() -> bool:
    return _engine_started


# ---------------------------------------------------------------- reads/writes

def _row_to_case(row: sqlite3.Row, full: bool = True) -> dict:
    c = {k: row[k] for k in row.keys()}
    c["entity"] = json.loads(c["entity"])
    for k in ("stats", "samples", "triage"):
        if full or k == "triage":
            c[k] = json.loads(c[k]) if c[k] else None
        else:
            c.pop(k, None)
    return c


def list_cases(status: Optional[str] = None, limit: int = 100) -> list[dict]:
    con = _db()
    try:
        q = "SELECT * FROM soc_cases"
        args: list[Any] = []
        if status in STATUSES:
            q += " WHERE status = ?"
            args.append(status)
        q += (" ORDER BY CASE status WHEN 'open' THEN 0 ELSE 1 END, "
              "CASE COALESCE(json_extract(triage, '$.severity'), rule_severity) "
              "WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END DESC, "
              "last_seen_ms DESC LIMIT ?")
        args.append(max(1, min(limit, 500)))
        return [_row_to_case(r, full=False) for r in con.execute(q, args).fetchall()]
    finally:
        con.close()


def get_case(case_id: str) -> Optional[dict]:
    con = _db()
    try:
        row = con.execute("SELECT * FROM soc_cases WHERE id = ?", (case_id,)).fetchone()
        return _row_to_case(row) if row else None
    finally:
        con.close()


def set_status(case_id: str, status: str) -> bool:
    if status not in STATUSES:
        return False
    con = _db()
    try:
        cur = con.execute("UPDATE soc_cases SET status=?, updated_at=? WHERE id=?", (status, _now_iso(), case_id))
        con.commit()
        return cur.rowcount == 1
    finally:
        con.close()


def set_feedback(case_id: str, verdict: Optional[str], note: Optional[str]) -> bool:
    if verdict is not None and verdict not in FEEDBACK:
        return False
    con = _db()
    try:
        cur = con.execute(
            "UPDATE soc_cases SET feedback=?, feedback_note=?, feedback_at=? WHERE id=?",
            (verdict, (note or "")[:1000] or None, _now_iso(), case_id),
        )
        con.commit()
        return cur.rowcount == 1
    finally:
        con.close()


def request_retriage(case_id: str) -> bool:
    con = _db()
    try:
        cur = con.execute(
            "UPDATE soc_cases SET triage_status='pending', triage_error=NULL WHERE id=? AND triage_count < ?",
            (case_id, MAX_TRIAGES_PER_CASE + 2),  # a human may ask twice more than the automatic limit
        )
        con.commit()
        return cur.rowcount == 1
    finally:
        con.close()


def usage_summary() -> dict:
    since = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=1)).isoformat(timespec="seconds")
    con = _db()
    try:
        r = con.execute(
            "SELECT count(*), COALESCE(sum(triage_in_tokens),0), COALESCE(sum(triage_out_tokens),0) "
            "FROM soc_cases WHERE triage_at >= ?", (since,)).fetchone()
        counts = dict(con.execute("SELECT status, count(*) FROM soc_cases GROUP BY status").fetchall())
    finally:
        con.close()
    return {"cases_triaged_24h": r[0], "input_tokens_24h": r[1], "output_tokens_24h": r[2],
            "open": counts.get("open", 0), "resolved": counts.get("resolved", 0)}
