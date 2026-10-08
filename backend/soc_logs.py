"""
Eagle SOC — read-only search over the collector's hot store.

The collector (soc/collector/vector.yaml) writes one JSON event per line to
    <hot>/<dataset>/<YYYY-MM-DD>/<HH>.ndjson      (UTC dates/hours)
using the flat "schema 1" format in docs/SOC-COLLECTOR.md. This module queries
those files in place with DuckDB — there is no database server to run — and
returns plain dicts for the API.

Security notes
- Everything in a log line is attacker-controlled (user agents, DNS names,
  signatures). This module never interprets log content; it only filters and
  returns it. The UI must escape it (it does) and anything that later feeds it
  to Claude must treat it as data, never instructions.
- All user input reaches DuckDB as bound parameters, never as SQL text. File
  paths are built only from the fixed directory layout and validated dates.
- The hot store is mounted read-only into the API container.
"""
from __future__ import annotations

import datetime as dt
import json
import os
import re
from pathlib import Path
from typing import Any, Optional

import duckdb

HOT_DIR = Path(os.environ.get("SOC_HOT_DIR_IN_CONTAINER", "/soc-hot"))

# Synthetic events from soc/deploy-collector.sh's self-test.
SELFTEST_HOST = "eagle-soc-selftest"

# Fixed column types so files with different shapes (FortiGate sends strings
# where Suricata sends numbers) always read the same way.
COLUMNS = {
    "timestamp": "VARCHAR",
    "source": "VARCHAR",
    "dataset": "VARCHAR",
    "subtype": "VARCHAR",
    "host": "VARCHAR",
    "action": "VARCHAR",
    "src_ip": "VARCHAR",
    "src_port": "INTEGER",
    "dst_ip": "VARCHAR",
    "dst_port": "INTEGER",
    "proto": "VARCHAR",
    "direction": "VARCHAR",
    "src_country": "VARCHAR",
    "dst_country": "VARCHAR",
    "bytes_out": "BIGINT",
    "bytes_in": "BIGINT",
    "app": "VARCHAR",
    "policy": "VARCHAR",
    "level": "VARCHAR",
    "signature": "VARCHAR",
    "collector_from": "VARCHAR",
    "raw": "JSON",
}

# What counts as "blocked" across FortiGate (deny/dropped/blocked/reset) and
# Suricata (blocked/drop). Everything else with an action is "allowed" —
# including alert-only verdicts like "detected" and "allowed".
BLOCKED_ACTIONS = ("deny", "dropped", "blocked", "block", "drop", "reset")

RANGES = {"1h": 1, "6h": 6, "24h": 24, "7d": 24 * 7}
DIRECTIONS = ("inbound", "outbound", "internal", "external")
OUTCOMES = ("allowed", "blocked")
MAX_LIMIT = 500
MAX_QUERY_LEN = 200

_DATASET_RE = re.compile(r"^[a-z0-9_]+\.[a-z0-9_]+$")
_DAY_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_HOUR_RE = re.compile(r"^(\d{2})\.ndjson$")

# The "other side" of a connection: for inbound traffic the remote end is the
# source, for outbound it's the destination.
_REMOTE_IP = "CASE WHEN direction = 'inbound' THEN src_ip WHEN direction IN ('outbound','external') THEN dst_ip END"
_REMOTE_COUNTRY = ("CASE WHEN direction = 'inbound' THEN src_country "
                   "WHEN direction IN ('outbound','external') THEN dst_country END")
_OUTCOME = (f"CASE WHEN lower(action) IN ({', '.join(repr(a) for a in BLOCKED_ACTIONS)}) THEN 'blocked' "
            "WHEN action IS NOT NULL THEN 'allowed' END")


def available() -> bool:
    """True when the hot store is mounted and has at least one dataset."""
    try:
        return HOT_DIR.is_dir() and any(_DATASET_RE.match(p.name) for p in HOT_DIR.iterdir() if p.is_dir())
    except OSError:
        return False


def datasets() -> list[str]:
    if not HOT_DIR.is_dir():
        return []
    return sorted(p.name for p in HOT_DIR.iterdir() if p.is_dir() and _DATASET_RE.match(p.name))


def _utcnow() -> dt.datetime:
    """The clock; tests replace it so fixtures never age out."""
    return dt.datetime.now(dt.timezone.utc)


def _window(range_key: str, now: Optional[dt.datetime] = None) -> tuple[dt.datetime, dt.datetime]:
    now = now or _utcnow()
    hours = RANGES.get(range_key, 24)
    return now - dt.timedelta(hours=hours), now


def _files(since: dt.datetime, until: dt.datetime, only: Optional[str] = None) -> list[str]:
    """Hourly files that can contain events in [since, until]. The folder layout
    (dataset/day/hour) lets us skip everything outside the window cheaply."""
    out: list[str] = []
    first_hour = since.replace(minute=0, second=0, microsecond=0)
    for ds in datasets():
        if only and ds != only:
            continue
        base = HOT_DIR / ds
        for day_dir in base.iterdir():
            if not (day_dir.is_dir() and _DAY_RE.match(day_dir.name)):
                continue
            day = dt.datetime.strptime(day_dir.name, "%Y-%m-%d").replace(tzinfo=dt.timezone.utc)
            if day + dt.timedelta(days=1) <= first_hour or day > until:
                continue
            for f in day_dir.iterdir():
                m = _HOUR_RE.match(f.name)
                if not m:
                    continue
                start = day + dt.timedelta(hours=int(m.group(1)))
                if start + dt.timedelta(hours=1) <= first_hour or start > until:
                    continue
                if f.stat().st_size > 0:
                    out.append(str(f))
    return sorted(out)


def _connect() -> duckdb.DuckDBPyConnection:
    con = duckdb.connect(database=":memory:")
    con.execute("SET threads = 2")
    con.execute("SET memory_limit = '1GB'")
    return con


def _base_query(files: list[str]) -> str:
    # ts_ms: epoch milliseconds, used for filtering and returned to the UI,
    # which renders it in the viewer's local time.
    return (
        "WITH ev AS ("
        " SELECT *, epoch_ms(try_cast(timestamp AS TIMESTAMPTZ)) AS ts_ms"
        " FROM read_json(?, format = 'newline_delimited', columns = ?, ignore_errors = true)"
        ")"
    )


def _filters(
    since: dt.datetime,
    until: dt.datetime,
    q: Optional[str],
    outcome: Optional[str],
    direction: Optional[str],
    include_selftest: bool,
) -> tuple[str, list[Any]]:
    where = ["ts_ms BETWEEN ? AND ?"]
    params: list[Any] = [int(since.timestamp() * 1000), int(until.timestamp() * 1000)]
    if not include_selftest:
        where.append("host IS DISTINCT FROM ?")
        params.append(SELFTEST_HOST)
    if outcome in OUTCOMES:
        where.append(f"({_OUTCOME}) = ?")
        params.append(outcome)
    if direction in DIRECTIONS:
        where.append("direction = ?")
        params.append(direction)
    if q:
        q = q.strip()[:MAX_QUERY_LEN]
        if q:
            like = f"%{q}%"
            fields = ["src_ip", "dst_ip", "src_country", "dst_country", "signature", "app", "host",
                      "CAST(dst_port AS VARCHAR)", "CAST(src_port AS VARCHAR)", "action", "dataset"]
            where.append("(" + " OR ".join(f"{f} ILIKE ?" for f in fields) + ")")
            params.extend([like] * len(fields))
    return " WHERE " + " AND ".join(where), params


def search(
    range_key: str = "24h",
    dataset: Optional[str] = None,
    q: Optional[str] = None,
    outcome: Optional[str] = None,
    direction: Optional[str] = None,
    limit: int = 200,
    include_selftest: bool = False,
    now: Optional[dt.datetime] = None,
) -> dict:
    since, until = _window(range_key, now)
    if dataset and not _DATASET_RE.match(dataset):
        dataset = None
    files = _files(since, until, dataset)
    limit = max(1, min(int(limit), MAX_LIMIT))
    if not files:
        return {"events": [], "files_scanned": 0, "truncated": False}
    where, params = _filters(since, until, q, outcome, direction, include_selftest)
    sql = (
        _base_query(files)
        + " SELECT timestamp, ts_ms, source, dataset, subtype, host, action, "
        + f"({_OUTCOME}) AS outcome, src_ip, src_port, dst_ip, dst_port, proto, direction, "
        + "src_country, dst_country, bytes_out, bytes_in, app, policy, level, signature, "
        + "CAST(raw AS VARCHAR) AS raw FROM ev"
        + where
        + " ORDER BY ts_ms DESC NULLS LAST LIMIT ?"
    )
    con = _connect()
    try:
        cur = con.execute(sql, [files, COLUMNS, *params, limit + 1])
        names = [d[0] for d in cur.description]
        rows = cur.fetchall()
    finally:
        con.close()
    events = []
    for r in rows[:limit]:
        e = dict(zip(names, r))
        try:
            e["raw"] = json.loads(e["raw"]) if e["raw"] else None
        except (TypeError, ValueError):
            e["raw"] = None
        events.append(e)
    return {"events": events, "files_scanned": len(files), "truncated": len(rows) > limit}


def summary(
    range_key: str = "24h",
    dataset: Optional[str] = None,
    q: Optional[str] = None,
    outcome: Optional[str] = None,
    direction: Optional[str] = None,
    include_selftest: bool = False,
    now: Optional[dt.datetime] = None,
) -> dict:
    """Headline numbers for the same filters as search()."""
    since, until = _window(range_key, now)
    if dataset and not _DATASET_RE.match(dataset):
        dataset = None
    files = _files(since, until, dataset)
    empty = {
        "total": 0, "blocked": 0, "inbound": 0, "outbound": 0, "remote_ips": 0,
        "newest_ms": None, "top_countries": [], "top_ports_inbound": [], "by_dataset": [],
        "timeline": [], "bucket_minutes": _bucket_minutes(range_key),
    }
    if not files:
        return empty
    where, params = _filters(since, until, q, outcome, direction, include_selftest)
    con = _connect()
    try:
        base = _base_query(files)
        head = [files, COLUMNS, *params]
        totals = con.execute(
            base + " SELECT count(*), "
            f"count(*) FILTER (WHERE ({_OUTCOME}) = 'blocked'), "
            "count(*) FILTER (WHERE direction = 'inbound'), "
            "count(*) FILTER (WHERE direction = 'outbound'), "
            f"count(DISTINCT {_REMOTE_IP}), max(ts_ms) FROM ev" + where,
            head,
        ).fetchone()
        countries = con.execute(
            base + f" SELECT {_REMOTE_COUNTRY} AS c, count(*) AS n FROM ev" + where
            + f" AND {_REMOTE_COUNTRY} IS NOT NULL AND {_REMOTE_COUNTRY} NOT IN ('Reserved', '')"
            " GROUP BY c ORDER BY n DESC LIMIT 8",
            head,
        ).fetchall()
        ports = con.execute(
            base + " SELECT dst_port, count(*) AS n FROM ev" + where
            + " AND direction = 'inbound' AND dst_port IS NOT NULL GROUP BY dst_port ORDER BY n DESC LIMIT 8",
            head,
        ).fetchall()
        by_ds = con.execute(
            base + " SELECT dataset, count(*) AS n FROM ev" + where + " GROUP BY dataset ORDER BY n DESC",
            head,
        ).fetchall()
        bucket_ms = _bucket_minutes(range_key) * 60_000
        timeline = con.execute(
            base + f" SELECT (ts_ms // {bucket_ms}) * {bucket_ms} AS b, count(*), "
            f"count(*) FILTER (WHERE ({_OUTCOME}) = 'blocked') FROM ev" + where + " GROUP BY b ORDER BY b",
            head,
        ).fetchall()
    finally:
        con.close()
    return {
        "total": totals[0], "blocked": totals[1], "inbound": totals[2], "outbound": totals[3],
        "remote_ips": totals[4], "newest_ms": totals[5],
        "top_countries": [{"country": c, "count": n} for c, n in countries],
        "top_ports_inbound": [{"port": p, "count": n} for p, n in ports],
        "by_dataset": [{"dataset": d, "count": n} for d, n in by_ds],
        "timeline": [{"t": b, "total": n, "blocked": k} for b, n, k in timeline],
        "bucket_minutes": _bucket_minutes(range_key),
    }


def _bucket_minutes(range_key: str) -> int:
    return {"1h": 2, "6h": 10, "24h": 30, "7d": 360}.get(range_key, 30)


def status() -> dict:
    """Is the hot store connected, and when did the newest event arrive?
    'Newest file' is a cheap freshness signal that needs no query."""
    if not available():
        return {"connected": False, "datasets": [], "newest_file_age_s": None}
    newest = 0.0
    for ds in datasets():
        for day_dir in (HOT_DIR / ds).iterdir():
            if day_dir.is_dir() and _DAY_RE.match(day_dir.name):
                for f in day_dir.iterdir():
                    if _HOUR_RE.match(f.name):
                        newest = max(newest, f.stat().st_mtime)
    age = (dt.datetime.now().timestamp() - newest) if newest else None
    return {"connected": True, "datasets": datasets(), "newest_file_age_s": round(age) if age is not None else None}
