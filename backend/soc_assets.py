"""
Eagle SOC — known devices (v0.6).

The operator names their own devices ("Eddy's MacBook", "Core") and can mark
behaviour as expected for that device, so rules stop opening cases about it:
for example, a laptop with a VPN app pinging servers all over the world.
Names show up across the UI, and Claude gets them as operator-provided
context.

Stored in the Talon DB (table soc_assets, additive). Only rule kinds that are
about *our* device's normal behaviour can be quieted. Attacks from outside
(scans, password guessing, IDS alerts, threat-intel matches) can't be.
"""
from __future__ import annotations

import datetime as dt
import ipaddress
import json
import re
import sqlite3
from typing import Optional

KINDS = ("laptop", "desktop", "phone", "server", "nas", "network", "iot", "tv", "printer", "other")
QUIETABLE = ("outbound_new_country", "outbound_volume", "allowed_inbound")
MAX_NAME = 60
MAX_NOTES = 300
_CTRL = re.compile(r"[\x00-\x1f\x7f]")


def _db() -> sqlite3.Connection:
    import soc_cases
    return soc_cases._db()


def init_db() -> None:
    con = _db()
    try:
        con.execute("""
            CREATE TABLE IF NOT EXISTS soc_assets (
                ip TEXT PRIMARY KEY, name TEXT, kind TEXT, notes TEXT,
                quiet TEXT, updated_at TEXT
            )""")
        con.commit()
    finally:
        con.close()


def normalise_ip(ip: str) -> str:
    return str(ipaddress.ip_address((ip or "").strip()))


def _clean(s: Optional[str], n: int) -> Optional[str]:
    s = _CTRL.sub(" ", (s or "")).strip()[:n]
    return s or None


def _row(r) -> dict:
    try:
        quiet = [q for q in json.loads(r["quiet"] or "[]") if q in QUIETABLE]
    except (TypeError, ValueError):
        quiet = []
    return {"ip": r["ip"], "name": r["name"], "kind": r["kind"], "notes": r["notes"],
            "quiet": quiet, "updated_at": r["updated_at"]}


def all_assets() -> dict[str, dict]:
    try:
        con = _db()
        try:
            rows = con.execute("SELECT * FROM soc_assets ORDER BY ip").fetchall()
        finally:
            con.close()
    except sqlite3.Error:
        return {}
    return {r["ip"]: _row(r) for r in rows}


def get(ip: str) -> Optional[dict]:
    return all_assets().get(ip)


def save(ip: str, name: Optional[str], kind: Optional[str], notes: Optional[str],
         quiet: list[str], resolve_matching: bool = False) -> dict:
    ip = normalise_ip(ip)
    if kind and kind not in KINDS:
        raise ValueError("unknown device type")
    bad = [q for q in quiet if q not in QUIETABLE]
    if bad:
        raise ValueError("these case types can't be quieted: " + ", ".join(bad))
    now = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
    con = _db()
    try:
        con.execute(
            "INSERT INTO soc_assets (ip, name, kind, notes, quiet, updated_at) VALUES (?,?,?,?,?,?) "
            "ON CONFLICT(ip) DO UPDATE SET name=excluded.name, kind=excluded.kind, notes=excluded.notes, "
            "quiet=excluded.quiet, updated_at=excluded.updated_at",
            (ip, _clean(name, MAX_NAME), kind or None, _clean(notes, MAX_NOTES), json.dumps(sorted(set(quiet))), now),
        )
        resolved = 0
        if resolve_matching and quiet:
            for r in con.execute("SELECT id, rule, entity FROM soc_cases WHERE status = 'open'").fetchall():
                if r["rule"] in quiet and ip in _entity_ips(r["entity"]):
                    con.execute("UPDATE soc_cases SET status='resolved', updated_at=?, resolved_at=?, "
                                "feedback=COALESCE(feedback, 'noise') WHERE id=?", (now, now, r["id"]))
                    resolved += 1
        con.commit()
    finally:
        con.close()
    out = get(ip) or {}
    out["resolved"] = resolved
    return out


def delete(ip: str) -> bool:
    con = _db()
    try:
        cur = con.execute("DELETE FROM soc_assets WHERE ip = ?", (normalise_ip(ip),))
        con.commit()
        return cur.rowcount == 1
    finally:
        con.close()


def _entity_ips(entity) -> list[str]:
    if isinstance(entity, str):
        try:
            entity = json.loads(entity)
        except ValueError:
            return []
    return [x for x in (entity or []) if isinstance(x, str)]


def is_quiet(rule: str, entity, assets: Optional[dict] = None) -> bool:
    """True when the case would be about a known device whose owner marked
    this kind of case as expected."""
    if rule not in QUIETABLE:
        return False
    assets = assets if assets is not None else all_assets()
    return any(rule in (assets.get(ip) or {}).get("quiet", []) for ip in _entity_ips(entity))


def context_text(limit: int = 40) -> str:
    """Operator-entered device names for Claude's network context."""
    lines = []
    for a in list(all_assets().values())[:limit]:
        if not (a["name"] or a["notes"]):
            continue
        bits = [a["ip"], "—", a["name"] or "(unnamed)"]
        if a["kind"]:
            bits.append(f"({a['kind']})")
        if a["notes"]:
            bits.append(f": {a['notes']}")
        if a["quiet"]:
            bits.append(f" [owner says expected: {', '.join(a['quiet'])}]")
        lines.append(" ".join(bits))
    return "\n".join(lines)
