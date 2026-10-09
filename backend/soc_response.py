"""SOC response: block an address on the FortiGate, only after a person approves (ADR 0009).

The one action: put a public IPv4 address into a FortiGate address group
(SOC_FGT_BLOCK_GROUP) that the operator's deny policies use, for a fixed time,
then take it out again. Talon never edits policies, never touches anything
outside its own address objects, and never acts on its own.

Safety, in order:
1. A person starts it from a case and approves it with the approval code
   (SOC_RESPONSE_APPROVAL_CODE). Claude's suggestions are never executed and
   never supply the target: the address comes from the case's own evidence
   and is re-validated here.
2. Protected addresses can't be blocked: private, loopback, link-local,
   CGNAT/Tailscale (100.64.0.0/10), multicast, reserved, anything in
   SOC_RESPONSE_PROTECT (your own public IPs, resolvers), and known devices.
3. Every block expires (1 hour to 30 days). An expiry loop removes it, and
   any block can be undone at once. Limits: SOC_RESPONSE_MAX_ACTIVE active
   blocks and SOC_RESPONSE_MAX_PER_HOUR new ones per hour.
4. SOC_RESPONSE_MODE: off (default) | dryrun (record, change nothing) | live.
   Every step is written to soc_actions and soc_action_log.
5. The FortiGate API token lives in secrets.env. The admin it belongs to may
   only edit firewall addresses; TLS is checked against a pinned SHA-256
   fingerprint (SOC_FGT_FINGERPRINT) or a CA file.
"""
from __future__ import annotations

import datetime as dt
import hmac
import ipaddress
import json
import os
import re
import sqlite3
import threading
import time
import uuid
from typing import Any, Optional

import requests
from requests.adapters import HTTPAdapter

import soc_assets
import soc_cases
import soc_intel

DURATIONS = {"1h": 3600, "24h": 86400, "7d": 7 * 86400, "30d": 30 * 86400}
ACTIVE = ("active", "dryrun")
_CGNAT = ipaddress.ip_network("100.64.0.0/10")
_lock = threading.Lock()
_attempts: list[float] = []          # failed approval-code attempts (time)
_expiry_started = False


def _env(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()


def mode() -> str:
    m = _env("SOC_RESPONSE_MODE", "off").lower()
    return m if m in ("off", "dryrun", "live") else "off"


def settings() -> dict:
    env = _env("EAGLE_TALON_ENV", "prod")
    return {
        "mode": mode(),
        "env": env,
        "group": _env("SOC_FGT_BLOCK_GROUP", "TALON-BLOCK"),
        "prefix": "talon-" if env == "prod" else f"talon-{re.sub(r'[^a-z0-9]', '', env.lower())[:8]}-",
        "max_active": int(_env("SOC_RESPONSE_MAX_ACTIVE", "200") or 200),
        "max_per_hour": int(_env("SOC_RESPONSE_MAX_PER_HOUR", "20") or 20),
        "code_set": bool(_env("SOC_RESPONSE_APPROVAL_CODE")),
        "fgt_set": bool(_env("SOC_FGT_HOST") and _env("SOC_FGT_TOKEN")),
        "tls": "fingerprint" if _env("SOC_FGT_FINGERPRINT") else ("ca_file" if _env("SOC_FGT_CA_FILE") else "system"),
    }


def ready() -> tuple[bool, str]:
    s = settings()
    if s["mode"] == "off":
        return False, "response is off (SOC_RESPONSE_MODE=off)"
    if not s["code_set"]:
        return False, "no approval code is set (SOC_RESPONSE_APPROVAL_CODE)"
    if s["mode"] == "live" and not s["fgt_set"]:
        return False, "the FortiGate is not configured (SOC_FGT_HOST, SOC_FGT_TOKEN)"
    return True, ""


# ------------------------------------------------------------------ storage

_ready_dbs: set[str] = set()


def _db() -> sqlite3.Connection:
    con = sqlite3.connect(soc_cases.DB_PATH, timeout=15)
    con.row_factory = sqlite3.Row
    if str(soc_cases.DB_PATH) not in _ready_dbs:
        con.execute("""CREATE TABLE IF NOT EXISTS soc_actions (
            id TEXT PRIMARY KEY, kind TEXT NOT NULL, target TEXT NOT NULL, case_id TEXT, reason TEXT,
            mode TEXT, status TEXT NOT NULL, duration_s INTEGER, fgt_object TEXT, fgt_group TEXT,
            requested_by TEXT, approved_by TEXT, approved_at TEXT, expires_at TEXT,
            ended_at TEXT, ended_by TEXT, end_reason TEXT, error TEXT, created_at TEXT, updated_at TEXT)""")
        con.execute("CREATE INDEX IF NOT EXISTS idx_soc_actions_status ON soc_actions (status, expires_at)")
        con.execute("CREATE INDEX IF NOT EXISTS idx_soc_actions_target ON soc_actions (target, status)")
        con.execute("""CREATE TABLE IF NOT EXISTS soc_action_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT, at TEXT NOT NULL, action_id TEXT, event TEXT NOT NULL,
            actor TEXT, detail TEXT)""")
        con.commit()
        _ready_dbs.add(str(soc_cases.DB_PATH))
    return con


def init_db() -> None:
    _db().close()


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _iso(t: dt.datetime) -> str:
    return t.isoformat(timespec="seconds")


def _log(con, action_id: Optional[str], event: str, actor: str, detail: Optional[dict] = None) -> None:
    con.execute("INSERT INTO soc_action_log (at, action_id, event, actor, detail) VALUES (?,?,?,?,?)",
                (_iso(_now()), action_id, event, actor, json.dumps(detail or {}, ensure_ascii=False)[:2000]))


def _clean(s: Any, n: int) -> str:
    return re.sub(r"[\x00-\x1f\x7f]", " ", str(s or "")).strip()[:n]


# ------------------------------------------------------------------ what may be blocked

def _protect_list() -> list:
    nets = []
    for part in re.split(r"[,\s]+", _env("SOC_RESPONSE_PROTECT")):
        if part:
            try:
                nets.append(ipaddress.ip_network(part, strict=False))
            except ValueError:
                continue
    return nets


def check_target(ip: str) -> tuple[Optional[str], Optional[str]]:
    """(normalised ip, None) if it may be blocked, else (None, reason)."""
    try:
        a = ipaddress.ip_address(str(ip).strip())
    except ValueError:
        return None, "not an IP address"
    if a.version != 4:
        return None, "only IPv4 blocks are supported for now"
    if a.is_private or a.is_loopback or a.is_link_local or a.is_multicast or a.is_reserved or a.is_unspecified:
        return None, "private or special-use address (your own network can't be blocked here)"
    if a in _CGNAT:
        return None, "CGNAT/Tailscale range (100.64.0.0/10)"
    if any(a in n for n in _protect_list()):
        return None, "on the protected list (SOC_RESPONSE_PROTECT)"
    if soc_assets.get(str(a)):
        return None, "a known device: remove it from Known devices first"
    return str(a), None


def candidates(case: dict) -> list[dict]:
    """External addresses from the case's own evidence, with whether each may be blocked."""
    st = case.get("stats") or {}
    seen: list[str] = []
    for x in [*(case.get("entity") or []), *(st.get("src_ips") or []), *(st.get("dst_ips") or []),
              *[s.get(k) for s in (case.get("samples") or []) for k in ("src_ip", "dst_ip")]]:
        if isinstance(x, str) and x not in seen:
            try:
                ipaddress.ip_address(x)
            except ValueError:
                continue
            seen.append(x)
    out = []
    active = {a["target"]: a for a in list_actions(status="active") + list_actions(status="dryrun")}
    for ip in seen[:20]:
        ok, why = check_target(ip)
        try:
            internal = ipaddress.ip_address(ip).is_private
        except ValueError:
            internal = False
        if internal:
            continue              # our own devices: not offered at all
        out.append({"ip": ip, "allowed": bool(ok), "reason": why, "intel": soc_intel.lookup(ip),
                    "active": active.get(ip)})
    return out


# ------------------------------------------------------------------ approval code

def check_code(code: str) -> bool:
    now = time.time()
    _attempts[:] = [t for t in _attempts if now - t < 900]
    if len(_attempts) >= 5:
        return False
    want = _env("SOC_RESPONSE_APPROVAL_CODE")
    ok = bool(want) and hmac.compare_digest(want.encode(), (code or "").encode())
    if not ok:
        _attempts.append(now)
    return ok


def code_locked() -> bool:
    now = time.time()
    return len([t for t in _attempts if now - t < 900]) >= 5


# ------------------------------------------------------------------ FortiGate client

class _PinnedAdapter(HTTPAdapter):
    def __init__(self, fingerprint: str, **kw):
        self._fp = fingerprint
        super().__init__(**kw)

    def init_poolmanager(self, *a, **kw):
        kw["assert_fingerprint"] = self._fp
        kw["cert_reqs"] = "CERT_NONE"        # trust comes from the pinned fingerprint, not a CA
        return super().init_poolmanager(*a, **kw)


class FortiGate:
    """Only the calls Talon needs: address objects and group membership."""

    def __init__(self):
        self.base = "https://" + _env("SOC_FGT_HOST").rstrip("/")
        self.vdom = _env("SOC_FGT_VDOM", "root")
        self.s = requests.Session()
        self.s.headers["Authorization"] = "Bearer " + _env("SOC_FGT_TOKEN")
        fp = re.sub(r"[^0-9a-fA-F]", "", _env("SOC_FGT_FINGERPRINT")).lower()
        if fp:
            self.s.mount("https://", _PinnedAdapter(fp))
            self.verify: Any = False
        else:
            self.verify = _env("SOC_FGT_CA_FILE") or True

    def _call(self, method: str, path: str, body: Optional[dict] = None) -> dict:
        r = self.s.request(method, f"{self.base}/api/v2/cmdb/{path}", params={"vdom": self.vdom}, json=body,
                           verify=self.verify, timeout=15)
        try:
            j = r.json()
        except ValueError:
            j = {}
        if not r.ok or j.get("status") == "error":
            raise FortiGateError(r.status_code, j.get("cli_error") or j.get("error") or r.reason)
        return j

    def group(self, name: str) -> dict:
        res = self._call("GET", f"firewall/addrgrp/{requests.utils.quote(name, safe='')}").get("results") or []
        if not res:
            raise FortiGateError(404, f"address group {name} not found")
        return res[0]

    def add_address(self, name: str, ip: str, comment: str) -> None:
        self._call("POST", "firewall/address", {"name": name, "type": "ipmask", "subnet": f"{ip} 255.255.255.255",
                                                "comment": comment[:255]})

    def delete_address(self, name: str) -> None:
        self._call("DELETE", f"firewall/address/{requests.utils.quote(name, safe='')}")

    def add_member(self, group: str, name: str) -> None:
        self._call("POST", f"firewall/addrgrp/{requests.utils.quote(group, safe='')}/member", {"name": name})

    def remove_member(self, group: str, name: str) -> None:
        self._call("DELETE", f"firewall/addrgrp/{requests.utils.quote(group, safe='')}/member/"
                             f"{requests.utils.quote(name, safe='')}")


class FortiGateError(Exception):
    def __init__(self, status: int, msg: Any):
        self.status = status
        super().__init__(f"FortiGate {status}: {_clean(msg, 200)}")


def client() -> FortiGate:
    return FortiGate()


def check_connection() -> dict:
    """Read-only: can Talon reach the FortiGate and see its block group?"""
    s = settings()
    if not s["fgt_set"]:
        return {"ok": False, "error": "SOC_FGT_HOST and SOC_FGT_TOKEN are not set"}
    try:
        g = client().group(s["group"])
        members = [m.get("name") for m in g.get("member") or []]
        return {"ok": True, "group": s["group"], "members": len(members),
                "talon_members": len([m for m in members if str(m).startswith(s["prefix"])])}
    except FortiGateError as e:
        return {"ok": False, "error": str(e)}
    except requests.exceptions.SSLError:
        return {"ok": False, "error": "TLS check failed: the FortiGate certificate doesn't match SOC_FGT_FINGERPRINT / CA"}
    except requests.RequestException as e:
        return {"ok": False, "error": f"can't reach the FortiGate ({type(e).__name__})"}


# ------------------------------------------------------------------ actions

def _row(r) -> dict:
    return {k: r[k] for k in r.keys()} if r else None


def list_actions(status: Optional[str] = None, limit: int = 100) -> list[dict]:
    con = _db()
    try:
        if status:
            rows = con.execute("SELECT * FROM soc_actions WHERE status = ? ORDER BY created_at DESC LIMIT ?", (status, limit))
        else:
            rows = con.execute("SELECT * FROM soc_actions ORDER BY created_at DESC LIMIT ?", (limit,))
        return [_row(r) for r in rows]
    finally:
        con.close()


def get_action(aid: str) -> Optional[dict]:
    con = _db()
    try:
        return _row(con.execute("SELECT * FROM soc_actions WHERE id = ?", (aid,)).fetchone())
    finally:
        con.close()


def action_log(aid: str) -> list[dict]:
    con = _db()
    try:
        return [_row(r) for r in con.execute("SELECT * FROM soc_action_log WHERE action_id = ? ORDER BY id", (aid,))]
    finally:
        con.close()


class ResponseError(Exception):
    def __init__(self, status: int, msg: str):
        self.status = status
        super().__init__(msg)


def _notify(title: str, body: str) -> None:
    try:
        import soc_alerts
        if soc_alerts.enabled():
            env = "" if settings()["env"] == "prod" else f"[{settings()['env'].upper()}] "
            soc_alerts.send({"title": env + title, "body": body, "severity": "info", "url": soc_alerts.settings()["base_url"]
                             + "/" if soc_alerts.settings()["base_url"] else "", "case_id": "_action", "priority": 3})
    except Exception:  # noqa: BLE001 — a notification failure never undoes a block
        pass


def block(case_id: str, ip: str, duration: str, approver: str, code: str, reason: str = "") -> dict:
    ok, why = ready()
    if not ok:
        raise ResponseError(409, why)
    if code_locked():
        raise ResponseError(429, "too many wrong approval codes; wait 15 minutes")
    if not check_code(code):
        raise ResponseError(403, "wrong approval code")
    approver = _clean(approver, 60)
    if len(approver) < 2:
        raise ResponseError(422, "say who is approving")
    if duration not in DURATIONS:
        raise ResponseError(422, "duration must be 1h, 24h, 7d or 30d")
    case = soc_cases.get_case(case_id)
    if not case:
        raise ResponseError(404, "case not found")
    offered = {c["ip"] for c in candidates(case)}
    if ip not in offered:
        raise ResponseError(422, "that address is not in this case's evidence")
    target, why = check_target(ip)
    if not target:
        raise ResponseError(422, f"can't block {ip}: {why}")
    s = settings()
    with _lock:
        con = _db()
        try:
            if con.execute("SELECT 1 FROM soc_actions WHERE target = ? AND status IN ('active','dryrun','pending')",
                           (target,)).fetchone():
                raise ResponseError(409, f"{target} is already blocked")
            n_active = con.execute("SELECT count(*) FROM soc_actions WHERE status IN ('active','dryrun')").fetchone()[0]
            if n_active >= s["max_active"]:
                raise ResponseError(429, f"{n_active} blocks are active (limit {s['max_active']}); undo some first")
            since = _iso(_now() - dt.timedelta(hours=1))
            n_hour = con.execute("SELECT count(*) FROM soc_actions WHERE created_at >= ? AND status != 'failed'",
                                 (since,)).fetchone()[0]
            if n_hour >= s["max_per_hour"]:
                raise ResponseError(429, f"{n_hour} blocks in the last hour (limit {s['max_per_hour']})")
            aid = "act_" + uuid.uuid4().hex[:12]
            now = _now()
            obj = s["prefix"] + target
            con.execute("INSERT INTO soc_actions (id, kind, target, case_id, reason, mode, status, duration_s, fgt_object, "
                        "fgt_group, requested_by, approved_by, approved_at, expires_at, created_at, updated_at) "
                        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                        (aid, "block_ip", target, case_id, _clean(reason, 300), s["mode"], "pending", DURATIONS[duration],
                         obj, s["group"], approver, approver, _iso(now), _iso(now + dt.timedelta(seconds=DURATIONS[duration])),
                         _iso(now), _iso(now)))
            _log(con, aid, "approved", approver, {"ip": target, "duration": duration, "mode": s["mode"], "case": case_id})
            con.commit()
        finally:
            con.close()
    # Talk to the FortiGate outside the lock and the DB transaction.
    status, err = "dryrun", None
    if s["mode"] == "live":
        fgt = client()
        try:
            comment = f"Talon {aid} case {case_id} by {approver}, until {_iso(now + dt.timedelta(seconds=DURATIONS[duration]))}"
            try:
                fgt.add_address(obj, target, comment)
            except FortiGateError as e:
                if e.status not in (424, 500) and "exist" not in str(e).lower():
                    raise
            fgt.add_member(s["group"], obj)
            status = "active"
        except (FortiGateError, requests.RequestException) as e:
            status, err = "failed", _clean(e, 300)
            try:
                fgt.delete_address(obj)          # don't leave a stray object behind
            except Exception:  # noqa: BLE001
                pass
    con = _db()
    try:
        con.execute("UPDATE soc_actions SET status=?, error=?, updated_at=? WHERE id=?", (status, err, _iso(_now()), aid))
        _log(con, aid, "executed" if status != "failed" else "failed", "talon", {"status": status, "error": err})
        con.commit()
    finally:
        con.close()
    if status == "failed":
        _notify(f"Block FAILED: {target}", f"{err}\nCase {case_id}. Nothing was changed.")
        raise ResponseError(502, f"the FortiGate refused the change: {err}")
    _notify(("Blocked " if status == "active" else "Dry run: would block ") + target,
            f"For {duration}, approved by {approver}. Case {case_id}.")
    return get_action(aid)


def unblock(aid: str, by: str, reason: str = "undone") -> dict:
    a = get_action(aid)
    if not a:
        raise ResponseError(404, "action not found")
    if a["status"] not in ACTIVE:
        raise ResponseError(409, f"this block is already {a['status']}")
    err = None
    if a["status"] == "active":
        try:
            fgt = client()
            try:
                fgt.remove_member(a["fgt_group"], a["fgt_object"])
            except FortiGateError as e:
                if e.status != 404:
                    raise
            try:
                fgt.delete_address(a["fgt_object"])
            except FortiGateError as e:
                if e.status != 404:
                    raise
        except (FortiGateError, requests.RequestException) as e:
            err = _clean(e, 300)
    con = _db()
    try:
        if err:
            con.execute("UPDATE soc_actions SET error=?, updated_at=? WHERE id=?", (err, _iso(_now()), aid))
            _log(con, aid, "unblock_failed", _clean(by, 60), {"error": err})
            con.commit()
            raise ResponseError(502, f"couldn't remove the block on the FortiGate: {err} (will retry at expiry check)")
        status = "expired" if reason == "expired" else "undone"
        con.execute("UPDATE soc_actions SET status=?, ended_at=?, ended_by=?, end_reason=?, error=NULL, updated_at=? "
                    "WHERE id=?", (status, _iso(_now()), _clean(by, 60), _clean(reason, 200), _iso(_now()), aid))
        _log(con, aid, status, _clean(by, 60), {"reason": reason})
        con.commit()
    finally:
        con.close()
    if reason != "expired":
        _notify(f"Unblocked {a['target']}", f"By {_clean(by, 60)}.")
    return get_action(aid)


def expire_due(now: Optional[dt.datetime] = None) -> dict:
    """Remove every block whose time is up. Failed removals are retried next time."""
    now = now or _now()
    con = _db()
    try:
        due = [r["id"] for r in con.execute("SELECT id FROM soc_actions WHERE status IN ('active','dryrun') AND expires_at <= ?",
                                            (_iso(now),))]
    finally:
        con.close()
    done = failed = 0
    for aid in due:
        try:
            unblock(aid, "talon", "expired")
            done += 1
        except ResponseError:
            failed += 1
    return {"expired": done, "expire_failed": failed}


def start_expiry() -> bool:
    """Always runs, whatever the mode: taking a block off is always safe, and a
    block must never outlive its time because response was switched off."""
    global _expiry_started
    if _expiry_started:
        return False

    def loop():
        time.sleep(30)
        while True:
            try:
                expire_due()
            except Exception:  # noqa: BLE001
                pass
            time.sleep(60)

    threading.Thread(target=loop, daemon=True, name="soc-response-expiry").start()
    _expiry_started = True
    return True


def status() -> dict:
    s = settings()
    ok, why = ready()
    con = _db()
    try:
        active = con.execute("SELECT count(*) FROM soc_actions WHERE status IN ('active','dryrun')").fetchone()[0]
    finally:
        con.close()
    return {**{k: s[k] for k in ("mode", "group", "prefix", "max_active", "max_per_hour", "tls", "fgt_set", "code_set")},
            "ready": ok, "not_ready_reason": why, "active": active, "durations": list(DURATIONS),
            "code_locked": code_locked()}
