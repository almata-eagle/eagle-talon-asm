"""SOC alerts: tell a person, quickly, when a case matters (Phase 1, ADR 0008).

After each detection run, every open case whose severity reaches the alert
threshold is sent to the configured channels (ntfy push, Slack). The alert
waits briefly for Claude's explanation so the phone shows plain words, not
a rule name. An alert nobody acknowledges is sent again (louder) a limited
number of times. A silent log collector is an alert of its own.

Safety:
- Case text comes from logs (attacker-controlled) and from Claude's reading
  of them. It is sent as plain text, length-capped, with Slack control
  syntax escaped, and never turned into an action.
- Only the explanation leaves Core, never raw log lines. SOC_ALERT_DETAIL=minimal
  sends only severity + a link (for client data on third-party channels).
- Alerting is read-only toward the network: it notifies, it does not act.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import hmac
import json
import os
import re
import sqlite3
import threading
from typing import Any, Optional
from zoneinfo import ZoneInfo

import requests

import soc_cases
import soc_logs
import soc_rules

SEV = soc_rules.SEVERITIES
COLLECTOR_KEY = "_collector"           # pseudo case id for "no logs arriving"
_lock = threading.Lock()


def _env(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()


def enabled() -> bool:
    return _env("SOC_ALERTS", "off").lower() in ("on", "1", "true", "yes")


def settings() -> dict:
    return {
        "enabled": enabled(),
        "min_severity": _env("SOC_ALERT_MIN_SEVERITY", "high") if _env("SOC_ALERT_MIN_SEVERITY", "high") in SEV else "high",
        "triage_wait_s": int(_env("SOC_ALERT_TRIAGE_WAIT_S", "600") or 600),
        "renotify_min": int(_env("SOC_ALERT_RENOTIFY_MIN", "30") or 30),
        "max_sends": max(1, int(_env("SOC_ALERT_MAX_SENDS", "3") or 3)),
        "quiet": _env("SOC_ALERT_QUIET", ""),            # e.g. 23:00-07:00 (only critical alerts then)
        "tz": _env("SOC_ALERT_TZ", "Asia/Tokyo"),
        "silent_min": int(_env("SOC_ALERT_SILENT_MIN", "30") or 30),
        "detail": "minimal" if _env("SOC_ALERT_DETAIL", "summary").lower() == "minimal" else "summary",
        "lang": _env("SOC_ALERT_LANG", "en").lower() if _env("SOC_ALERT_LANG", "en").lower() in ("en", "ja", "both") else "en",
        "base_url": _env("SOC_ALERT_BASE_URL", "").rstrip("/"),
        "env": _env("EAGLE_TALON_ENV", "prod"),
    }


def channels() -> dict[str, bool]:
    return {"ntfy": bool(_env("SOC_NTFY_TOPIC")), "slack": bool(_env("SOC_SLACK_WEBHOOK"))}


# ------------------------------------------------------------------ storage

_ready: set[str] = set()       # DB files whose alert tables exist


def _db() -> sqlite3.Connection:
    con = sqlite3.connect(soc_cases.DB_PATH, timeout=15)
    con.row_factory = sqlite3.Row
    if str(soc_cases.DB_PATH) not in _ready:
        _create(con)
        _ready.add(str(soc_cases.DB_PATH))
    return con


def init_db() -> None:
    _db().close()


def _create(con: sqlite3.Connection) -> None:
    """Additive only: CREATE ... IF NOT EXISTS."""
    con.execute("""CREATE TABLE IF NOT EXISTS soc_alert_state (
        case_id TEXT PRIMARY KEY, level TEXT, first_sent_at TEXT, last_sent_at TEXT,
        sends INTEGER DEFAULT 0, acked_at TEXT, acked_by TEXT)""")
    con.execute("""CREATE TABLE IF NOT EXISTS soc_alert_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT, at TEXT NOT NULL, case_id TEXT, kind TEXT,
        level TEXT, title TEXT, results TEXT)""")
    con.execute("CREATE INDEX IF NOT EXISTS idx_soc_alert_log_at ON soc_alert_log (at)")
    con.commit()


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _iso(t: dt.datetime) -> str:
    return t.isoformat(timespec="seconds")


# ------------------------------------------------------------------ text safety

_CTRL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")


def plain(s: Any, n: int) -> str:
    s = _CTRL.sub(" ", str(s or "")).strip()
    return s if len(s) <= n else s[: n - 1] + "…"


def slack_escape(s: str) -> str:
    """Slack treats <…> as links/mentions (<!channel>, <@U…>) and & as entities."""
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


# ------------------------------------------------------------------ ack tokens

def _secret() -> bytes:
    return _env("SOC_ALERT_SECRET").encode()


def ack_token(case_id: str) -> Optional[str]:
    if not _secret():
        return None
    return hmac.new(_secret(), case_id.encode(), hashlib.sha256).hexdigest()[:32]


def check_token(case_id: str, token: str) -> bool:
    want = ack_token(case_id)
    return bool(want) and hmac.compare_digest(want, token or "")


# ------------------------------------------------------------------ quiet hours

def in_quiet_hours(now: Optional[dt.datetime] = None, quiet: Optional[str] = None, tz: Optional[str] = None) -> bool:
    s = settings()
    quiet = s["quiet"] if quiet is None else quiet
    m = re.fullmatch(r"(\d{1,2}):(\d{2})-(\d{1,2}):(\d{2})", quiet or "")
    if not m:
        return False
    try:
        local = (now or _now()).astimezone(ZoneInfo(tz or s["tz"]))
    except Exception:  # noqa: BLE001 — a bad zone name means no quiet hours
        return False
    a = int(m[1]) * 60 + int(m[2])
    b = int(m[3]) * 60 + int(m[4])
    cur = local.hour * 60 + local.minute
    return (a <= cur < b) if a <= b else (cur >= a or cur < b)


# ------------------------------------------------------------------ messages

def _eff_sev(c: dict) -> str:
    tri = c.get("triage") or {}
    return tri.get("severity") or c.get("rule_severity") or "low"


def _sev_ge(a: str, b: str) -> bool:
    return (SEV.index(a) if a in SEV else 0) >= (SEV.index(b) if b in SEV else 0)


def build_message(c: dict, kind: str, s: Optional[dict] = None) -> dict:
    """Plain-text alert for one case. kind: new | escalated | reminder."""
    s = s or settings()
    sev = _eff_sev(c)
    tri = c.get("triage") or {}
    lang = s["lang"]
    def pick(block: dict, key: str) -> str:
        en, ja = (block.get("en") or {}).get(key, ""), (block.get("ja") or {}).get(key, "")
        if lang == "ja":
            return ja or en
        if lang == "both" and ja and en:
            return f"{en}\n{ja}"
        return en or ja
    headline = pick(tri, "headline") if tri else ""
    if not headline:
        headline = c.get("title_ja") if lang == "ja" and c.get("title_ja") else (c.get("title_en") or c.get("rule"))
    prefix = {"new": "", "escalated": "Severity raised: ", "reminder": "Still open: "}.get(kind, "")
    env = "" if s["env"] == "prod" else f"[{s['env'].upper()}] "
    title = plain(f"{env}{sev.upper()} · {prefix}{headline}", 200)
    lines: list[str] = []
    if s["detail"] == "summary":
        if tri:
            lines.append(plain(pick(tri, "what_happened"), 500))
            rec = next((o for o in tri.get("options") or [] if o.get("recommended")), None)
            if rec:
                lines.append("Suggested: " + plain(pick(rec, "title"), 160))
            if tri.get("injection_suspected"):
                lines.append("Warning: the logs may contain text aimed at the AI. Check the raw events.")
        else:
            lines.append(plain(c.get("title_en") or c.get("rule"), 300))
            lines.append("No AI explanation yet.")
        lines.append(f"Events: {c.get('event_count') or 0} · rule {plain(c.get('rule'), 40)}")
    else:
        lines.append("Open Talon to see the case.")
    url = f"{s['base_url']}/#case={c['id']}" if s["base_url"] else ""
    return {"title": title, "body": "\n".join(x for x in lines if x), "severity": sev, "url": url, "case_id": c["id"],
            "priority": 5 if (sev == "critical" or kind == "reminder") else 4}


def collector_message(silent: bool, age_s: Optional[int], s: Optional[dict] = None) -> dict:
    s = s or settings()
    env = "" if s["env"] == "prod" else f"[{s['env'].upper()}] "
    if silent:
        mins = round(age_s / 60) if age_s else None
        body = (f"The newest log is {mins} minutes old. Detection is blind until logs arrive again."
                if mins is not None else "No log files found. Detection is blind until logs arrive.")
        return {"title": f"{env}HIGH · No logs arriving from the collector", "body": body, "severity": "high",
                "url": s["base_url"] + "/" if s["base_url"] else "", "case_id": COLLECTOR_KEY, "priority": 4}
    return {"title": f"{env}Logs are arriving again", "body": "The collector recovered.", "severity": "info",
            "url": s["base_url"] + "/" if s["base_url"] else "", "case_id": COLLECTOR_KEY, "priority": 3}


# ------------------------------------------------------------------ channels

def _post_ntfy(msg: dict) -> dict:
    base = _env("SOC_NTFY_URL", "https://ntfy.sh").rstrip("/")
    payload: dict[str, Any] = {"topic": _env("SOC_NTFY_TOPIC"), "title": msg["title"], "message": msg["body"] or " ",
                               "priority": msg["priority"],
                               "tags": ["rotating_light" if msg["severity"] in ("high", "critical") else "information_source"]}
    actions = []
    if msg.get("url"):
        payload["click"] = msg["url"]
        actions.append({"action": "view", "label": "Open case", "url": msg["url"]})
    tok = ack_token(msg["case_id"]) if msg["case_id"] != COLLECTOR_KEY else None
    if tok and settings()["base_url"]:
        actions.append({"action": "http", "label": "Acknowledge", "method": "POST", "clear": True,
                        "url": f"{settings()['base_url']}/api/soc/alerts/ack/{msg['case_id']}?token={tok}"})
    if actions:
        payload["actions"] = actions
    headers = {"Content-Type": "application/json"}
    if _env("SOC_NTFY_TOKEN"):
        headers["Authorization"] = "Bearer " + _env("SOC_NTFY_TOKEN")
    r = requests.post(base, data=json.dumps(payload, ensure_ascii=False).encode(), headers=headers, timeout=10)
    return {"ok": r.ok, "status": r.status_code}


def _post_slack(msg: dict) -> dict:
    text = f"*{slack_escape(msg['title'])}*"
    if msg["body"]:
        text += "\n" + slack_escape(msg["body"])
    if msg.get("url"):
        text += f"\n<{msg['url']}|Open in Talon>"
    r = requests.post(_env("SOC_SLACK_WEBHOOK"), json={"text": text, "unfurl_links": False, "unfurl_media": False},
                      timeout=10)
    return {"ok": r.ok, "status": r.status_code}


SENDERS = {"ntfy": _post_ntfy, "slack": _post_slack}


def send(msg: dict) -> dict:
    results: dict[str, Any] = {}
    for name, on in channels().items():
        if not on:
            continue
        try:
            results[name] = SENDERS[name](msg)
        except Exception as e:  # noqa: BLE001 — one channel failing must not stop the other
            results[name] = {"ok": False, "error": type(e).__name__}
    return results


def _log(con, case_id: str, kind: str, msg: dict, results: dict) -> None:
    con.execute("INSERT INTO soc_alert_log (at, case_id, kind, level, title, results) VALUES (?,?,?,?,?,?)",
                (_iso(_now()), case_id, kind, msg["severity"], msg["title"], json.dumps(results)))


# ------------------------------------------------------------------ the decision

def decide(c: dict, state: Optional[dict], now: dt.datetime, s: dict, quiet: bool) -> Optional[str]:
    """What to send for this open case now: 'new', 'escalated', 'reminder' or None."""
    sev = _eff_sev(c)
    if not _sev_ge(sev, s["min_severity"]):
        return None
    if quiet and sev != "critical":
        return None                       # held until quiet hours end
    if state is None:
        # Wait for Claude's explanation, but not forever.
        waiting = c.get("triage_status") in ("pending", "stale")
        created = dt.datetime.fromisoformat(c["created_at"]) if c.get("created_at") else now
        if waiting and (now - created).total_seconds() < s["triage_wait_s"]:
            return None
        return "new"
    if state.get("acked_at"):
        return None
    if not _sev_ge(state.get("level") or "info", sev):
        return "escalated"
    if (state.get("sends") or 0) >= s["max_sends"]:
        return None
    last = dt.datetime.fromisoformat(state["last_sent_at"]) if state.get("last_sent_at") else now
    if (now - last).total_seconds() >= s["renotify_min"] * 60:
        return "reminder"
    return None


def process(now: Optional[dt.datetime] = None) -> dict:
    """Called after each detection run. Returns counts; never raises."""
    if not enabled() or not any(channels().values()):
        return {"alerts": "off"}
    if not _lock.acquire(blocking=False):
        return {"alerts": "busy"}
    try:
        now = now or _now()
        s = settings()
        quiet = in_quiet_hours(now)
        sent = 0
        con = _db()
        try:
            states = {r["case_id"]: dict(r) for r in con.execute("SELECT * FROM soc_alert_state")}
            for c in soc_cases.list_cases(status="open", limit=500):
                kind = decide(c, states.get(c["id"]), now, s, quiet)
                if not kind:
                    continue
                msg = build_message(c, kind, s)
                results = send(msg)
                ok = any(r.get("ok") for r in results.values())
                _log(con, c["id"], kind, msg, results)
                if ok:
                    st = states.get(c["id"])
                    if st:
                        con.execute("UPDATE soc_alert_state SET level=?, last_sent_at=?, sends=sends+1 WHERE case_id=?",
                                    (msg["severity"], _iso(now), c["id"]))
                    else:
                        con.execute("INSERT INTO soc_alert_state (case_id, level, first_sent_at, last_sent_at, sends) "
                                    "VALUES (?,?,?,?,1)", (c["id"], msg["severity"], _iso(now), _iso(now)))
                    sent += 1
            sent += _collector_check(con, now, s, states.get(COLLECTOR_KEY))
            con.commit()
        finally:
            con.close()
        return {"alerts_sent": sent}
    except Exception as e:  # noqa: BLE001 — alerting must never break detection
        return {"alerts_error": type(e).__name__}
    finally:
        _lock.release()


def _collector_check(con, now: dt.datetime, s: dict, state: Optional[dict]) -> int:
    st = soc_logs.status()
    if not st.get("connected"):
        return 0                          # no hot store configured: nothing to watch
    age = st.get("newest_file_age_s")
    silent = age is None or age > s["silent_min"] * 60
    if silent and not state:
        msg = collector_message(True, age, s)
        results = send(msg)
        _log(con, COLLECTOR_KEY, "collector_silent", msg, results)
        if any(r.get("ok") for r in results.values()):
            con.execute("INSERT INTO soc_alert_state (case_id, level, first_sent_at, last_sent_at, sends) VALUES (?,?,?,?,1)",
                        (COLLECTOR_KEY, "high", _iso(now), _iso(now)))
            return 1
    elif not silent and state:
        msg = collector_message(False, age, s)
        results = send(msg)
        _log(con, COLLECTOR_KEY, "collector_recovered", msg, results)
        con.execute("DELETE FROM soc_alert_state WHERE case_id = ?", (COLLECTOR_KEY,))
        return 1
    return 0


# ------------------------------------------------------------------ ack, test, reads

def ack(case_id: str, by: str) -> bool:
    con = _db()
    try:
        cur = con.execute("UPDATE soc_alert_state SET acked_at=?, acked_by=? WHERE case_id=? AND acked_at IS NULL",
                          (_iso(_now()), plain(by, 60), case_id))
        if not cur.rowcount and not con.execute("SELECT 1 FROM soc_alert_state WHERE case_id=?", (case_id,)).fetchone():
            # Acknowledged before any alert went out: record it so none is sent.
            con.execute("INSERT INTO soc_alert_state (case_id, level, sends, acked_at, acked_by) VALUES (?,?,0,?,?)",
                        (case_id, "info", _iso(_now()), plain(by, 60)))
        con.commit()
        return True
    finally:
        con.close()


def state_for(case_ids: list[str]) -> dict[str, dict]:
    if not case_ids:
        return {}
    con = _db()
    try:
        q = ",".join("?" * len(case_ids))
        return {r["case_id"]: dict(r) for r in con.execute(f"SELECT * FROM soc_alert_state WHERE case_id IN ({q})", case_ids)}
    finally:
        con.close()


def recent(limit: int = 50) -> list[dict]:
    con = _db()
    try:
        out = []
        for r in con.execute("SELECT * FROM soc_alert_log ORDER BY id DESC LIMIT ?", (max(1, min(limit, 500)),)):
            d = dict(r)
            d["results"] = json.loads(d["results"] or "{}")
            out.append(d)
        return out
    finally:
        con.close()


def send_test() -> dict:
    s = settings()
    env = "" if s["env"] == "prod" else f"[{s['env'].upper()}] "
    msg = {"title": f"{env}Talon test alert", "body": "If you can read this, alerts reach you.", "severity": "info",
           "url": s["base_url"] + "/" if s["base_url"] else "", "case_id": "_test", "priority": 3}
    results = send(msg)
    con = _db()
    try:
        _log(con, "_test", "test", msg, results)
        con.commit()
    finally:
        con.close()
    return results


def status() -> dict:
    s = settings()
    return {**{k: s[k] for k in ("enabled", "min_severity", "quiet", "tz", "renotify_min", "max_sends", "detail", "lang",
                                  "silent_min", "triage_wait_s")},
            "channels": channels(), "ack_links": bool(_secret() and s["base_url"]),
            "base_url_set": bool(s["base_url"]), "quiet_now": in_quiet_hours()}
