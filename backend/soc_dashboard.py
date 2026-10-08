"""
Eagle SOC — dashboard aggregates (Phase 3).

Two read-only views over data that already exists:

  traffic_map()  hot store → one flow per (direction, remote country), with
                 events, blocked, bytes, remote IPs, top ports and top IPs,
                 placed on the map by soc_geo.
  dashboard()    cases + sensors + engine → KPIs (MTTD, time to triage, MTTR),
                 an ATT&CK tally, and "callouts": the few things a person
                 should look at now, each with options.

Nothing here acts on anything. Callout options are navigation (open the case,
open the matching events) or the existing human "resolve" switch. Claude's
recommended option is shown as text, exactly as in the Cases view.
All log-derived and Claude-derived strings are data; the UI escapes them.
"""
from __future__ import annotations

import datetime as dt
import json
import statistics
from typing import Any, Optional

import soc_cases
import soc_geo
import soc_logs
import soc_triage

MAP_MAX_FLOWS = 40          # per direction
MAP_TOP_N = 3               # ports and IPs listed per flow
KPI_WINDOW_DAYS = 30
CALLOUT_MAX_CASES = 6

# Freshness thresholds per sensor family, in seconds. FortiGate logs every few
# seconds on a live network; Suricata alerts can be quiet, but its flow and
# stats records (dropped before the hot store) mean any eve dataset going
# silent for a day is worth a look.
SENSOR_STALE_S = {"fortigate": 15 * 60, "suricata": 24 * 3600}

SEV_ORDER = soc_triage.SEVERITIES  # info < low < medium < high < critical

# ATT&CK enterprise tactics in kill-chain order, and the techniques we expect
# from network evidence. Sub-techniques (T1110.001) map to their parent.
TACTICS = ("reconnaissance", "resource-development", "initial-access", "execution", "persistence",
           "privilege-escalation", "defense-evasion", "credential-access", "discovery",
           "lateral-movement", "collection", "command-and-control", "exfiltration", "impact")
TECHNIQUES: dict[str, tuple[str, str]] = {
    "T1595": ("reconnaissance", "Active Scanning"),
    "T1590": ("reconnaissance", "Gather Victim Network Information"),
    "T1592": ("reconnaissance", "Gather Victim Host Information"),
    "T1589": ("reconnaissance", "Gather Victim Identity Information"),
    "T1583": ("resource-development", "Acquire Infrastructure"),
    "T1584": ("resource-development", "Compromise Infrastructure"),
    "T1588": ("resource-development", "Obtain Capabilities"),
    "T1078": ("initial-access", "Valid Accounts"),
    "T1133": ("initial-access", "External Remote Services"),
    "T1190": ("initial-access", "Exploit Public-Facing Application"),
    "T1189": ("initial-access", "Drive-by Compromise"),
    "T1566": ("initial-access", "Phishing"),
    "T1199": ("initial-access", "Trusted Relationship"),
    "T1059": ("execution", "Command and Scripting Interpreter"),
    "T1203": ("execution", "Exploitation for Client Execution"),
    "T1053": ("execution", "Scheduled Task/Job"),
    "T1098": ("persistence", "Account Manipulation"),
    "T1136": ("persistence", "Create Account"),
    "T1505": ("persistence", "Server Software Component"),
    "T1543": ("persistence", "Create or Modify System Process"),
    "T1068": ("privilege-escalation", "Exploitation for Privilege Escalation"),
    "T1562": ("defense-evasion", "Impair Defenses"),
    "T1070": ("defense-evasion", "Indicator Removal"),
    "T1110": ("credential-access", "Brute Force"),
    "T1557": ("credential-access", "Adversary-in-the-Middle"),
    "T1040": ("credential-access", "Network Sniffing"),
    "T1003": ("credential-access", "OS Credential Dumping"),
    "T1046": ("discovery", "Network Service Discovery"),
    "T1018": ("discovery", "Remote System Discovery"),
    "T1210": ("lateral-movement", "Exploitation of Remote Services"),
    "T1021": ("lateral-movement", "Remote Services"),
    "T1005": ("collection", "Data from Local System"),
    "T1119": ("collection", "Automated Collection"),
    "T1560": ("collection", "Archive Collected Data"),
    "T1071": ("command-and-control", "Application Layer Protocol"),
    "T1090": ("command-and-control", "Proxy"),
    "T1095": ("command-and-control", "Non-Application Layer Protocol"),
    "T1105": ("command-and-control", "Ingress Tool Transfer"),
    "T1219": ("command-and-control", "Remote Access Software"),
    "T1571": ("command-and-control", "Non-Standard Port"),
    "T1572": ("command-and-control", "Protocol Tunneling"),
    "T1573": ("command-and-control", "Encrypted Channel"),
    "T1020": ("exfiltration", "Automated Exfiltration"),
    "T1030": ("exfiltration", "Data Transfer Size Limits"),
    "T1041": ("exfiltration", "Exfiltration Over C2 Channel"),
    "T1048": ("exfiltration", "Exfiltration Over Alternative Protocol"),
    "T1567": ("exfiltration", "Exfiltration Over Web Service"),
    "T1486": ("impact", "Data Encrypted for Impact"),
    "T1496": ("impact", "Resource Hijacking"),
    "T1498": ("impact", "Network Denial of Service"),
    "T1499": ("impact", "Endpoint Denial of Service"),
}


# ------------------------------------------------------------------ map

# The map folds 'external' (public ↔ public through the firewall) into
# outbound, matching soc_logs._REMOTE_COUNTRY.
_MAP_DIR = "CASE WHEN direction = 'inbound' THEN 'inbound' WHEN direction IN ('outbound','external') THEN 'outbound' END"


def traffic_map(range_key: str = "24h", now: Optional[dt.datetime] = None) -> dict:
    since, until = soc_logs._window(range_key, now)
    files = soc_logs._files(since, until)
    out: dict[str, Any] = {"range": range_key, "home": soc_geo.HOME, "flows": [], "unmapped": [],
                           "totals": {"inbound": 0, "outbound": 0, "countries": 0}}
    if not files:
        return out
    where = " WHERE ts_ms BETWEEN ? AND ? AND host IS DISTINCT FROM ? AND dir IS NOT NULL AND country IS NOT NULL"
    params = [int(since.timestamp() * 1000), int(until.timestamp() * 1000), soc_logs.SELFTEST_HOST]
    base = (soc_logs._base_query(files)
            + f", m AS (SELECT *, {_MAP_DIR} AS dir, {soc_logs._REMOTE_COUNTRY} AS country, "
            + f"{soc_logs._REMOTE_IP} AS remote_ip, ({soc_logs._OUTCOME}) AS outcome FROM ev)")
    head = [files, soc_logs.COLUMNS, *params]
    con = soc_logs._connect()
    try:
        groups = con.execute(
            base + " SELECT dir, country, count(*) AS n, count(*) FILTER (WHERE outcome = 'blocked'), "
            "COALESCE(sum(COALESCE(bytes_in,0) + COALESCE(bytes_out,0)), 0), count(DISTINCT remote_ip), max(ts_ms) "
            "FROM m" + where + " GROUP BY dir, country ORDER BY n DESC",
            head,
        ).fetchall()
        tops = con.execute(
            base + " SELECT dir, country, kind, v, n FROM ("
            " SELECT dir, country, kind, v, n, row_number() OVER (PARTITION BY dir, country, kind ORDER BY n DESC, v) AS r"
            " FROM ("
            "  SELECT dir, country, 'port' AS kind, CAST(dst_port AS VARCHAR) AS v, count(*) AS n FROM m" + where
            + "   AND dst_port IS NOT NULL GROUP BY dir, country, dst_port"
            "  UNION ALL"
            "  SELECT dir, country, 'ip' AS kind, remote_ip AS v, count(*) AS n FROM m" + where
            + "   AND remote_ip IS NOT NULL GROUP BY dir, country, remote_ip"
            " )) WHERE r <= ?",
            [files, soc_logs.COLUMNS, *params, *params, MAP_TOP_N],
        ).fetchall()
    finally:
        con.close()

    top_of: dict[tuple, dict[str, list]] = {}
    for d, c, kind, v, n in tops:
        top_of.setdefault((d, c), {"port": [], "ip": []})[kind].append({"v": v, "n": n})

    per_dir = {"inbound": 0, "outbound": 0}
    countries = set()
    for d, c, n, blocked, nbytes, ips, last_ms in groups:
        out["totals"][d] += n
        if not soc_geo.is_country(c):
            continue
        place = soc_geo.lookup(c)
        if not place:
            out["unmapped"].append({"dir": d, "country": c, "events": n})
            continue
        if per_dir[d] >= MAP_MAX_FLOWS:
            continue
        per_dir[d] += 1
        countries.add(place["iso2"])
        t = top_of.get((d, c), {"port": [], "ip": []})
        out["flows"].append({
            "dir": d, "country": c, **place, "events": n, "blocked": blocked, "bytes": nbytes,
            "remote_ips": ips, "last_ms": last_ms,
            "top_ports": [{"port": int(x["v"]), "n": x["n"]} for x in sorted(t["port"], key=lambda x: -x["n"])],
            "top_ips": [{"ip": x["v"], "n": x["n"]} for x in sorted(t["ip"], key=lambda x: -x["n"])],
        })
    out["totals"]["countries"] = len(countries)
    out["unmapped"] = out["unmapped"][:20]
    return out


# ------------------------------------------------------------------ sensors

def sensors(now: Optional[dt.datetime] = None) -> list[dict]:
    """Newest hot-store file per dataset, as a freshness signal (no query)."""
    now_ts = (now or dt.datetime.now(dt.timezone.utc)).timestamp()
    out = []
    for ds in soc_logs.datasets():
        newest = 0.0
        for day_dir in (soc_logs.HOT_DIR / ds).iterdir():
            if day_dir.is_dir() and soc_logs._DAY_RE.match(day_dir.name):
                for f in day_dir.iterdir():
                    if soc_logs._HOUR_RE.match(f.name):
                        newest = max(newest, f.stat().st_mtime)
        family = ds.split(".", 1)[0]
        limit = SENSOR_STALE_S.get(family)
        age = round(now_ts - newest) if newest else None
        out.append({"dataset": ds, "family": family, "age_s": age, "stale_after_s": limit,
                    "stale": bool(limit and (age is None or age > limit))})
    return out


# ------------------------------------------------------------------ cases

def _parse_iso(s: Optional[str]) -> Optional[float]:
    if not s:
        return None
    try:
        return dt.datetime.fromisoformat(s).timestamp()
    except ValueError:
        return None


def _eff_sev(case: dict) -> str:
    t = case.get("triage") or {}
    s = t.get("severity") or case.get("rule_severity") or "info"
    return s if s in SEV_ORDER else "info"


def _median(xs: list[float]) -> Optional[int]:
    return round(statistics.median(xs)) if xs else None


def _case_rows(since_iso: str) -> list[dict]:
    con = soc_cases._db()
    try:
        rows = con.execute(
            "SELECT id, rule, entity, title_en, title_ja, rule_severity, status, first_seen_ms, last_seen_ms, "
            "event_count, created_at, updated_at, resolved_at, triage, triage_status, triage_at, feedback "
            "FROM soc_cases WHERE status = 'open' OR updated_at >= ? OR created_at >= ?",
            (since_iso, since_iso),
        ).fetchall()
    finally:
        con.close()
    out = []
    for r in rows:
        c = {k: r[k] for k in r.keys()}
        try:
            c["entity"] = json.loads(c["entity"])
        except (TypeError, ValueError):
            c["entity"] = []
        try:
            c["triage"] = json.loads(c["triage"]) if c["triage"] else None
        except (TypeError, ValueError):
            c["triage"] = None
        out.append(c)
    return out


def kpis(cases: list[dict], now: dt.datetime) -> dict:
    """MTTD: first event → case created. Time to triage: created → Claude's
    assessment. MTTR: created → resolved by a person. Medians, because one
    case left open over a holiday shouldn't define the number."""
    window_start = (now - dt.timedelta(days=KPI_WINDOW_DAYS)).timestamp()
    day_ago = (now - dt.timedelta(days=1)).timestamp()
    detect, triage, resolve = [], [], []
    open_by_sev = {s: 0 for s in SEV_ORDER}
    new_24h = resolved_7d = noise = useful = 0
    for c in cases:
        created = _parse_iso(c["created_at"])
        if c["status"] == "open":
            open_by_sev[_eff_sev(c)] += 1
        if created and created >= day_ago:
            new_24h += 1
        if not created or created < window_start:
            continue
        if c["first_seen_ms"]:
            detect.append(max(0.0, created - c["first_seen_ms"] / 1000))
        if c["triage_status"] == "done":
            t = _parse_iso(c["triage_at"])
            if t:
                triage.append(max(0.0, t - created))
        if c["status"] == "resolved":
            # Cases resolved before v0.5.0 have no resolved_at; a resolved case
            # never merges again, so its last update is when it was resolved.
            r = _parse_iso(c["resolved_at"]) or _parse_iso(c["updated_at"])
            if r:
                resolve.append(max(0.0, r - created))
                if r >= (now - dt.timedelta(days=7)).timestamp():
                    resolved_7d += 1
        if c["feedback"] == "noise":
            noise += 1
        elif c["feedback"] == "useful":
            useful += 1
    return {
        "window_days": KPI_WINDOW_DAYS,
        "open": sum(open_by_sev.values()), "open_by_severity": open_by_sev,
        "new_24h": new_24h, "resolved_7d": resolved_7d,
        "mttd_s": _median(detect), "mttd_n": len(detect),
        "mttt_s": _median(triage), "mttt_n": len(triage),
        "mttr_s": _median(resolve), "mttr_n": len(resolve),
        "feedback": {"useful": useful, "noise": noise},
    }


def attack_tally(cases: list[dict]) -> dict:
    """Count ATT&CK techniques Claude named on cases in the KPI window."""
    counts: dict[str, int] = {}
    for c in cases:
        for tid in (c.get("triage") or {}).get("mitre_attack") or []:
            if isinstance(tid, str):
                counts[tid] = counts.get(tid, 0) + 1
    techniques = []
    for tid, n in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])):
        tactic, name = TECHNIQUES.get(tid.split(".")[0], ("other", tid))
        techniques.append({"id": tid, "name": name, "tactic": tactic, "count": n})
    by_tactic = {t: 0 for t in (*TACTICS, "other")}
    for t in techniques:
        by_tactic[t["tactic"]] += t["count"]
    return {"tactics": list(TACTICS), "by_tactic": by_tactic, "techniques": techniques}


def _remote_ip(entity: list) -> Optional[str]:
    for v in entity or []:
        if isinstance(v, str) and (v.count(".") == 3 or ":" in v):
            return v
    return None


def _case_callout(c: dict) -> dict:
    t = c.get("triage") or {}
    rec = next((o for o in t.get("options") or [] if o.get("recommended")), None)
    return {
        "kind": "case", "severity": _eff_sev(c), "case_id": c["id"], "rule": c["rule"],
        "title_en": c["title_en"], "title_ja": c["title_ja"],
        "headline_en": (t.get("en") or {}).get("headline"), "headline_ja": (t.get("ja") or {}).get("headline"),
        "verdict": t.get("verdict"), "confidence": t.get("confidence"),
        "injection_suspected": bool(t.get("injection_suspected")),
        "triage_status": c["triage_status"], "event_count": c["event_count"], "last_seen_ms": c["last_seen_ms"],
        "entity_ip": _remote_ip(c["entity"]),
        "recommended": ({"action_type": rec.get("action_type"), "en": rec.get("en"), "ja": rec.get("ja")}
                        if rec else None),
    }


def _sev_rank(s: str) -> int:
    return SEV_ORDER.index(s) if s in SEV_ORDER else 0


def callouts(cases: list[dict], sensor_list: list[dict], engine: dict) -> list[dict]:
    out: list[dict] = []
    # System health first: a blind sensor hides everything else.
    if not engine["hot_store"]:
        out.append({"kind": "system", "code": "hot_store_missing", "severity": "high"})
    for s in sensor_list:
        if s["stale"]:
            out.append({"kind": "sensor", "code": "sensor_stale", "dataset": s["dataset"], "family": s["family"],
                        "age_s": s["age_s"],
                        "severity": "high" if s["family"] == "fortigate" else "medium"})
    if engine["hot_store"] and not any(s["family"] == "suricata" for s in sensor_list):
        out.append({"kind": "sensor", "code": "no_ids", "severity": "low"})
    tri = engine["triage"]
    if engine["detect"] and not tri["enabled"]:
        out.append({"kind": "system", "code": "triage_off", "severity": "info"})
    errors = sum(1 for c in cases if c["status"] == "open" and c["triage_status"] == "error")
    if errors:
        out.append({"kind": "system", "code": "triage_errors", "count": errors, "severity": "low"})

    open_cases = [c for c in cases if c["status"] == "open"]
    open_cases.sort(key=lambda c: (-_sev_rank(_eff_sev(c)), -(c["last_seen_ms"] or 0)))
    for c in open_cases:
        if len([o for o in out if o["kind"] == "case"]) >= CALLOUT_MAX_CASES:
            break
        if _eff_sev(c) == "info" and (c.get("triage") or {}).get("verdict") == "likely_benign":
            continue  # nothing to do; still listed in Cases
        out.append(_case_callout(c))
    out.sort(key=lambda o: -_sev_rank(o["severity"]))
    return out


def dashboard(now: Optional[dt.datetime] = None) -> dict:
    now = now or soc_logs._utcnow()
    since_iso = (now - dt.timedelta(days=KPI_WINDOW_DAYS)).isoformat(timespec="seconds")
    cases = _case_rows(since_iso)
    hot = soc_logs.available()
    sensor_list = sensors() if hot else []  # file mtimes are wall-clock, not the (patchable) log clock
    engine = {"hot_store": hot, "detect": soc_cases.engine_enabled(), "triage": soc_triage.status(),
              "last_run": soc_cases.last_run()}
    posture = soc_logs.summary("24h", now=now) if hot else None
    return {
        "generated_ms": int(now.timestamp() * 1000),
        "engine": engine,
        "sensors": sensor_list,
        "posture": posture,
        "kpis": kpis(cases, now),
        "attack": attack_tally([c for c in cases if (_parse_iso(c["created_at"]) or 0)
                                >= (now - dt.timedelta(days=KPI_WINDOW_DAYS)).timestamp() or c["status"] == "open"]),
        "callouts": callouts(cases, sensor_list, engine),
    }


# ------------------------------------------------------------------ map drill-down

DETAIL_TOP_IPS = 15      # per direction
DETAIL_TOP_PORTS = 10
DETAIL_RECENT = 25
MAX_COUNTRY_LEN = 80


def _cases_for_country(country: str, place: Optional[dict], limit: int = 10) -> list[dict]:
    """Open cases, and cases seen in the last 7 days, whose evidence names this country."""
    names = {country.lower()}
    if place:
        names |= {place["name"].lower(), place["iso2"].lower()}
    since = (soc_logs._utcnow() - dt.timedelta(days=7)).timestamp() * 1000
    con = soc_cases._db()
    try:
        rows = con.execute(
            "SELECT id, rule, title_en, title_ja, rule_severity, status, event_count, last_seen_ms, stats, triage "
            "FROM soc_cases WHERE status = 'open' OR last_seen_ms >= ? ORDER BY last_seen_ms DESC LIMIT 500",
            (since,),
        ).fetchall()
    finally:
        con.close()
    out = []
    for r in rows:
        try:
            st = json.loads(r["stats"]) if r["stats"] else {}
            tri = json.loads(r["triage"]) if r["triage"] else {}
        except (TypeError, ValueError):
            continue
        seen = {str(x).lower() for x in [*(st.get("src_countries") or []), *(st.get("dst_countries") or [])]}
        if not seen & names:
            continue
        sev = (tri or {}).get("severity") or r["rule_severity"] or "info"
        out.append({"id": r["id"], "rule": r["rule"], "status": r["status"], "severity": sev,
                    "title_en": r["title_en"], "title_ja": r["title_ja"],
                    "headline_en": ((tri or {}).get("en") or {}).get("headline"),
                    "headline_ja": ((tri or {}).get("ja") or {}).get("headline"),
                    "event_count": r["event_count"], "last_seen_ms": r["last_seen_ms"]})
    out.sort(key=lambda c: (c["status"] != "open", -_sev_rank(c["severity"]), -(c["last_seen_ms"] or 0)))
    return out[:limit]


def country_detail(country: str, range_key: str = "24h", now: Optional[dt.datetime] = None) -> dict:
    """Everything the map knows about one remote country: totals per direction,
    a timeline, top remote IPs and ports, the latest events and related cases.
    `country` is the firewall's own spelling, exactly as /api/soc/map returns it."""
    country = (country or "").strip()[:MAX_COUNTRY_LEN]
    place = soc_geo.lookup(country)
    out: dict[str, Any] = {
        "country": country, "place": place, "range": range_key,
        "bucket_minutes": soc_logs._bucket_minutes(range_key),
        "directions": {d: {"events": 0, "blocked": 0, "bytes": 0, "remote_ips": 0, "first_ms": None, "last_ms": None}
                       for d in ("inbound", "outbound")},
        "timeline": [], "top_ips": [], "top_ports": [], "recent": [], "cases": [],
    }
    if not country or not soc_geo.is_country(country):
        return out
    out["cases"] = _cases_for_country(country, place)
    since, until = soc_logs._window(range_key, now)
    files = soc_logs._files(since, until)
    if not files:
        return out
    where = (" WHERE ts_ms BETWEEN ? AND ? AND host IS DISTINCT FROM ? AND dir IS NOT NULL AND country = ?")
    params = [int(since.timestamp() * 1000), int(until.timestamp() * 1000), soc_logs.SELFTEST_HOST, country]
    base = (soc_logs._base_query(files)
            + f", m AS (SELECT *, {_MAP_DIR} AS dir, {soc_logs._REMOTE_COUNTRY} AS country, "
            + f"{soc_logs._REMOTE_IP} AS remote_ip, ({soc_logs._OUTCOME}) AS outcome FROM ev)")
    head = [files, soc_logs.COLUMNS, *params]
    bucket_ms = out["bucket_minutes"] * 60_000
    nbytes = "COALESCE(bytes_in,0) + COALESCE(bytes_out,0)"
    con = soc_logs._connect()
    try:
        dirs = con.execute(
            base + f" SELECT dir, count(*), count(*) FILTER (WHERE outcome = 'blocked'), COALESCE(sum({nbytes}),0), "
            "count(DISTINCT remote_ip), min(ts_ms), max(ts_ms) FROM m" + where + " GROUP BY dir", head).fetchall()
        timeline = con.execute(
            base + f" SELECT (ts_ms // {bucket_ms}) * {bucket_ms} AS b, "
            "count(*) FILTER (WHERE dir = 'inbound'), count(*) FILTER (WHERE dir = 'outbound'), "
            "count(*) FILTER (WHERE outcome = 'blocked') FROM m" + where + " GROUP BY b ORDER BY b", head).fetchall()
        # Top-N per direction, so a busy inbound side can't crowd out outbound.
        ips = con.execute(
            base + " SELECT ip, dir, n, k, b, ports, last FROM ("
            " SELECT *, row_number() OVER (PARTITION BY dir ORDER BY n DESC, ip) AS r FROM ("
            f"  SELECT remote_ip AS ip, dir, count(*) AS n, count(*) FILTER (WHERE outcome = 'blocked') AS k, "
            f"  COALESCE(sum({nbytes}),0) AS b, list(DISTINCT dst_port ORDER BY dst_port)[1:6] AS ports, max(ts_ms) AS last"
            "  FROM m" + where + " AND remote_ip IS NOT NULL GROUP BY remote_ip, dir)) WHERE r <= ? ORDER BY dir, n DESC, ip",
            [*head, DETAIL_TOP_IPS]).fetchall()
        ports = con.execute(
            base + " SELECT p, dir, n, k FROM ("
            " SELECT *, row_number() OVER (PARTITION BY dir ORDER BY n DESC, p) AS r FROM ("
            "  SELECT dst_port AS p, dir, count(*) AS n, count(*) FILTER (WHERE outcome = 'blocked') AS k"
            "  FROM m" + where + " AND dst_port IS NOT NULL GROUP BY dst_port, dir)) WHERE r <= ? ORDER BY n DESC, p",
            [*head, DETAIL_TOP_PORTS]).fetchall()
        # Latest events, per direction. (One query per direction: DuckDB 1.5.6
        # fails internally on a row_number() filter over read_json here.)
        recent_rows: list = []
        rnames: list = []
        for d in ("inbound", "outbound"):
            cur = con.execute(
                base + " SELECT ts_ms, dataset, action, outcome, dir, src_ip, src_port, dst_ip, dst_port, proto, app, "
                "signature, bytes_out, bytes_in FROM m" + where + " AND dir = ? ORDER BY ts_ms DESC LIMIT ?",
                [*head, d, DETAIL_RECENT])
            rnames = [x[0] for x in cur.description]
            recent_rows += cur.fetchall()
        recent_rows.sort(key=lambda r: -(r[0] or 0))
    finally:
        con.close()
    for d, n, k, b, r, first, last in dirs:
        out["directions"][d] = {"events": n, "blocked": k, "bytes": b, "remote_ips": r, "first_ms": first, "last_ms": last}
    out["timeline"] = [{"t": b, "inbound": i, "outbound": o, "blocked": k} for b, i, o, k in timeline]
    out["top_ips"] = [{"ip": ip, "dir": d, "events": n, "blocked": k, "bytes": b,
                       "ports": [p for p in (pl or []) if p is not None], "last_ms": last}
                      for ip, d, n, k, b, pl, last in ips]
    out["top_ports"] = [{"port": p, "dir": d, "events": n, "blocked": k} for p, d, n, k in ports]
    out["recent"] = [dict(zip(rnames, r)) for r in recent_rows]
    return out
