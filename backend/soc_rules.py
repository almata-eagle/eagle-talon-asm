"""
Eagle SOC — deterministic detection rules (Phase 2).

Rules turn raw events from the hot store into *findings*: "this entity did
this suspicious thing in this time window". They are plain SQL over the same
files the Events view reads (see soc_logs.py) — cheap, explainable, testable.
Claude never decides what is a finding; it only explains findings afterwards
(soc_triage.py). That keeps cost bounded and makes every case traceable to a
rule a human can read.

Each rule declares:
  name         stable id, stored on cases
  window_min   how far back the trigger looks
  where        SQL filter (no user input — all constant)
  entity       columns that identify "who" (grouping key)
  having       threshold that makes a group a finding
  severity     rule-level severity hint; Claude assesses its own separately
"""
from __future__ import annotations

import datetime as dt
from dataclasses import dataclass
from typing import Callable, Optional

import soc_intel
import soc_logs

# Ports where repeated inbound attempts mean someone is trying to log in or
# exploit a service, not just sweeping.
SENSITIVE_PORTS = (21, 22, 23, 25, 110, 135, 139, 143, 445, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200, 10443)
_SENSITIVE_SQL = "(" + ", ".join(str(p) for p in SENSITIVE_PORTS) + ")"
_BLOCKED_SQL = "(" + ", ".join(repr(a) for a in soc_logs.BLOCKED_ACTIONS) + ")"
_OUTCOME = soc_logs._OUTCOME

SEVERITIES = ("info", "low", "medium", "high", "critical")


@dataclass(frozen=True)
class Rule:
    name: str
    window_min: int
    where: str
    entity: tuple[str, ...]
    having: str
    severity: Callable[[dict], str]
    title: Callable[[dict], tuple[str, str]]  # (en, ja)


def _sev_by_allowed(base: str, escalated: str) -> Callable[[dict], str]:
    return lambda s: escalated if (s.get("allowed") or 0) > 0 else base


def _ids_severity(s: dict) -> str:
    levels = [str(x).lower() for x in (s.get("levels") or [])]
    if any(x in ("emergency", "alert", "critical", "1") for x in levels):
        sev = "high"
    elif any(x in ("error", "warning", "2") for x in levels):
        sev = "medium"
    else:
        sev = "low"
    # Fully blocked by the firewall/IPS → one notch lower.
    if s.get("allowed", 0) == 0 and s.get("blocked", 0) > 0 and sev != "low":
        sev = SEVERITIES[SEVERITIES.index(sev) - 1]
    return sev


def _cc(s: dict, key: str = "src_countries") -> str:
    c = [x for x in (s.get(key) or []) if x and x != "Reserved"]
    return f" ({c[0]})" if c else ""


RULES: tuple[Rule, ...] = (
    Rule(
        name="inbound_port_scan",
        window_min=15,
        where="direction = 'inbound'",
        entity=("src_ip",),
        having="count(DISTINCT dst_port) >= 10",
        severity=_sev_by_allowed("low", "medium"),
        title=lambda s: (
            f"Port scan from {s['entity'][0]}{_cc(s)} — {s['ports_n']} ports probed",
            f"{s['entity'][0]}{_cc(s)} からのポートスキャン（{s['ports_n']}ポート）",
        ),
    ),
    Rule(
        name="inbound_brute_force",
        window_min=15,
        where=f"direction = 'inbound' AND dst_port IN {_SENSITIVE_SQL}",
        entity=("src_ip", "dst_port"),
        having="count(*) >= 20",
        severity=_sev_by_allowed("low", "high"),
        title=lambda s: (
            f"Repeated attempts on port {s['entity'][1]} from {s['entity'][0]}{_cc(s)}",
            f"{s['entity'][0]}{_cc(s)} からポート{s['entity'][1]}への繰り返しの接続試行",
        ),
    ),
    Rule(
        name="ids_alert",
        window_min=15,
        where="(dataset = 'suricata.alert' OR (dataset = 'fortigate.utm' AND subtype IN ('ips', 'virus', 'anomaly')))",
        entity=("signature", "src_ip"),
        having="count(*) >= 1",
        severity=_ids_severity,
        title=lambda s: (
            f"IDS/IPS alert: {s['entity'][0] or 'unnamed signature'} from {s['entity'][1]}",
            f"IDS/IPSアラート：{s['entity'][0] or '名称なし'}（送信元 {s['entity'][1]}）",
        ),
    ),
    Rule(
        name="allowed_inbound",
        window_min=15,
        where=f"direction = 'inbound' AND dataset = 'fortigate.traffic' AND ({_OUTCOME}) = 'allowed'",
        entity=("dst_ip", "dst_port"),
        having="count(*) >= 1",
        severity=lambda s: "high" if s["entity"][1] is not None and int(s["entity"][1]) in SENSITIVE_PORTS else "medium",
        title=lambda s: (
            f"Internet traffic allowed in to {s['entity'][0]}:{s['entity'][1]} from {s['src_n']} source(s)",
            f"インターネットから {s['entity'][0]}:{s['entity'][1]} への通信が許可されています（送信元 {s['src_n']}件）",
        ),
    ),
    Rule(
        name="outbound_volume",
        window_min=60,
        where="direction = 'outbound'",
        entity=("src_ip", "dst_ip"),
        having="sum(bytes_out) >= 500000000",
        severity=lambda s: "medium",
        title=lambda s: (
            f"Large upload: {s['entity'][0]} sent {round((s.get('bytes_out') or 0) / 1e6)} MB to {s['entity'][1]}{_cc(s, 'dst_countries')}",
            f"大量送信：{s['entity'][0]} から {s['entity'][1]}{_cc(s, 'dst_countries')} へ {round((s.get('bytes_out') or 0) / 1e6)} MB",
        ),
    ),
)
RULES_BY_NAME = {r.name: r for r in RULES}

# Threat-intel matches are checked in Python against soc_intel, so they're
# handled separately too (v0.6): allowed traffic to/from a listed address.
INTEL_RULE = "intel_match"
INTEL_WINDOW_MIN = 15

# New-country detection needs a baseline, so it's handled separately below.
NEW_COUNTRY_RULE = "outbound_new_country"
NEW_COUNTRY_WINDOW_MIN = 60
BASELINE_DAYS = 7
MIN_BASELINE_HOURS = 24

# Columns shared by every rule's statistics and samples.
_STATS_SELECT = (
    "count(*) AS n, "
    f"count(*) FILTER (WHERE ({_OUTCOME}) = 'blocked') AS blocked, "
    f"count(*) FILTER (WHERE ({_OUTCOME}) = 'allowed') AS allowed, "
    "count(DISTINCT dst_port) AS ports_n, "
    "list(DISTINCT dst_port ORDER BY dst_port)[1:25] AS ports, "
    "count(DISTINCT src_ip) AS src_n, "
    "list(DISTINCT src_ip ORDER BY src_ip)[1:10] AS src_ips, "
    "list(DISTINCT dst_ip ORDER BY dst_ip)[1:10] AS dst_ips, "
    "list(DISTINCT src_country ORDER BY src_country) FILTER (WHERE src_country IS NOT NULL)[1:5] AS src_countries, "
    "list(DISTINCT dst_country ORDER BY dst_country) FILTER (WHERE dst_country IS NOT NULL)[1:5] AS dst_countries, "
    "list(DISTINCT signature ORDER BY signature) FILTER (WHERE signature IS NOT NULL)[1:5] AS signatures, "
    "list(DISTINCT action ORDER BY action) FILTER (WHERE action IS NOT NULL)[1:6] AS actions, "
    "list(DISTINCT level ORDER BY level) FILTER (WHERE level IS NOT NULL)[1:6] AS levels, "
    "list(DISTINCT dataset ORDER BY dataset)[1:5] AS datasets, "
    "sum(bytes_out) AS bytes_out, sum(bytes_in) AS bytes_in, "
    "min(ts_ms) AS first_ms, max(ts_ms) AS last_ms"
)
SAMPLE_COLUMNS = ("timestamp", "ts_ms", "dataset", "subtype", "host", "action", "src_ip", "src_port",
                  "src_country", "dst_ip", "dst_port", "dst_country", "proto", "app", "signature",
                  "level", "bytes_out", "bytes_in", "direction")
MAX_SAMPLES = 20


def _ev(files: list[str]) -> str:
    return (
        "WITH ev AS (SELECT *, epoch_ms(try_cast(timestamp AS TIMESTAMPTZ)) AS ts_ms "
        "FROM read_json(?, format = 'newline_delimited', columns = ?, ignore_errors = true))"
    )


def _base_where() -> str:
    return "ts_ms BETWEEN ? AND ? AND host IS DISTINCT FROM ?"


def _entity_where(cols: tuple[str, ...]) -> str:
    # IS NOT DISTINCT FROM so a NULL signature still matches its own case.
    return " AND ".join(f"{c} IS NOT DISTINCT FROM ?" for c in cols)


def _row_dict(cur, row) -> dict:
    return dict(zip([d[0] for d in cur.description], row))


def detect(now: Optional[dt.datetime] = None) -> list[dict]:
    """Run every rule once. Returns findings: one per entity that crossed a
    rule's threshold inside that rule's window."""
    now = now or soc_logs._utcnow()
    findings: list[dict] = []
    con = soc_logs._connect()
    try:
        for rule in RULES:
            since = now - dt.timedelta(minutes=rule.window_min)
            files = soc_logs._files(since, now)
            if not files:
                continue
            ent = ", ".join(rule.entity)
            sql = (
                _ev(files)
                + f" SELECT {ent}, {_STATS_SELECT} FROM ev WHERE {_base_where()} AND ({rule.where})"
                + f" GROUP BY {ent} HAVING {rule.having} ORDER BY n DESC LIMIT 50"
            )
            cur = con.execute(sql, [files, soc_logs.COLUMNS, _ms(since), _ms(now), soc_logs.SELFTEST_HOST])
            for row in cur.fetchall():
                d = _row_dict(cur, row)
                entity = tuple(d.pop(c) for c in rule.entity)
                findings.append(_finding(rule.name, entity, d))
        findings.extend(_detect_new_country(con, now))
        findings.extend(_detect_intel(con, now))
    finally:
        con.close()
    return findings


def _finding(rule_name: str, entity: tuple, stats: dict) -> dict:
    stats = dict(stats)
    stats["entity"] = list(entity)
    if rule_name == INTEL_RULE:
        sev, title = _intel_severity_title(entity, stats)
    elif rule_name == NEW_COUNTRY_RULE:
        sev = "low"
        title = (
            f"{entity[0]} contacted {entity[1]} for the first time in {BASELINE_DAYS} days",
            f"{entity[0]} が過去{BASELINE_DAYS}日間で初めて {entity[1]} と通信しました",
        )
    else:
        rule = RULES_BY_NAME[rule_name]
        sev = rule.severity(stats)
        title = rule.title(stats)
    return {"rule": rule_name, "entity": list(entity), "severity": sev,
            "title_en": title[0], "title_ja": title[1], "stats": stats}


def _detect_new_country(con, now: dt.datetime) -> list[dict]:
    """An internal host talking to a country it hasn't contacted in the past
    week. Only runs once the hot store holds at least a day of history —
    otherwise every country would look new. Ping-only contact doesn't count."""
    win_start = now - dt.timedelta(minutes=NEW_COUNTRY_WINDOW_MIN)
    base_start = now - dt.timedelta(days=BASELINE_DAYS)
    base_files = soc_logs._files(base_start, win_start)
    win_files = soc_logs._files(win_start, now)
    if not base_files or not win_files:
        return []
    oldest = con.execute(
        _ev(base_files) + f" SELECT min(ts_ms) FROM ev WHERE {_base_where()}",
        [base_files, soc_logs.COLUMNS, _ms(base_start), _ms(win_start), soc_logs.SELFTEST_HOST],
    ).fetchone()[0]
    if oldest is None or oldest > _ms(now - dt.timedelta(hours=MIN_BASELINE_HOURS)):
        return []
    seen = {
        (a, b) for a, b in con.execute(
            _ev(base_files) + f" SELECT DISTINCT src_ip, dst_country FROM ev WHERE {_base_where()}"
            " AND direction = 'outbound' AND dst_country IS NOT NULL",
            [base_files, soc_logs.COLUMNS, _ms(base_start), _ms(win_start), soc_logs.SELFTEST_HOST],
        ).fetchall()
    }
    cur = con.execute(
        _ev(win_files) + f" SELECT src_ip, dst_country, {_STATS_SELECT} FROM ev WHERE {_base_where()}"
        " AND direction = 'outbound' AND dst_country IS NOT NULL AND dst_country NOT IN ('Reserved', '')"
        # Pings alone don't count: VPN apps and games ping servers worldwide to
        # measure latency, and no data moves (v0.6).
        " AND lower(COALESCE(proto, '')) NOT IN ('icmp', 'icmp6', 'ipv6-icmp')"
        " GROUP BY src_ip, dst_country",
        [win_files, soc_logs.COLUMNS, _ms(win_start), _ms(now), soc_logs.SELFTEST_HOST],
    )
    out = []
    for row in cur.fetchall():
        d = _row_dict(cur, row)
        key = (d.pop("src_ip"), d.pop("dst_country"))
        if key not in seen:
            out.append(_finding(NEW_COUNTRY_RULE, key, d))
    return out


def _intel_severity_title(entity: tuple, stats: dict) -> tuple[str, tuple[str, str]]:
    hits = stats.get("intel") or []
    level = soc_intel.worst_level(hits) or "info"
    outbound = stats.get("dir") == "outbound"
    if level == "malicious":
        sev = "critical" if outbound else "high"
    elif level == "suspicious":
        sev = "medium"
    else:
        sev = "low"
    top = next((h for h in hits if h["level"] == level), hits[0] if hits else {"label_en": "listed", "label_ja": "リスト掲載"})
    tag = f" ({top['tag']})" if top.get("tag") else ""
    ip = entity[0]
    if outbound:
        return sev, (f"Allowed traffic from our network to {ip}, a known {top['label_en'].lower()}{tag}",
                     f"社内から既知の{top['label_ja']}{tag}である {ip} への通信が許可されました")
    return sev, (f"Allowed traffic in from {ip}, a known {top['label_en'].lower()}{tag}",
                 f"既知の{top['label_ja']}{tag}である {ip} からの通信が許可されました")


def _detect_intel(con, now: dt.datetime) -> list[dict]:
    """Allowed traffic to or from an address on a threat-intel list. Blocked
    traffic from listed addresses is normal internet noise and opens nothing;
    Tor exits and reported attackers only count when they came in."""
    if not soc_intel.INDEX.loaded:
        soc_intel.INDEX.reload()
    if not soc_intel.INDEX.count:
        return []
    since = now - dt.timedelta(minutes=INTEL_WINDOW_MIN)
    files = soc_logs._files(since, now)
    if not files:
        return []
    remote = soc_logs._REMOTE_IP
    cur = con.execute(
        _ev(files) + f" SELECT {remote} AS rip, CASE WHEN direction = 'inbound' THEN 'inbound' ELSE 'outbound' END AS dir, "
        f"{_STATS_SELECT} FROM ev WHERE {_base_where()} AND ({_OUTCOME}) = 'allowed' AND {remote} IS NOT NULL "
        "GROUP BY rip, dir ORDER BY n DESC LIMIT 5000",
        [files, soc_logs.COLUMNS, _ms(since), _ms(now), soc_logs.SELFTEST_HOST],
    )
    out = []
    for row in cur.fetchall():
        d = _row_dict(cur, row)
        ip, direction = d.pop("rip"), d.pop("dir")
        hits = soc_intel.lookup(ip)
        level = soc_intel.worst_level(hits)
        if not level or (level != "malicious" and direction != "inbound"):
            continue
        d["dir"] = direction
        d["intel"] = hits
        out.append(_finding(INTEL_RULE, (ip,), d))
    return out


def case_evidence(rule_name: str, entity: list, since_ms: int, until_ms: int) -> tuple[dict, list[dict]]:
    """Statistics and newest samples for one case over its whole lifetime, so
    a case that keeps going is described by all of its events, not just the
    last window."""
    if rule_name == INTEL_RULE:
        # Every event with the listed address on either side, blocked or not.
        where, cols = "(src_ip IS NOT DISTINCT FROM ? OR dst_ip IS NOT DISTINCT FROM ?)", ()
        entity_params = [entity[0], entity[0]]
    elif rule_name == NEW_COUNTRY_RULE:
        where, cols = "direction = 'outbound'", ("src_ip", "dst_country")
    else:
        rule = RULES_BY_NAME[rule_name]
        where, cols = rule.where, rule.entity
    since = dt.datetime.fromtimestamp(since_ms / 1000, dt.timezone.utc)
    until = dt.datetime.fromtimestamp(until_ms / 1000, dt.timezone.utc)
    files = soc_logs._files(since, until)
    if not files:
        return {}, []
    if rule_name == INTEL_RULE:
        params = [files, soc_logs.COLUMNS, since_ms, until_ms, soc_logs.SELFTEST_HOST, *entity_params]
        filt = f" FROM ev WHERE {_base_where()} AND {where}"
    else:
        params = [files, soc_logs.COLUMNS, since_ms, until_ms, soc_logs.SELFTEST_HOST, *entity]
        filt = f" FROM ev WHERE {_base_where()} AND ({where}) AND {_entity_where(cols)}"
    con = soc_logs._connect()
    try:
        cur = con.execute(_ev(files) + f" SELECT {_STATS_SELECT}" + filt, params)
        stats = _row_dict(cur, cur.fetchone())
        stats["entity"] = list(entity)
        if rule_name == INTEL_RULE:
            stats["intel"] = soc_intel.lookup(entity[0])
            dirs = con.execute(_ev(files) + " SELECT count(*) FILTER (WHERE direction = 'inbound'), count(*)" + filt,
                               params).fetchone()
            stats["dir"] = "inbound" if dirs[0] * 2 >= (dirs[1] or 1) else "outbound"
        cur = con.execute(
            _ev(files) + f" SELECT {', '.join(SAMPLE_COLUMNS)}, ({_OUTCOME}) AS outcome" + filt
            + f" ORDER BY ts_ms DESC LIMIT {MAX_SAMPLES}",
            params,
        )
        samples = [_row_dict(cur, r) for r in cur.fetchall()]
    finally:
        con.close()
    return stats, samples


def _ms(t: dt.datetime) -> int:
    return int(t.timestamp() * 1000)
