"""
Eagle SOC — threat intelligence (v0.6).

Downloads public lists of known-bad addresses ("feeds"), keeps them in the
Talon DB, and answers "is this IP on any list?" locally. Matching is local:
our IPs are never sent to a feed provider. Keyed lookup services (AbuseIPDB,
GreyNoise) and STIX/TAXII feeds such as Blackwired come later through the same
indicator table. See ADR 0006 and docs/SOC-INTEL.md.

Feed contents are third-party data and treated like log data: only valid IP
addresses and networks are kept (parsed by `ipaddress`), plus a short tag
limited to a safe character set. Feed text never becomes an instruction.

Refreshing runs in a background thread when SOC_INTEL=on, each feed on its own
interval (Spamhaus asks for at most one download a day).
"""
from __future__ import annotations

import csv
import datetime as dt
import io
import ipaddress
import json
import os
import re
import sqlite3
import threading
import time
import urllib.request
from dataclasses import dataclass
from typing import Callable, Iterable, Optional

import soc_logs

USER_AGENT = "EagleTalon-SOC/0.6 (+https://almata.co.jp)"
MAX_FEED_BYTES = 30 * 1024 * 1024
FETCH_TIMEOUT_S = 60
_TAG_RE = re.compile(r"[^A-Za-z0-9 ._\-/]")

# How bad a category is. "malicious" categories can open a case when traffic
# was allowed; "suspicious" adds context; "info" is only a label.
CATEGORIES = {
    "botnet_c2": ("malicious", "Botnet command-and-control server", "ボットネットの指令サーバー"),
    "malware_c2": ("malicious", "Malware infrastructure", "マルウェアの基盤"),
    "hijacked_network": ("malicious", "Hijacked or criminal network", "乗っ取られた／犯罪者のネットワーク"),
    "attacker": ("suspicious", "Recently reported attacker", "最近報告された攻撃元"),
    "tor_exit": ("info", "Tor exit node", "Tor出口ノード"),
}
LEVEL_ORDER = ("info", "suspicious", "malicious")


@dataclass(frozen=True)
class Feed:
    id: str
    name: str
    url: str
    category: str
    refresh_h: float
    parse: Callable[[bytes], Iterable[tuple[str, Optional[str]]]]  # → (ip or cidr, tag)
    licence: str
    needs_key: Optional[str] = None      # env var that must be set
    method: str = "GET"


# ------------------------------------------------------------------ parsers

def _tag(s) -> Optional[str]:
    if not s:
        return None
    s = _TAG_RE.sub("", str(s))[:40].strip()
    return s or None


def _valid(value: str) -> Optional[str]:
    """Normalise an IP or network; anything else is dropped."""
    value = value.strip()
    if not value or len(value) > 50:
        return None
    try:
        if "/" in value:
            net = ipaddress.ip_network(value, strict=False)
            if net.prefixlen == net.max_prefixlen:
                return str(net.network_address)
            return str(net)
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None


def parse_lines(data: bytes) -> Iterable[tuple[str, Optional[str]]]:
    """One IP per line; '#' and ';' start comments."""
    for line in data.decode("utf-8", "replace").splitlines():
        line = line.split("#", 1)[0].split(";", 1)[0].strip()
        if line:
            v = _valid(line.split()[0])
            if v:
                yield v, None


def parse_spamhaus_json(data: bytes) -> Iterable[tuple[str, Optional[str]]]:
    """NDJSON: {"cidr": "1.10.16.0/20", "sblid": "SBL256894", ...}; last line is metadata."""
    for line in data.decode("utf-8", "replace").splitlines():
        try:
            obj = json.loads(line)
        except ValueError:
            continue
        if isinstance(obj, dict) and obj.get("cidr"):
            v = _valid(str(obj["cidr"]))
            if v:
                yield v, _tag(obj.get("sblid"))


def parse_threatfox(data: bytes) -> Iterable[tuple[str, Optional[str]]]:
    """ThreatFox API get_iocs response; keeps ip:port IOCs, tagged with the malware name."""
    try:
        obj = json.loads(data.decode("utf-8", "replace"))
    except ValueError:
        return
    for row in (obj.get("data") or []) if isinstance(obj, dict) else []:
        if not isinstance(row, dict) or row.get("ioc_type") != "ip:port":
            continue
        ip = str(row.get("ioc", "")).rsplit(":", 1)[0].strip("[]")
        v = _valid(ip)
        if v:
            yield v, _tag(row.get("malware_printable"))


FEEDS: tuple[Feed, ...] = (
    Feed("feodo", "abuse.ch Feodo Tracker", "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt",
         "botnet_c2", 1, parse_lines, "CC0 (commercial use allowed)"),
    Feed("spamhaus_drop", "Spamhaus DROP (IPv4)", "https://www.spamhaus.org/drop/drop_v4.json",
         "hijacked_network", 24, parse_spamhaus_json, "Free incl. commercial; credit The Spamhaus Project; max 1 download/day"),
    Feed("spamhaus_drop_v6", "Spamhaus DROP (IPv6)", "https://www.spamhaus.org/drop/drop_v6.json",
         "hijacked_network", 24, parse_spamhaus_json, "Free incl. commercial; credit The Spamhaus Project; max 1 download/day"),
    Feed("tor_exits", "Tor Project exit list", "https://check.torproject.org/torbulkexitlist",
         "tor_exit", 6, parse_lines, "Public list"),
    Feed("blocklist_de", "blocklist.de (all attacks, 48 h)", "https://lists.blocklist.de/lists/all.txt",
         "attacker", 6, parse_lines, "Commercial terms not stated — review before selling"),
    Feed("threatfox", "abuse.ch ThreatFox (7 days)", "https://threatfox-api.abuse.ch/api/v1/",
         "malware_c2", 6, parse_threatfox, "abuse.ch terms; free Auth-Key", needs_key="ABUSECH_AUTH_KEY", method="POST"),
)
FEEDS_BY_ID = {f.id: f for f in FEEDS}
DEFAULT_FEEDS = "feodo,spamhaus_drop,spamhaus_drop_v6,tor_exits,blocklist_de,threatfox"


def enabled() -> bool:
    return os.environ.get("SOC_INTEL", "off").lower() in ("on", "1", "true", "yes")


def active_feeds() -> list[Feed]:
    want = [x.strip() for x in os.environ.get("SOC_INTEL_FEEDS", DEFAULT_FEEDS).split(",") if x.strip()]
    out = []
    for fid in want:
        f = FEEDS_BY_ID.get(fid)
        if f and (not f.needs_key or os.environ.get(f.needs_key, "").strip()):
            out.append(f)
    return out


# ------------------------------------------------------------------ storage

def _db() -> sqlite3.Connection:
    # Imported here: soc_cases → soc_rules → soc_intel would otherwise be a cycle.
    import soc_cases
    return soc_cases._db()


def init_db() -> None:
    con = _db()
    try:
        con.execute("""
            CREATE TABLE IF NOT EXISTS ti_indicators (
                feed TEXT NOT NULL, value TEXT NOT NULL, kind TEXT NOT NULL,
                category TEXT NOT NULL, tag TEXT,
                first_seen TEXT, last_seen TEXT,
                PRIMARY KEY (feed, value)
            )""")
        con.execute("""
            CREATE TABLE IF NOT EXISTS ti_feeds (
                id TEXT PRIMARY KEY, last_attempt TEXT, last_ok TEXT,
                count INTEGER DEFAULT 0, error TEXT
            )""")
        con.commit()
    finally:
        con.close()


def _now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def store(feed: Feed, items: Iterable[tuple[str, Optional[str]]]) -> int:
    """Replace one feed's indicators. Keeps first_seen for values still listed."""
    now = _now_iso()
    rows = {}
    for value, tag in items:
        rows[value] = tag
    con = _db()
    try:
        old = dict(con.execute("SELECT value, first_seen FROM ti_indicators WHERE feed = ?", (feed.id,)).fetchall())
        con.execute("DELETE FROM ti_indicators WHERE feed = ?", (feed.id,))
        con.executemany(
            "INSERT INTO ti_indicators (feed, value, kind, category, tag, first_seen, last_seen) VALUES (?,?,?,?,?,?,?)",
            [(feed.id, v, "cidr" if "/" in v else "ip", feed.category, t, old.get(v, now), now) for v, t in rows.items()],
        )
        con.execute(
            "INSERT INTO ti_feeds (id, last_attempt, last_ok, count, error) VALUES (?,?,?,?,NULL) "
            "ON CONFLICT(id) DO UPDATE SET last_attempt=excluded.last_attempt, last_ok=excluded.last_ok, "
            "count=excluded.count, error=NULL",
            (feed.id, now, now, len(rows)),
        )
        con.commit()
    finally:
        con.close()
    return len(rows)


def _record_error(feed: Feed, err: str) -> None:
    con = _db()
    try:
        con.execute(
            "INSERT INTO ti_feeds (id, last_attempt, error) VALUES (?,?,?) "
            "ON CONFLICT(id) DO UPDATE SET last_attempt=excluded.last_attempt, error=excluded.error",
            (feed.id, _now_iso(), err[:300]),
        )
        con.commit()
    finally:
        con.close()


# ------------------------------------------------------------------ fetching

def fetch(feed: Feed) -> bytes:
    headers = {"User-Agent": USER_AGENT}
    body = None
    if feed.needs_key:
        headers["Auth-Key"] = os.environ.get(feed.needs_key, "").strip()
    if feed.id == "threatfox":
        body = json.dumps({"query": "get_iocs", "days": 7}).encode()
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(feed.url, data=body, headers=headers, method=feed.method)
    with urllib.request.urlopen(req, timeout=FETCH_TIMEOUT_S) as r:  # noqa: S310 — fixed https URLs only
        data = r.read(MAX_FEED_BYTES + 1)
    if len(data) > MAX_FEED_BYTES:
        raise ValueError("feed larger than the size limit")
    return data


MIN_GAP_S = 3600   # never fetch any feed more often than hourly, even when forced


def _due(feed: Feed, now: float, force: bool = False) -> bool:
    con = _db()
    try:
        row = con.execute("SELECT last_attempt FROM ti_feeds WHERE id = ?", (feed.id,)).fetchone()
    finally:
        con.close()
    if not row or not row[0]:
        return True
    try:
        last = dt.datetime.fromisoformat(row[0]).timestamp()
    except ValueError:
        return True
    return now - last >= (MIN_GAP_S if force else max(MIN_GAP_S, feed.refresh_h * 3600))


def refresh(force: bool = False, fetcher: Callable[[Feed], bytes] = None) -> dict:
    """Fetch every active feed that is due. With force, any feed not fetched in
    the last hour. One bad feed never stops the others; its error is stored
    and shown in the UI."""
    fetcher = fetcher or fetch
    now = time.time()
    done: dict = {}
    for feed in active_feeds():
        if not _due(feed, now, force):
            continue
        try:
            items = list(feed.parse(fetcher(feed)))
            if not items:
                raise ValueError("feed returned no usable addresses")
            done[feed.id] = store(feed, items)
        except Exception as e:  # noqa: BLE001 — record and continue
            _record_error(feed, f"{type(e).__name__}: {e}")
            done[feed.id] = f"error: {e}"[:200]
    if done:
        INDEX.reload()
    return done


_engine_started = False


def start_engine() -> bool:
    global _engine_started
    if _engine_started or not enabled():
        return False

    def loop():
        time.sleep(15)
        while True:
            try:
                refresh()
            except Exception:  # noqa: BLE001
                pass
            time.sleep(600)   # check every 10 min; each feed has its own interval

    threading.Thread(target=loop, daemon=True, name="soc-intel").start()
    _engine_started = True
    return True


# ------------------------------------------------------------------ matching

class _Index:
    """In-memory lookup: exact IPs in a dict, networks grouped by prefix length."""

    def __init__(self):
        self._lock = threading.Lock()
        self._ips: dict[str, list] = {}
        self._nets: dict[tuple[int, int], dict[int, list]] = {}   # (version, prefixlen) → {network int: hits}
        self.loaded = False
        self.count = 0

    def reload(self) -> None:
        ips: dict[str, list] = {}
        nets: dict[tuple[int, int], dict[int, list]] = {}
        n = 0
        try:
            con = _db()
            try:
                rows = con.execute("SELECT feed, value, kind, category, tag, first_seen FROM ti_indicators").fetchall()
            finally:
                con.close()
        except sqlite3.Error:
            rows = []
        for feed, value, kind, category, tag, first_seen in rows:
            hit = (feed, category, tag, first_seen, value)
            try:
                if kind == "cidr":
                    net = ipaddress.ip_network(value)
                    nets.setdefault((net.version, net.prefixlen), {}).setdefault(int(net.network_address), []).append(hit)
                else:
                    ips.setdefault(str(ipaddress.ip_address(value)), []).append(hit)
                n += 1
            except ValueError:
                continue
        with self._lock:
            self._ips, self._nets, self.count, self.loaded = ips, nets, n, True

    def lookup(self, ip: Optional[str]) -> list[dict]:
        if not ip:
            return []
        if not self.loaded:
            self.reload()
        try:
            addr = ipaddress.ip_address(str(ip).strip())
        except ValueError:
            return []
        if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_multicast or addr.is_reserved:
            return []
        with self._lock:
            hits = list(self._ips.get(str(addr), []))
            a = int(addr)
            bits = addr.max_prefixlen
            for (ver, plen), table in self._nets.items():
                if ver != addr.version:
                    continue
                key = (a >> (bits - plen)) << (bits - plen) if plen else 0
                hits.extend(table.get(key, []))
        return [_describe(*h, ip=str(addr)) for h in hits]


INDEX = _Index()


# Public pages where a person can check the listing themselves. The IP is
# always a parsed ipaddress value, never raw input.
LOOKUP_URLS = {
    "feodo": "https://feodotracker.abuse.ch/browse/host/{ip}/",
    "spamhaus_drop": "https://check.spamhaus.org/results/?query={ip}",
    "spamhaus_drop_v6": "https://check.spamhaus.org/results/?query={ip}",
    "tor_exits": "https://metrics.torproject.org/rs.html#search/{ip}",
    "blocklist_de": "https://www.blocklist.de/en/view.html?ip={ip}",
    "threatfox": "https://threatfox.abuse.ch/browse.php?search=ioc%3A{ip}",
}


def _describe(feed_id: str, category: str, tag: Optional[str], first_seen: Optional[str] = None,
              listed: Optional[str] = None, ip: Optional[str] = None) -> dict:
    level, en, ja = CATEGORIES.get(category, ("info", category, category))
    feed = FEEDS_BY_ID.get(feed_id)
    url = LOOKUP_URLS.get(feed_id)
    return {"feed": feed_id, "feed_name": feed.name if feed else feed_id, "category": category,
            "level": level, "label_en": en, "label_ja": ja, "tag": tag,
            "listed_since": first_seen, "listed_as": listed,
            "url": url.format(ip=ip) if url and ip else None}


def lookup(ip: Optional[str]) -> list[dict]:
    return INDEX.lookup(ip)


def lookup_many(ips: Iterable[Optional[str]]) -> dict[str, list[dict]]:
    out = {}
    for ip in ips:
        if ip and ip not in out:
            h = lookup(ip)
            if h:
                out[ip] = h
    return out


def worst_level(hits: list[dict]) -> Optional[str]:
    lv = [h["level"] for h in hits if h.get("level") in LEVEL_ORDER]
    return max(lv, key=LEVEL_ORDER.index) if lv else None


def status() -> dict:
    con = _db()
    try:
        rows = {r[0]: r for r in con.execute("SELECT id, last_attempt, last_ok, count, error FROM ti_feeds").fetchall()}
    except sqlite3.Error:
        rows = {}
    finally:
        con.close()
    active = {f.id for f in active_feeds()}
    feeds = []
    for f in FEEDS:
        r = rows.get(f.id)
        feeds.append({"id": f.id, "name": f.name, "category": f.category, "licence": f.licence,
                      "refresh_h": f.refresh_h, "active": f.id in active,
                      "needs_key": f.needs_key if f.needs_key and f.id not in active else None,
                      "last_attempt": r[1] if r else None, "last_ok": r[2] if r else None,
                      "count": r[3] if r else 0, "error": r[4] if r else None})
    if not INDEX.loaded:
        INDEX.reload()
    return {"enabled": enabled(), "indicators": INDEX.count, "feeds": feeds}


# ------------------------------------------------------------------ sightings

MAX_SIGHTING_IPS = 100_000


def sightings(range_key: str = "24h", now: Optional[dt.datetime] = None, limit: int = 50) -> dict:
    """Remote IPs seen in the hot store that are on a list, busiest first."""
    out = {"range": range_key, "ips": [], "listed_ips": 0, "allowed_ips": 0, "malicious_ips": 0}
    since, until = soc_logs._window(range_key, now)
    files = soc_logs._files(since, until)
    if not INDEX.loaded:
        INDEX.reload()
    if not files or not INDEX.count:
        return out
    con = soc_logs._connect()
    try:
        rows = con.execute(
            soc_logs._base_query(files)
            + f" SELECT {soc_logs._REMOTE_IP} AS ip, "
            "CASE WHEN direction = 'inbound' THEN 'inbound' ELSE 'outbound' END AS dir, "
            f"any_value({soc_logs._REMOTE_COUNTRY}) AS country, count(*) AS n, "
            f"count(*) FILTER (WHERE ({soc_logs._OUTCOME}) = 'blocked') AS blocked, "
            f"count(*) FILTER (WHERE ({soc_logs._OUTCOME}) = 'allowed') AS allowed, max(ts_ms) AS last_ms "
            "FROM ev WHERE ts_ms BETWEEN ? AND ? AND host IS DISTINCT FROM ? "
            f"AND {soc_logs._REMOTE_IP} IS NOT NULL GROUP BY ip, dir ORDER BY n DESC LIMIT ?",
            [files, soc_logs.COLUMNS, int(since.timestamp() * 1000), int(until.timestamp() * 1000),
             soc_logs.SELFTEST_HOST, MAX_SIGHTING_IPS],
        ).fetchall()
    finally:
        con.close()
    listed = []
    for ip, d, country, n, blocked, allowed, last_ms in rows:
        hits = lookup(ip)
        if hits:
            listed.append({"ip": ip, "dir": d, "country": country, "events": n, "blocked": blocked,
                           "allowed": allowed, "last_ms": last_ms, "level": worst_level(hits), "intel": hits})
    out["listed_ips"] = len({x["ip"] for x in listed})
    out["allowed_ips"] = len({x["ip"] for x in listed if x["allowed"]})
    out["malicious_ips"] = len({x["ip"] for x in listed if x["level"] == "malicious"})
    # Worst list first; within it, allowed traffic first (outbound before inbound: an
    # internal host reaching a C2 server is the most urgent), then the busiest.
    rank = lambda x: (-LEVEL_ORDER.index(x["level"]), -(x["allowed"] > 0),  # noqa: E731
                      -(x["allowed"] > 0 and x["dir"] == "outbound"), -x["events"])
    out["ips"] = sorted(listed, key=rank)[:limit]
    return out


def ip_context(ip: str, range_key: str = "7d", now: Optional[dt.datetime] = None) -> dict:
    """What our own logs say about one remote address: which local devices
    talked to it, how, how often, and what the firewall did. Used to explain
    a threat-intel hit in plain language."""
    out = {"ip": ip, "range": range_key, "intel": lookup(ip), "events": 0, "first_ms": None, "last_ms": None,
           "by": [], "local_hosts": [], "services": [], "countries": [], "bytes_out": 0, "bytes_in": 0,
           "only_icmp": False}
    since, until = soc_logs._window(range_key, now)
    files = soc_logs._files(since, until)
    if not files:
        return out
    where = (" FROM ev WHERE ts_ms BETWEEN ? AND ? AND host IS DISTINCT FROM ? AND (src_ip = ? OR dst_ip = ?)")
    params = [files, soc_logs.COLUMNS, int(since.timestamp() * 1000), int(until.timestamp() * 1000),
              soc_logs.SELFTEST_HOST, ip, ip]
    base = soc_logs._base_query(files)
    local = "CASE WHEN src_ip = ? THEN dst_ip ELSE src_ip END"
    con = soc_logs._connect()
    try:
        tot = con.execute(base + " SELECT count(*), min(ts_ms), max(ts_ms), COALESCE(sum(bytes_out),0), "
                          "COALESCE(sum(bytes_in),0), bool_and(lower(proto) IN ('icmp','icmp6','ipv6-icmp'))" + where,
                          params).fetchone()
        by = con.execute(base + f" SELECT direction, ({soc_logs._OUTCOME}) AS o, count(*)" + where
                         + " GROUP BY direction, o ORDER BY 3 DESC", params).fetchall()
        rdir = "CASE WHEN direction = 'inbound' THEN 'inbound' ELSE 'outbound' END"
        hosts = con.execute(base + f" SELECT {local} AS h, {rdir} AS d, count(*) AS n" + where
                            + " GROUP BY h, d ORDER BY n DESC LIMIT 12", [*params[:2], ip, *params[2:]]).fetchall()
        svcs = con.execute(base + f" SELECT lower(proto), dst_port, app, {rdir} AS d, count(*) AS n, "
                           f"count(*) FILTER (WHERE ({soc_logs._OUTCOME}) = 'allowed')" + where
                           + " GROUP BY 1, 2, 3, 4 ORDER BY n DESC LIMIT 10", params).fetchall()
        ccs = con.execute(base + " SELECT CASE WHEN src_ip = ? THEN src_country ELSE dst_country END AS c, count(*)"
                          + where + " GROUP BY c ORDER BY 2 DESC LIMIT 3", [*params[:2], ip, *params[2:]]).fetchall()
    finally:
        con.close()
    out.update({"events": tot[0], "first_ms": tot[1], "last_ms": tot[2], "bytes_out": tot[3], "bytes_in": tot[4],
                "only_icmp": bool(tot[5]) if tot[0] else False,
                "by": [{"dir": d, "outcome": o, "n": n} for d, o, n in by],
                "local_hosts": [{"ip": h, "dir": d, "n": n} for h, d, n in hosts if h],
                "services": [{"proto": p, "port": port, "app": a, "dir": d, "n": n, "allowed": k}
                             for p, port, a, d, n, k in svcs],
                "countries": [c for c, _ in ccs if c and c != "Reserved"]})
    return out
