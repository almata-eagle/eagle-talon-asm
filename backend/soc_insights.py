"""
Eagle SOC — plain-language insights over a slice of traffic (v0.6).

Given a slice (one remote country, or one local device), compute a compact
traffic profile from the hot store and recognise common patterns in it:
"one device pings a different server every minute" (VPN or game latency
checks), "the internet knocks and the firewall blocks it" (background
scanning), "ordinary web traffic", "a big upload", and so on.

Everything here is deterministic and explainable: each insight is a code
plus numbers, and the UI turns it into a sentence (EN/JA). The same profile,
not raw logs, is what "Ask Claude" sends when a person wants a fuller
explanation (soc_ask.py).
"""
from __future__ import annotations

import datetime as dt
import ipaddress
import statistics
from typing import Any, Optional

import soc_intel
import soc_logs

_MAP_DIR = "CASE WHEN direction = 'inbound' THEN 'inbound' WHEN direction IN ('outbound','external') THEN 'outbound' END"
ICMP = ("icmp", "icmp6", "ipv6-icmp")
WEB_PORTS = (80, 443, 8080, 8443)
DNS_PORTS = (53, 853)
BIG_UPLOAD_BYTES = 200_000_000


def _net24(ip: str) -> Optional[str]:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if a.version == 4:
        return str(ipaddress.ip_network(f"{ip}/24", strict=False))
    return str(ipaddress.ip_network(f"{ip}/48", strict=False))


def profile(kind: str, value: str, range_key: str = "24h", now: Optional[dt.datetime] = None) -> dict:
    """kind: 'country' (remote country, firewall spelling) or 'device' (local IP)."""
    since, until = soc_logs._window(range_key, now)
    files = soc_logs._files(since, until)
    out: dict[str, Any] = {"kind": kind, "value": value, "range": range_key, "events": 0,
                           "dirs": {}, "protocols": [], "local_hosts": [], "remote_ips": 0, "remote_nets": [],
                           "countries": [], "bytes_out": 0, "bytes_in": 0, "cadence_s": None,
                           "listed_ips": 0, "first_ms": None, "last_ms": None}
    if not files or kind not in ("country", "device"):
        return out
    rc, rip = soc_logs._REMOTE_COUNTRY, soc_logs._REMOTE_IP
    base = (soc_logs._base_query(files)
            + f", m AS (SELECT *, {_MAP_DIR} AS dir, {rc} AS country, {rip} AS remote_ip, "
            + "CASE WHEN direction = 'inbound' THEN dst_ip ELSE src_ip END AS local_ip, "
            + f"({soc_logs._OUTCOME}) AS outcome FROM ev)")
    cond = "country = ?" if kind == "country" else "local_ip = ?"
    where = f" FROM m WHERE ts_ms BETWEEN ? AND ? AND host IS DISTINCT FROM ? AND dir IS NOT NULL AND {cond}"
    params = [files, soc_logs.COLUMNS, int(since.timestamp() * 1000), int(until.timestamp() * 1000),
              soc_logs.SELFTEST_HOST, value]
    con = soc_logs._connect()
    try:
        tot = con.execute(base + " SELECT count(*), COALESCE(sum(bytes_out),0), COALESCE(sum(bytes_in),0), "
                          "min(ts_ms), max(ts_ms), count(DISTINCT remote_ip)" + where, params).fetchone()
        dirs = con.execute(base + " SELECT dir, outcome, count(*)" + where + " GROUP BY 1, 2", params).fetchall()
        protos = con.execute(
            base + " SELECT dir, lower(proto), dst_port, any_value(app), count(*) AS n, "
            "count(*) FILTER (WHERE outcome = 'allowed'), COALESCE(sum(bytes_out),0)" + where
            + " GROUP BY 1, 2, 3 ORDER BY n DESC LIMIT 12", params).fetchall()
        hosts = con.execute(base + " SELECT local_ip, dir, count(*) AS n, count(DISTINCT remote_ip)" + where
                            + " GROUP BY 1, 2 ORDER BY n DESC LIMIT 8", params).fetchall()
        remotes = con.execute(base + " SELECT remote_ip, count(*)" + where
                              + " AND remote_ip IS NOT NULL GROUP BY 1 ORDER BY 2 DESC LIMIT 5000", params).fetchall()
        ccs = con.execute(base + " SELECT country, count(*) AS n, count(DISTINCT remote_ip)" + where
                          + " AND country IS NOT NULL AND country NOT IN ('Reserved','') GROUP BY 1 ORDER BY n DESC LIMIT 12",
                          params).fetchall()
        # Cadence of the busiest local device's outbound traffic in this slice.
        top = hosts[0][0] if hosts else None
        ts = []
        if top:
            ts = [r[0] for r in con.execute(base + " SELECT ts_ms" + where + " AND local_ip = ? AND dir = 'outbound' "
                                            "ORDER BY ts_ms DESC LIMIT 400", [*params, top]).fetchall()]
    finally:
        con.close()
    out.update({"events": tot[0], "bytes_out": tot[1], "bytes_in": tot[2], "first_ms": tot[3], "last_ms": tot[4],
                "remote_ips": tot[5]})
    for d, o, n in dirs:
        out["dirs"].setdefault(d, {"allowed": 0, "blocked": 0, "other": 0})[o if o in ("allowed", "blocked") else "other"] += n
    out["protocols"] = [{"dir": d, "proto": p, "port": port, "app": a, "n": n, "allowed": k, "bytes_out": b}
                        for d, p, port, a, n, k, b in protos]
    out["local_hosts"] = [{"ip": h, "dir": d, "n": n, "remotes": r} for h, d, n, r in hosts if h]
    nets: dict[str, list] = {}
    listed = 0
    for ip, n in remotes:
        net = _net24(ip)
        if net:
            e = nets.setdefault(net, [0, 0])
            e[0] += 1
            e[1] += n
        if soc_intel.lookup(ip):
            listed += 1
    out["listed_ips"] = listed
    out["remote_nets"] = [{"net": k, "ips": v[0], "events": v[1]}
                          for k, v in sorted(nets.items(), key=lambda kv: -kv[1][1])[:5]]
    out["countries"] = [{"country": c, "events": n, "ips": r} for c, n, r in ccs]
    if len(ts) >= 5:
        gaps = [(a - b) / 1000 for a, b in zip(ts, ts[1:]) if a > b]
        if gaps:
            out["cadence_s"] = round(statistics.median(gaps))
    out["insights"] = insights(out)
    return out


def insights(p: dict) -> list[dict]:
    """Patterns in a profile, worst first. Each is {code, tone, vars}."""
    ev = p["events"]
    if not ev:
        return []
    found: list[dict] = []
    out_d = p["dirs"].get("outbound", {})
    in_d = p["dirs"].get("inbound", {})
    n_out = sum(out_d.values())
    n_in = sum(in_d.values())
    protos_out = [x for x in p["protocols"] if x["dir"] == "outbound"]
    icmp_out = sum(x["n"] for x in protos_out if (x["proto"] or "") in ICMP)
    web_out = sum(x["n"] for x in protos_out if x["port"] in WEB_PORTS)
    dns_out = sum(x["n"] for x in protos_out if x["port"] in DNS_PORTS)
    hosts_out = [h for h in p["local_hosts"] if h["dir"] == "outbound"]
    top_host = hosts_out[0] if hosts_out else None
    net = p["remote_nets"][0] if p["remote_nets"] else None
    n_countries = len(p["countries"])

    if p["listed_ips"]:
        found.append({"code": "listed", "tone": "check", "vars": {"n": p["listed_ips"]}})

    if p["bytes_out"] >= BIG_UPLOAD_BYTES and n_out:
        found.append({"code": "big_upload", "tone": "check",
                      "vars": {"mb": round(p["bytes_out"] / 1e6), "local": top_host["ip"] if top_host else "?"}})

    if n_in:
        blocked = in_d.get("blocked", 0)
        allowed = in_d.get("allowed", 0)
        if allowed:
            port = next((x["port"] for x in p["protocols"] if x["dir"] == "inbound" and x["allowed"]), None)
            found.append({"code": "inbound_allowed", "tone": "check", "vars": {"n": allowed, "port": port if port is not None else "?"}})
        if blocked and blocked >= 0.8 * n_in:
            ports = [str(x["port"]) for x in p["protocols"] if x["dir"] == "inbound" and x["port"] is not None][:4]
            found.append({"code": "inbound_noise", "tone": "ok",
                          "vars": {"n": blocked, "ports": ", ".join(ports) or "—"}})

    if n_out and icmp_out >= 0.8 * n_out and top_host:
        many = top_host["remotes"] >= 5 or n_countries >= 3 or (p["kind"] == "device" and p["remote_ips"] >= 5)
        v = {"local": top_host["ip"], "n": icmp_out, "ips": p["remote_ips"], "countries": n_countries,
             "cadence": p["cadence_s"] or "?",
             "net": net["net"] if net and net["ips"] >= 3 else None, "net_ips": net["ips"] if net else 0}
        code = "ping_check" if not many else ("ping_sweep_here" if p["kind"] == "country" else "ping_sweep")
        found.append({"code": code, "tone": "info", "vars": v})
    elif n_out and web_out >= 0.6 * n_out:
        found.append({"code": "web", "tone": "ok",
                      "vars": {"n": web_out, "hosts": len(hosts_out), "mb": round(p["bytes_out"] / 1e6, 1)}})
    elif n_out and dns_out >= 0.6 * n_out:
        found.append({"code": "dns", "tone": "ok", "vars": {"n": dns_out}})

    if top_host and n_out and top_host["n"] >= 0.9 * n_out and len(hosts_out) >= 1 and p["kind"] == "country":
        found.append({"code": "one_device", "tone": "info",
                      "vars": {"local": top_host["ip"], "pct": round(top_host["n"] * 100 / n_out)}})

    order = {"urgent": 0, "check": 1, "info": 2, "ok": 3}
    found.sort(key=lambda x: order.get(x["tone"], 9))
    return found
