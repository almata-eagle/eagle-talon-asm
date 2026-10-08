"""Tests for the SOC hot-store search (backend/soc_logs.py) and its API routes.

Fixtures mirror what the real collector writes (schema 1, see
docs/SOC-COLLECTOR.md): hourly NDJSON under <hot>/<dataset>/<YYYY-MM-DD>/<HH>.ndjson.
Run:  cd backend && python -m pytest -q tests
"""
import datetime as dt
import json
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("EAGLE_TALON_DB_PATH", str(Path(__file__).parent / ".test-talon.db"))
os.environ["EAGLE_TALON_SCHEDULER"] = "off"

import soc_logs  # noqa: E402

NOW = dt.datetime(2026, 10, 8, 5, 0, 0, tzinfo=dt.timezone.utc)


def ev(ts: dt.datetime, **kw) -> dict:
    base = {
        "timestamp": ts.strftime("%Y-%m-%dT%H:%M:%S.%f") + "123Z",  # nanosecond precision, like FortiGate
        "source": "fortigate", "dataset": "fortigate.traffic", "subtype": "forward",
        "host": "FortiGate-60F", "action": "accept", "src_ip": "192.168.10.113", "src_port": 40000,
        "dst_ip": "142.250.196.110", "dst_port": 443, "proto": "tcp", "direction": "outbound",
        "src_country": "Reserved", "dst_country": "United States", "bytes_out": 100, "bytes_in": 200,
        "app": "HTTPS", "policy": "1", "level": "notice", "signature": None,
        "collector_from": "192.168.10.1", "raw": {"logid": "0000000013"}, "schema": 1,
    }
    base.update(kw)
    return base


def write(hot: Path, events: list[dict]) -> None:
    for e in events:
        ts = dt.datetime.strptime(e["timestamp"][:19], "%Y-%m-%dT%H:%M:%S")
        f = hot / e["dataset"] / ts.strftime("%Y-%m-%d") / ts.strftime("%H.ndjson")
        f.parent.mkdir(parents=True, exist_ok=True)
        with f.open("a") as fh:
            fh.write(json.dumps(e) + "\n")


@pytest.fixture
def hot(tmp_path, monkeypatch):
    h = tmp_path / "hot"
    h.mkdir()
    monkeypatch.setattr(soc_logs, "HOT_DIR", h)
    m = lambda minutes: NOW - dt.timedelta(minutes=minutes)  # noqa: E731
    write(h, [
        ev(m(5)),                                                     # outbound allowed
        ev(m(10), action="deny", direction="inbound", src_ip="45.148.10.12", src_country="Netherlands",
           dst_ip="203.0.113.5", dst_country="Japan", dst_port=22, subtype="local"),
        ev(m(12), action="deny", direction="inbound", src_ip="45.148.10.13", src_country="Netherlands",
           dst_ip="203.0.113.5", dst_country="Japan", dst_port=22, subtype="local"),
        ev(m(20), action="close", dst_ip="96.45.46.46", dst_port=853, app="tcp/853"),
        ev(m(30), dataset="fortigate.utm", subtype="ips", action="dropped", direction="inbound",
           src_ip="185.220.101.4", src_country="Germany", dst_ip="192.168.10.109", dst_country="Reserved",
           dst_port=8080, signature="Apache.Log4j.Error.Log.Remote.Code.Execution"),
        ev(m(40), source="suricata", dataset="suricata.alert", action="allowed", direction="internal",
           dst_ip="192.168.10.109", dst_country=None, src_country=None, policy=2013028, level=2,
           signature="ET POLICY curl User-Agent Outbound"),
        ev(m(1), host="eagle-soc-selftest", src_ip="192.168.10.250"),   # self-test: hidden by default
        ev(NOW - dt.timedelta(days=3)),                                  # outside 24h, inside 7d
    ])
    return h


def test_not_connected_when_missing(tmp_path, monkeypatch):
    monkeypatch.setattr(soc_logs, "HOT_DIR", tmp_path / "nope")
    assert soc_logs.available() is False
    assert soc_logs.status()["connected"] is False


def test_search_newest_first_and_hides_selftest(hot):
    res = soc_logs.search("24h", now=NOW)
    ts = [e["ts_ms"] for e in res["events"]]
    assert ts == sorted(ts, reverse=True)
    assert len(res["events"]) == 6
    assert all(e["host"] != "eagle-soc-selftest" for e in res["events"])
    assert res["events"][0]["raw"] == {"logid": "0000000013"}


def test_selftest_visible_when_asked(hot):
    res = soc_logs.search("24h", include_selftest=True, now=NOW)
    assert any(e["host"] == "eagle-soc-selftest" for e in res["events"])


def test_window_skips_old_files(hot):
    in_day = soc_logs.search("24h", now=NOW)
    in_week = soc_logs.search("7d", now=NOW)
    assert len(in_week["events"]) == len(in_day["events"]) + 1
    assert in_week["files_scanned"] > in_day["files_scanned"]


def test_outcome_and_direction_filters(hot):
    blocked = soc_logs.search("24h", outcome="blocked", now=NOW)["events"]
    assert {e["action"] for e in blocked} == {"deny", "dropped"}
    assert all(e["outcome"] == "blocked" for e in blocked)
    inbound = soc_logs.search("24h", direction="inbound", now=NOW)["events"]
    assert len(inbound) == 3 and all(e["direction"] == "inbound" for e in inbound)


def test_text_search_matches_country_ip_port_signature(hot):
    assert len(soc_logs.search("24h", q="netherlands", now=NOW)["events"]) == 2
    assert len(soc_logs.search("24h", q="45.148.10.12", now=NOW)["events"]) == 1
    assert len(soc_logs.search("24h", q="853", now=NOW)["events"]) == 1
    assert len(soc_logs.search("24h", q="log4j", now=NOW)["events"]) == 1


def test_injection_shaped_query_is_literal(hot):
    for q in ["' OR 1=1 --", "%'; DROP TABLE x; --", "*", "\\"]:
        assert soc_logs.search("24h", q=q, now=NOW)["events"] == []


def test_dataset_filter_and_bad_dataset_ignored(hot):
    assert len(soc_logs.search("24h", dataset="fortigate.utm", now=NOW)["events"]) == 1
    # A path-shaped dataset is not a dataset: it's ignored, never used as a path.
    assert len(soc_logs.search("24h", dataset="../../etc", now=NOW)["events"]) == 6


def test_limit_and_truncated(hot):
    res = soc_logs.search("24h", limit=2, now=NOW)
    assert len(res["events"]) == 2 and res["truncated"] is True


def test_malformed_lines_are_skipped(hot):
    f = next((hot / "fortigate.traffic").rglob("04.ndjson"))
    with f.open("a") as fh:
        fh.write("this is not json\n")
    assert len(soc_logs.search("24h", now=NOW)["events"]) == 6


def test_summary_numbers(hot):
    s = soc_logs.summary("24h", now=NOW)
    assert s["total"] == 6
    assert s["blocked"] == 3
    assert s["inbound"] == 3
    assert s["outbound"] == 2
    # remote IPs: 2 Netherlands + 1 Germany (inbound) + 2 outbound destinations
    assert s["remote_ips"] == 5
    countries = {c["country"]: c["count"] for c in s["top_countries"]}
    assert countries["Netherlands"] == 2 and "Reserved" not in countries
    assert {p["port"] for p in s["top_ports_inbound"]} == {22, 8080}
    assert sum(b["total"] for b in s["timeline"]) == 6
    assert s["newest_ms"] is not None


def test_status_connected(hot):
    st = soc_logs.status()
    assert st["connected"] is True
    assert "fortigate.traffic" in st["datasets"] and "suricata.alert" in st["datasets"]


# ---- API layer: input validation happens before soc_logs is touched ----

@pytest.fixture
def client(hot, monkeypatch):
    from fastapi.testclient import TestClient
    import main
    monkeypatch.setattr(soc_logs, "_utcnow", lambda: NOW)
    return TestClient(main.app)


def test_api_events_ok(client):
    r = client.get("/api/soc/events", params={"range": "24h", "outcome": "blocked"})
    assert r.status_code == 200
    body = r.json()
    assert body["connected"] is True and len(body["events"]) == 3


@pytest.mark.parametrize("params", [
    {"range": "1y"},
    {"outcome": "maybe"},
    {"direction": "sideways"},
    {"dataset": "../../etc/passwd"},
    {"limit": 100000},
    {"q": "x" * 500},
])
def test_api_rejects_bad_input(client, params):
    assert client.get("/api/soc/events", params=params).status_code == 422


def test_api_not_connected(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient
    import main
    monkeypatch.setattr(soc_logs, "HOT_DIR", tmp_path / "missing")
    c = TestClient(main.app)
    assert c.get("/api/soc/events").json()["connected"] is False
    assert c.get("/api/soc/summary").json() == {"connected": False}
