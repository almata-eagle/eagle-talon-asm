"""Tests for threat intelligence (backend/soc_intel.py) and how it feeds rules,
triage, the dashboard and the API. Feeds are faked — no network.
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
os.environ["SOC_DETECT"] = "off"

import soc_cases  # noqa: E402
import soc_dashboard  # noqa: E402
import soc_intel  # noqa: E402
import soc_logs  # noqa: E402
import soc_rules  # noqa: E402
import soc_triage  # noqa: E402
from test_soc_logs import ev, write  # noqa: E402

NOW = dt.datetime(2026, 10, 8, 5, 0, 0, tzinfo=dt.timezone.utc)
M = lambda minutes: NOW - dt.timedelta(minutes=minutes)  # noqa: E731

FEODO = b"# Feodo Tracker\n# comment\n162.243.103.246\n50.16.16.211 \nnot-an-ip\n10.0.0.1\n<script>\n"
DROP = (b'{"cidr":"1.10.16.0/20","sblid":"SBL256894","rir":"apnic"}\n'
        b'{"cidr":"223.254.0.0/16","sblid":"SBL<b>212803"}\n'
        b'{"type":"metadata","timestamp":1728000000,"size":2,"records":2}\n')
DROP6 = b'{"cidr":"2a06:e480::/29","sblid":"SBL303641"}\n'
TOR = b"185.220.101.4\n185.220.101.5\n"
BLDE = b"218.92.0.112\n61.82.3.1\n45.148.10.12\n"
TFOX = json.dumps({"query_status": "ok", "data": [
    {"ioc": "91.240.118.9:443", "ioc_type": "ip:port", "malware_printable": "Cobalt <Strike>"},
    {"ioc": "evil.example", "ioc_type": "domain", "malware_printable": "x"},
]}).encode()
PAYLOADS = {"feodo": FEODO, "spamhaus_drop": DROP, "spamhaus_drop_v6": DROP6, "tor_exits": TOR,
            "blocklist_de": BLDE, "threatfox": TFOX}


def fake_fetch(feed):
    return PAYLOADS[feed.id]


@pytest.fixture
def env(tmp_path, monkeypatch):
    hot = tmp_path / "hot"
    hot.mkdir()
    monkeypatch.setattr(soc_logs, "HOT_DIR", hot)
    monkeypatch.setattr(soc_logs, "_utcnow", lambda: NOW)
    monkeypatch.setattr(soc_cases, "DB_PATH", tmp_path / "talon.db")
    monkeypatch.setenv("SOC_INTEL", "on")
    monkeypatch.delenv("SOC_INTEL_FEEDS", raising=False)
    monkeypatch.delenv("ABUSECH_AUTH_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    soc_cases.init_db()
    soc_intel.init_db()
    soc_intel.INDEX.reload()
    yield hot
    soc_intel.INDEX.loaded = False


# ------------------------------------------------------------------ parsing

def test_line_parser_keeps_only_addresses():
    got = [v for v, _ in soc_intel.parse_lines(FEODO)]
    assert got == ["162.243.103.246", "50.16.16.211", "10.0.0.1"]


def test_spamhaus_parser_skips_metadata_and_sanitizes_tags():
    got = list(soc_intel.parse_spamhaus_json(DROP))
    assert [v for v, _ in got] == ["1.10.16.0/20", "223.254.0.0/16"]
    assert got[1][1] == "SBLb212803"            # "<" and ">" stripped


def test_threatfox_parser_ip_port_only():
    assert list(soc_intel.parse_threatfox(TFOX)) == [("91.240.118.9", "Cobalt Strike")]
    assert list(soc_intel.parse_threatfox(b"<html>login</html>")) == []


def test_single_host_networks_become_ips():
    assert soc_intel._valid("8.8.8.8/32") == "8.8.8.8"
    assert soc_intel._valid("1.2.3.4/24") == "1.2.3.0/24"
    assert soc_intel._valid("999.1.1.1") is None


# ------------------------------------------------------------------ refresh + lookup

def test_refresh_stores_and_matches_ips_and_networks(env):
    res = soc_intel.refresh(fetcher=fake_fetch)
    assert res["feodo"] == 3 and res["spamhaus_drop"] == 2 and "threatfox" not in res   # no key → skipped
    assert soc_intel.lookup("162.243.103.246")[0]["category"] == "botnet_c2"
    assert soc_intel.lookup("1.10.20.7")[0]["feed"] == "spamhaus_drop"                  # inside 1.10.16.0/20
    assert soc_intel.lookup("2a06:e480::1")[0]["category"] == "hijacked_network"
    assert soc_intel.lookup("1.10.32.1") == []
    assert soc_intel.lookup("10.0.0.1") == []           # private addresses never match
    assert soc_intel.lookup("not-an-ip") == [] and soc_intel.lookup(None) == []
    st = soc_intel.status()
    assert st["indicators"] == 11 and {f["id"]: f["count"] for f in st["feeds"]}["tor_exits"] == 2
    assert {f["id"]: f["needs_key"] for f in st["feeds"]}["threatfox"] == "ABUSECH_AUTH_KEY"


def test_one_failing_feed_does_not_stop_the_others(env):
    def fetch(feed):
        if feed.id == "tor_exits":
            raise OSError("connection refused")
        return PAYLOADS[feed.id]
    res = soc_intel.refresh(fetcher=fetch)
    assert res["tor_exits"].startswith("error") and res["feodo"] == 3
    feeds = {f["id"]: f for f in soc_intel.status()["feeds"]}
    assert "connection refused" in feeds["tor_exits"]["error"] and feeds["feodo"]["error"] is None


def test_refresh_respects_intervals_even_when_forced(env):
    calls = []
    fetch = lambda f: calls.append(f.id) or PAYLOADS[f.id]  # noqa: E731
    soc_intel.refresh(fetcher=fetch)
    n = len(calls)
    soc_intel.refresh(fetcher=fetch)
    soc_intel.refresh(force=True, fetcher=fetch)        # still under the 1-hour minimum gap
    assert len(calls) == n


def test_threatfox_needs_key_and_sends_it(env, monkeypatch):
    monkeypatch.setenv("ABUSECH_AUTH_KEY", "k-123")
    assert "threatfox" in [f.id for f in soc_intel.active_feeds()]
    seen = {}

    class Resp:
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def read(self, n): return TFOX

    def urlopen(req, timeout):
        seen["key"] = req.get_header("Auth-key")
        seen["body"] = json.loads(req.data)
        return Resp()
    monkeypatch.setattr(soc_intel.urllib.request, "urlopen", urlopen)
    assert soc_intel.fetch(soc_intel.FEEDS_BY_ID["threatfox"]) == TFOX
    assert seen == {"key": "k-123", "body": {"query": "get_iocs", "days": 7}}


def test_empty_feed_is_an_error_not_a_wipe(env):
    soc_intel.refresh(fetcher=fake_fetch)
    con = soc_cases._db()
    con.execute("UPDATE ti_feeds SET last_attempt = '2000-01-01T00:00:00+00:00'")
    con.commit()
    con.close()
    res = soc_intel.refresh(fetcher=lambda f: b"<html>maintenance</html>")
    assert res["feodo"].startswith("error")
    assert soc_intel.lookup("162.243.103.246")            # previous list kept


# ------------------------------------------------------------------ detection

def test_intel_rule(env):
    soc_intel.refresh(fetcher=fake_fetch)
    write(env, [
        ev(M(3), dst_ip="162.243.103.246", dst_country="United States"),                     # out, allowed, C2
        ev(M(4), action="deny", direction="inbound", src_ip="50.16.16.211", src_country="United States"),  # blocked C2
        ev(M(5), action="accept", direction="inbound", src_ip="218.92.0.112", src_country="China",
           dst_ip="192.168.10.109", dst_port=22),                                             # in, allowed, attacker
        ev(M(6), dst_ip="185.220.101.4", dst_country="Germany"),                             # out to Tor exit
        ev(M(7), action="deny", direction="inbound", src_ip="61.82.3.1", src_country="Korea, Republic of"),
    ])
    f = {x["entity"][0]: x for x in soc_rules.detect(NOW) if x["rule"] == soc_rules.INTEL_RULE}
    assert set(f) == {"162.243.103.246", "218.92.0.112"}
    assert f["162.243.103.246"]["severity"] == "critical" and "command-and-control" in f["162.243.103.246"]["title_en"]
    assert f["218.92.0.112"]["severity"] == "medium" and "ボット" not in f["218.92.0.112"]["title_ja"]
    res = soc_cases.merge_findings(list(f.values()), now=NOW)
    assert res["created"] == 2
    case = [c for c in soc_cases.list_cases() if c["rule"] == soc_rules.INTEL_RULE and c["entity"] == ["162.243.103.246"]][0]
    full = soc_cases.get_case(case["id"])
    assert full["stats"]["intel"][0]["feed"] == "feodo" and full["stats"]["dir"] == "outbound"
    assert full["samples"] and full["samples"][0]["dst_ip"] == "162.243.103.246"


def test_triage_evidence_carries_threat_intel_as_fenced_data(env):
    soc_intel.refresh(fetcher=fake_fetch)
    case = {"id": "case_aaaaaaaaaaaa", "rule": "inbound_port_scan", "entity": ["45.148.10.12"],
            "stats": {"src_ips": ["45.148.10.12"], "dst_ips": ["203.0.113.5"]}, "samples": []}
    ev_ = soc_triage.build_evidence(case)
    assert ev_["threat_intel"]["45.148.10.12"][0]["category"] == "attacker"
    _, msgs = soc_triage.build_messages(case)
    assert "threat_intel" in msgs[0]["content"] and "<case_evidence>" in msgs[0]["content"]


# ------------------------------------------------------------------ dashboard + API

def test_sightings_and_map_counts(env):
    soc_intel.refresh(fetcher=fake_fetch)
    write(env, [ev(M(4), action="deny", direction="inbound", src_ip="50.16.16.211", src_country="United States"),
                ev(M(5), action="deny", direction="inbound", src_ip="45.148.10.12", src_country="Netherlands"),
                ev(M(6), direction="inbound", src_ip="45.148.10.99", src_country="Netherlands")])
    s = soc_intel.sightings("24h", NOW)
    assert s["listed_ips"] == 2 and s["malicious_ips"] == 1 and s["ips"][0]["ip"] == "50.16.16.211"
    m = soc_dashboard.traffic_map("24h", now=NOW)
    nl = [f for f in m["flows"] if f["iso2"] == "NL"][0]
    assert nl["intel_ips"] == 1 and m["totals"]["intel_ips"] == 2
    d = soc_dashboard.country_detail("Netherlands", "24h", now=NOW)
    top = {x["ip"]: x for x in d["top_ips"]}
    assert top["45.148.10.12"]["intel"] and top["45.148.10.99"]["intel"] == []


def test_dashboard_reports_feeds_down(env):
    soc_intel.refresh(fetcher=lambda f: (_ for _ in ()).throw(OSError("offline")))
    write(env, [ev(M(5))])
    d = soc_dashboard.dashboard(now=NOW)
    assert "intel_down" in [c.get("code") for c in d["callouts"]]
    assert d["intel"]["enabled"] and d["intel"]["indicators"] == 0


@pytest.fixture
def client(env):
    from fastapi.testclient import TestClient
    import main
    return TestClient(main.app)


def test_api_intel(client, env):
    soc_intel.refresh(fetcher=fake_fetch)
    write(env, [ev(M(4), action="deny", direction="inbound", src_ip="50.16.16.211", src_country="United States")])
    r = client.get("/api/soc/intel/lookup", params={"ip": "162.243.103.246"})
    assert r.status_code == 200 and r.json()["intel"][0]["feed"] == "feodo"
    assert client.get("/api/soc/intel/lookup", params={"ip": "1.2.3.4; rm -rf"}).status_code == 422
    assert client.get("/api/soc/intel").json()["indicators"] == 11
    evs = client.get("/api/soc/events", params={"range": "1h"}).json()["events"]
    assert evs[0]["intel"]["src"][0]["category"] == "botnet_c2"
    assert client.get("/api/soc/intel/sightings", params={"range": "1h"}).json()["listed_ips"] == 1


def test_ip_context_explains_what_we_saw(env):
    soc_intel.refresh(fetcher=fake_fetch)
    write(env, [ev(M(3 + i), src_ip="192.168.10.121", dst_ip="45.148.10.12", dst_country="Denmark", proto="icmp",
                   dst_port=None, app="PING", bytes_out=60, bytes_in=60) for i in range(4)])
    c = soc_intel.ip_context("45.148.10.12", "24h", NOW)
    assert c["events"] == 4 and c["only_icmp"] is True and c["countries"] == ["Denmark"]
    assert c["local_hosts"] == [{"ip": "192.168.10.121", "dir": "outbound", "n": 4}]
    assert c["services"][0]["dir"] == "outbound" and c["services"][0]["allowed"] == 4
    assert c["by"] == [{"dir": "outbound", "outcome": "allowed", "n": 4}]
    hit = c["intel"][0]
    assert hit["url"] == "https://www.blocklist.de/en/view.html?ip=45.148.10.12" and hit["listed_since"]


def test_api_explain_validates(client, env):
    assert client.get("/api/soc/intel/explain", params={"ip": "<script>"}).status_code == 422
    r = client.get("/api/soc/intel/explain", params={"ip": "45.148.10.12", "range": "24h"})
    assert r.status_code == 200 and r.json()["ip"] == "45.148.10.12"
