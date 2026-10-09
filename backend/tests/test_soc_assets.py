"""Tests for known devices (soc_assets.py) and quieting expected behaviour.
Run:  cd backend && python -m pytest -q tests
"""
import datetime as dt
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("EAGLE_TALON_DB_PATH", str(Path(__file__).parent / ".test-talon.db"))
os.environ["EAGLE_TALON_SCHEDULER"] = "off"
os.environ["SOC_DETECT"] = "off"

import soc_assets  # noqa: E402
import soc_cases  # noqa: E402
import soc_intel  # noqa: E402
import soc_logs  # noqa: E402
import soc_rules  # noqa: E402
import soc_triage  # noqa: E402
from test_soc_logs import ev, write  # noqa: E402

NOW = dt.datetime(2026, 10, 8, 5, 0, 0, tzinfo=dt.timezone.utc)
M = lambda minutes: NOW - dt.timedelta(minutes=minutes)  # noqa: E731


@pytest.fixture
def env(tmp_path, monkeypatch):
    hot = tmp_path / "hot"
    hot.mkdir()
    monkeypatch.setattr(soc_logs, "HOT_DIR", hot)
    monkeypatch.setattr(soc_logs, "_utcnow", lambda: NOW)
    monkeypatch.setattr(soc_cases, "DB_PATH", tmp_path / "talon.db")
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    soc_cases.init_db()
    soc_intel.init_db()
    soc_assets.init_db()
    soc_intel.INDEX.loaded = False
    # A day of baseline: this device only ever talked to Japan.
    write(hot, [ev(NOW - dt.timedelta(hours=30), src_ip="192.168.10.121", dst_country="Japan")])
    return hot


def test_pings_alone_never_count_as_a_new_country(env):
    write(env, [ev(M(5), src_ip="192.168.10.121", dst_ip="146.70.65.180", dst_country="Nigeria", proto="icmp",
                   dst_port=None, app="PING")])
    assert not [f for f in soc_rules.detect(NOW) if f["rule"] == soc_rules.NEW_COUNTRY_RULE]
    write(env, [ev(M(4), src_ip="192.168.10.121", dst_ip="146.70.65.181", dst_country="Nigeria", dst_port=443)])
    assert [f for f in soc_rules.detect(NOW) if f["rule"] == soc_rules.NEW_COUNTRY_RULE]


def test_quieted_device_opens_no_case_and_old_ones_resolve(env):
    write(env, [ev(M(4), src_ip="192.168.10.121", dst_ip="146.70.65.181", dst_country="Nigeria", dst_port=443)])
    findings = soc_rules.detect(NOW)
    assert soc_cases.merge_findings(findings, now=NOW)["created"] >= 1
    a = soc_assets.save("192.168.10.121", "Eddy's MacBook", "laptop", "Runs a VPN app",
                        ["outbound_new_country"], resolve_matching=True)
    assert a["resolved"] == 1 and a["name"] == "Eddy's MacBook"
    c = [x for x in soc_cases.list_cases() if x["rule"] == soc_rules.NEW_COUNTRY_RULE][0]
    assert c["status"] == "resolved" and c["feedback"] == "noise"
    res = soc_cases.merge_findings(findings, now=NOW)
    assert res["quieted"] >= 1 and res["created"] == 0


def test_attacks_from_outside_cannot_be_quieted(env):
    with pytest.raises(ValueError):
        soc_assets.save("192.168.10.121", "x", None, None, ["inbound_brute_force"])
    with pytest.raises(ValueError):
        soc_assets.save("192.168.10.121", "x", None, None, ["intel_match"])
    assert not soc_assets.is_quiet("ids_alert", ["sig", "192.168.10.121"], {"192.168.10.121": {"quiet": ["ids_alert"]}})


def test_names_are_cleaned_and_reach_claude_context(env):
    soc_assets.save(" 192.168.10.121 ", "Mac\x00Book\n" + "x" * 100, "laptop", "VPN", [])
    a = soc_assets.get("192.168.10.121")
    assert "\x00" not in a["name"] and len(a["name"]) <= soc_assets.MAX_NAME
    ctx = soc_triage._network_context()
    assert "KNOWN DEVICES" in ctx and "192.168.10.121" in ctx
    with pytest.raises(ValueError):
        soc_assets.save("not-an-ip", "x", None, None, [])
    with pytest.raises(ValueError):
        soc_assets.save("192.168.10.5", "x", "spaceship", None, [])


@pytest.fixture
def client(env):
    from fastapi.testclient import TestClient
    import main
    return TestClient(main.app)


def test_api_assets(client):
    r = client.put("/api/soc/assets/192.168.10.121", json={"name": "MacBook", "kind": "laptop",
                                                           "quiet": ["outbound_new_country"]})
    assert r.status_code == 200 and r.json()["quiet"] == ["outbound_new_country"]
    assert client.get("/api/soc/assets").json()["assets"]["192.168.10.121"]["name"] == "MacBook"
    assert client.put("/api/soc/assets/x.x", json={"name": "a"}).status_code == 422
    assert client.put("/api/soc/assets/192.168.10.9", json={"quiet": ["ids_alert"]}).status_code == 422
    assert client.delete("/api/soc/assets/192.168.10.121").status_code == 200
    assert client.delete("/api/soc/assets/192.168.10.121").status_code == 404
