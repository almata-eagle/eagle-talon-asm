"""Tests for the internal-traffic rules: scans, sweeps and repeated logins
between devices inside the network (traffic the FortiGate routes between VLANs).
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
import soc_logs  # noqa: E402
import soc_rules  # noqa: E402
from test_soc_logs import ev, write  # noqa: E402

NOW = dt.datetime(2026, 10, 12, 5, 0, 0, tzinfo=dt.timezone.utc)
M = lambda minutes: NOW - dt.timedelta(minutes=minutes)  # noqa: E731
KALI, NAS, CORE = "192.168.30.50", "192.168.10.20", "192.168.10.5"


@pytest.fixture
def env(tmp_path, monkeypatch):
    hot = tmp_path / "hot"
    hot.mkdir()
    monkeypatch.setattr(soc_logs, "HOT_DIR", hot)
    monkeypatch.setattr(soc_logs, "_utcnow", lambda: NOW)
    monkeypatch.setattr(soc_cases, "DB_PATH", tmp_path / "talon.db")
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    soc_cases.init_db()
    soc_assets.init_db()
    return hot


def inside(ts, src, dst, port, action="accept", **kw):
    return ev(ts, src_ip=src, dst_ip=dst, dst_port=port, direction="internal", src_country="Reserved",
              dst_country="Reserved", action=action, **kw)


def found(rule):
    return [f for f in soc_rules.detect(NOW) if f["rule"] == rule]


def test_internal_port_scan(env):
    write(env, [inside(M(5) + dt.timedelta(seconds=i), KALI, NAS, 1000 + i, action="deny") for i in range(20)])
    f = found("internal_port_scan")
    assert len(f) == 1 and f[0]["entity"] == [KALI, NAS] and f[0]["severity"] == "medium"
    assert "20 ports" in f[0]["title_en"] and "内部" in f[0]["title_ja"]


def test_a_few_ports_is_normal(env):
    write(env, [inside(M(5), CORE, NAS, p) for p in (22, 80, 443, 445, 5000, 5001)])
    assert not found("internal_port_scan") and not found("internal_host_sweep")


def test_host_sweep_on_remote_access_ports_is_high(env):
    write(env, [inside(M(4) + dt.timedelta(seconds=i), KALI, f"192.168.10.{100 + i}", 445, action="deny")
                for i in range(12)])
    f = found("internal_host_sweep")
    assert len(f) == 1 and f[0]["entity"] == [KALI] and f[0]["severity"] == "high"
    assert "12 other devices" in f[0]["title_en"] and "445" in f[0]["title_en"]


def test_sweep_on_web_ports_is_not_lateral_movement(env):
    write(env, [inside(M(4), CORE, f"192.168.10.{100 + i}", 443) for i in range(15)])   # e.g. a monitoring tool
    assert not found("internal_host_sweep")


def test_internal_brute_force_escalates_when_allowed(env):
    write(env, [inside(M(6) + dt.timedelta(seconds=i), KALI, NAS, 22, action="deny") for i in range(35)])
    f = found("internal_brute_force")
    assert len(f) == 1 and f[0]["entity"] == [KALI, NAS, 22] and f[0]["severity"] == "medium"
    write(env, [inside(M(1), KALI, NAS, 22, action="accept")])
    assert found("internal_brute_force")[0]["severity"] == "high"


def test_outbound_and_inbound_traffic_does_not_trip_internal_rules(env):
    write(env, [ev(M(5), dst_port=1000 + i) for i in range(30)])                                  # outbound
    write(env, [ev(M(5), direction="inbound", src_ip="45.148.10.12", dst_ip=NAS, dst_port=445,
                   action="deny") for _ in range(40)])
    assert not any(f["rule"] in soc_rules.INTERNAL_RULES for f in soc_rules.detect(NOW))


def test_marking_a_scanner_normal_quiets_only_its_own_scans(env):
    soc_assets.save(CORE, "Core", "server", "Uptime Kuma checks", ["internal_port_scan", "internal_host_sweep"])
    write(env, [inside(M(5) + dt.timedelta(seconds=i), CORE, NAS, 1000 + i) for i in range(20)])   # Core scans: quiet
    write(env, [inside(M(5) + dt.timedelta(seconds=i), KALI, CORE, 2000 + i) for i in range(20)])  # scan OF Core: reported
    res = soc_cases.merge_findings(soc_rules.detect(NOW), now=NOW)
    cases = {tuple(c["entity"]) for c in soc_cases.list_cases() if c["rule"] == "internal_port_scan"}
    assert cases == {(KALI, CORE)} and res["quieted"] == 1


def test_brute_force_inside_cannot_be_quieted(env):
    assert "internal_brute_force" not in soc_assets.QUIETABLE
    with pytest.raises(ValueError):
        soc_assets.save(KALI, "Kali", "laptop", None, ["internal_brute_force"])


def test_internal_case_merges_and_keeps_evidence(env):
    write(env, [inside(M(10) + dt.timedelta(seconds=i), KALI, f"192.168.10.{100 + i}", 3389, action="deny")
                for i in range(11)])
    soc_cases.merge_findings(soc_rules.detect(NOW), now=NOW)
    write(env, [inside(M(2), KALI, "192.168.10.200", 445, action="deny")])
    soc_cases.merge_findings(soc_rules.detect(NOW), now=NOW)
    cases = [c for c in soc_cases.list_cases() if c["rule"] == "internal_host_sweep"]
    assert len(cases) == 1
    full = soc_cases.get_case(cases[0]["id"])
    assert full["event_count"] == 12 and full["stats"]["dst_n"] == 12 and full["samples"]
