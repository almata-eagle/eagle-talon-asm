"""Tests for SOC Phase 3: country lookup, traffic map, KPIs, ATT&CK tally and callouts.
Run:  cd backend && python -m pytest -q tests
"""
import datetime as dt
import json
import os
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("EAGLE_TALON_DB_PATH", str(Path(__file__).parent / ".test-talon.db"))
os.environ["EAGLE_TALON_SCHEDULER"] = "off"
os.environ["SOC_DETECT"] = "off"

import soc_cases  # noqa: E402
import soc_dashboard  # noqa: E402
import soc_geo  # noqa: E402
import soc_logs  # noqa: E402
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
    return hot


# ------------------------------------------------------------------- geo

@pytest.mark.parametrize("name,iso2", [
    ("United States", "US"), ("United States of America", "US"), ("Korea, Republic of", "KR"),
    ("Russian Federation", "RU"), ("Viet Nam", "VN"), ("Hong Kong", "HK"), ("Singapore", "SG"),
    ("Netherlands", "NL"), ("Iran, Islamic Republic of", "IR"), ("Taiwan", "TW"), ("japan", "JP"),
    ("Côte d'Ivoire", "CI"), ("Czechia", "CZ"), ("JP", "JP"),
])
def test_country_lookup_handles_fortigate_spellings(name, iso2):
    p = soc_geo.lookup(name)
    assert p and p["iso2"] == iso2
    assert -90 <= p["lat"] <= 90 and -180 <= p["lon"] <= 180


def test_country_lookup_rejects_non_countries():
    for n in ("Reserved", "", None, "Anonymous Proxy", "<script>alert(1)</script>", "x" * 200, 42):
        assert soc_geo.lookup(n) is None


def test_japanese_names_present():
    assert soc_geo.lookup("Japan")["name_ja"] == "日本"
    assert soc_geo.lookup("United States")["name_ja"]


def test_map_geometry_matches_table():
    world = json.loads((Path(__file__).resolve().parents[2] / "frontend" / "world-110m.json").read_text())
    assert world["projection"]["name"] == "naturalEarth1" and len(world["countries"]) > 150
    drawn = {c["iso2"] for c in world["countries"] if c["iso2"]}
    for iso2 in ("JP", "US", "CN", "NL", "DE", "BR", "AU"):
        assert iso2 in drawn


# ------------------------------------------------------------------- map

def test_traffic_map_flows_by_direction_and_country(env):
    write(env, [
        ev(M(5)), ev(M(6), dst_ip="142.250.0.1", dst_port=80), ev(M(7), dst_country="Japan", dst_ip="1.1.1.1"),
        *[ev(M(10) + dt.timedelta(seconds=i), action="deny", direction="inbound", src_ip=f"45.148.10.{i % 3}",
             src_country="Netherlands", dst_ip="203.0.113.5", dst_country="Japan", dst_port=22, subtype="local")
          for i in range(9)],
        ev(M(8), action="deny", direction="inbound", src_ip="10.0.0.9", src_country="Reserved"),
        ev(M(9), direction="inbound", src_ip="5.5.5.5", src_country="Atlantis"),
        ev(M(1), host="eagle-soc-selftest", direction="inbound", src_country="Brazil"),
        ev(NOW - dt.timedelta(days=3), dst_country="France"),
    ])
    m = soc_dashboard.traffic_map("24h", now=NOW)
    flows = {(f["dir"], f["iso2"]): f for f in m["flows"]}
    nl = flows[("inbound", "NL")]
    assert nl["events"] == 9 and nl["blocked"] == 9 and nl["remote_ips"] == 3
    assert nl["top_ports"] == [{"port": 22, "n": 9}]
    assert len(nl["top_ips"]) == 3 and nl["name_ja"]
    us = flows[("outbound", "US")]
    assert us["events"] == 2 and us["blocked"] == 0 and us["bytes"] == 600
    assert {p["port"] for p in us["top_ports"]} == {443, 80}
    assert ("outbound", "JP") in flows
    assert ("inbound", "BR") not in flows            # self-test hidden
    assert ("outbound", "FR") not in flows           # outside the range
    assert m["unmapped"] == [{"dir": "inbound", "country": "Atlantis", "events": 1}]
    assert m["totals"]["inbound"] == 11 and m["home"]["lat"]
    assert ("outbound", "FR") in {(f["dir"], f["iso2"]) for f in soc_dashboard.traffic_map("7d", now=NOW)["flows"]}


def test_traffic_map_empty_store(env):
    m = soc_dashboard.traffic_map("1h", now=NOW)
    assert m["flows"] == [] and m["totals"]["inbound"] == 0


# ------------------------------------------------------------------- cases → KPIs, ATT&CK, callouts

def _case(cid, *, created_min, first_min, status="open", sev="medium", triage=None, triage_after_s=None,
          resolved_after_s=None, rule="inbound_port_scan", entity=("45.148.10.12",)):
    created = M(created_min)
    con = soc_cases._db()
    con.execute(
        "INSERT INTO soc_cases (id, rule, entity, title_en, title_ja, rule_severity, status, first_seen_ms, "
        "last_seen_ms, event_count, created_at, updated_at, triage, triage_status, triage_at, resolved_at) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (cid, rule, json.dumps(list(entity)), f"title {cid}", f"題 {cid}", sev, status,
         int(M(first_min).timestamp() * 1000), int(M(created_min).timestamp() * 1000), 12,
         created.isoformat(timespec="seconds"), created.isoformat(timespec="seconds"),
         json.dumps(triage) if triage else None, "done" if triage else "pending",
         (created + dt.timedelta(seconds=triage_after_s)).isoformat(timespec="seconds") if triage_after_s else None,
         (created + dt.timedelta(seconds=resolved_after_s)).isoformat(timespec="seconds") if resolved_after_s else None),
    )
    con.commit()
    con.close()


def _triage(sev="high", verdict="suspicious", mitre=("T1046",), headline="<b>Scan</b> from NL"):
    txt = {"headline": headline, "what_happened": "x", "why_it_matters": "y", "unknowns": ""}
    opt = lambda i, rec: {"id": f"o{i}", "action_type": "block_ip", "recommended": rec,  # noqa: E731
                          "en": {"title": f"Block {i}", "detail": "d", "impact": "i"},
                          "ja": {"title": f"ブロック {i}", "detail": "d", "impact": "i"}}
    return {"verdict": verdict, "severity": sev, "confidence": "medium", "injection_suspected": False,
            "en": txt, "ja": txt, "options": [opt(1, False), opt(2, True)], "mitre_attack": list(mitre)}


def test_kpis_use_medians(env):
    _case("case_000000000001", created_min=60, first_min=70, triage=_triage(), triage_after_s=30,
          status="resolved", resolved_after_s=3600)
    _case("case_000000000002", created_min=50, first_min=52, triage=_triage(), triage_after_s=90,
          status="resolved", resolved_after_s=600)
    _case("case_000000000003", created_min=40, first_min=45, sev="low")
    k = soc_dashboard.kpis(soc_dashboard._case_rows((NOW - dt.timedelta(days=30)).isoformat()), NOW)
    assert k["mttd_n"] == 3 and k["mttd_s"] == 300       # median of 600, 120, 300
    assert k["mttt_s"] == 60 and k["mttt_n"] == 2
    assert k["mttr_s"] == 2100 and k["mttr_n"] == 2
    assert k["open"] == 1 and k["open_by_severity"]["low"] == 1
    assert k["new_24h"] == 3 and k["resolved_7d"] == 2


def test_resolve_sets_resolved_at_and_reopen_clears_it(env):
    _case("case_00000000000a", created_min=30, first_min=31)
    assert soc_cases.set_status("case_00000000000a", "resolved")
    assert soc_cases.get_case("case_00000000000a")["resolved_at"]
    assert soc_cases.set_status("case_00000000000a", "open")
    assert soc_cases.get_case("case_00000000000a")["resolved_at"] is None


def test_migration_adds_resolved_at_to_an_old_table(tmp_path, monkeypatch):
    db = tmp_path / "old.db"
    monkeypatch.setattr(soc_cases, "DB_PATH", db)
    import sqlite3
    con = sqlite3.connect(db)
    con.execute("CREATE TABLE soc_cases (id TEXT PRIMARY KEY, rule TEXT NOT NULL, entity TEXT NOT NULL, "
                "status TEXT NOT NULL DEFAULT 'open', last_seen_ms INTEGER, triage_status TEXT NOT NULL DEFAULT 'pending', "
                "keepme TEXT)")
    con.execute("INSERT INTO soc_cases (id, rule, entity, keepme) VALUES ('case_aaaaaaaaaaaa','r','[]','old')")
    con.commit()
    con.close()
    soc_cases.init_db()
    con = sqlite3.connect(db)
    cols = [r[1] for r in con.execute("PRAGMA table_info(soc_cases)")]
    assert "resolved_at" in cols and "keepme" in cols
    assert con.execute("SELECT keepme FROM soc_cases").fetchone()[0] == "old"
    con.close()


def test_attack_tally_maps_tactics_and_subtechniques(env):
    _case("case_000000000004", created_min=30, first_min=31, triage=_triage(mitre=("T1046", "T1595.001")))
    _case("case_000000000005", created_min=20, first_min=21, triage=_triage(mitre=("T1110.001", "T9999")),
          rule="inbound_brute_force", entity=("218.92.0.112", 22))
    a = soc_dashboard.attack_tally(soc_dashboard._case_rows((NOW - dt.timedelta(days=30)).isoformat()))
    by = {t["id"]: t for t in a["techniques"]}
    assert by["T1595.001"]["tactic"] == "reconnaissance"
    assert by["T1110.001"]["tactic"] == "credential-access" and by["T1110.001"]["name"] == "Brute Force"
    assert by["T9999"]["tactic"] == "other"
    assert a["by_tactic"]["discovery"] == 1 and a["tactics"][0] == "reconnaissance"


def test_callouts_order_and_content(env):
    write(env, [ev(M(5))])
    _case("case_000000000006", created_min=30, first_min=31, sev="low", triage=_triage(sev="critical"))
    _case("case_000000000007", created_min=20, first_min=21, sev="medium")
    _case("case_000000000008", created_min=10, first_min=11, sev="info",
          triage=_triage(sev="info", verdict="likely_benign"))
    _case("case_000000000009", created_min=10, first_min=11, status="resolved", resolved_after_s=60)
    d = soc_dashboard.dashboard(now=NOW)
    cases = [c for c in d["callouts"] if c["kind"] == "case"]
    assert [c["case_id"] for c in cases] == ["case_000000000006", "case_000000000007"]
    top = cases[0]
    assert top["severity"] == "critical"                   # Claude's severity wins over the rule's
    assert top["headline_en"] == "<b>Scan</b> from NL"     # passed through as data; the UI escapes it
    assert top["recommended"]["en"]["title"] == "Block 2"
    assert top["entity_ip"] == "45.148.10.12"
    assert d["kpis"]["open"] == 3 and d["posture"]["total"] == 1
    # No Suricata dataset in this store → a low "no IDS" callout, after the critical case.
    codes = [c.get("code") for c in d["callouts"]]
    assert "no_ids" in codes and d["callouts"][0]["case_id"] == "case_000000000006"


def test_stale_sensor_callout(env):
    write(env, [ev(M(5)), ev(M(5), source="suricata", dataset="suricata.alert", direction="internal")])
    old = time.time() - 3 * 86400
    for f in (env / "suricata.alert").rglob("*.ndjson"):
        os.utime(f, (old, old))
    s = {x["dataset"]: x for x in soc_dashboard.sensors()}
    assert s["suricata.alert"]["stale"] and not s["fortigate.traffic"]["stale"]
    d = soc_dashboard.dashboard(now=NOW)
    stale = [c for c in d["callouts"] if c.get("code") == "sensor_stale"]
    assert len(stale) == 1 and stale[0]["dataset"] == "suricata.alert" and stale[0]["age_s"] >= 3 * 86400 - 5
    assert "no_ids" not in [c.get("code") for c in d["callouts"]]


def test_dashboard_without_hot_store(tmp_path, monkeypatch):
    monkeypatch.setattr(soc_logs, "HOT_DIR", tmp_path / "missing")
    monkeypatch.setattr(soc_cases, "DB_PATH", tmp_path / "talon.db")
    soc_cases.init_db()
    d = soc_dashboard.dashboard(now=NOW)
    assert d["posture"] is None and d["callouts"][0]["code"] == "hot_store_missing"


# ------------------------------------------------------------------- API

@pytest.fixture
def client(env):
    from fastapi.testclient import TestClient
    import main
    return TestClient(main.app)


def test_api_map_and_dashboard(client, env):
    write(env, [ev(M(5))])
    r = client.get("/api/soc/map?range=1h")
    assert r.status_code == 200 and r.json()["connected"] and r.json()["flows"][0]["iso2"] == "US"
    assert client.get("/api/soc/map?range=99d").status_code == 422
    assert client.get("/api/soc/map?range=1h;DROP").status_code == 422
    r = client.get("/api/soc/dashboard")
    assert r.status_code == 200 and "kpis" in r.json() and "callouts" in r.json()


# ------------------------------------------------------------------- country drill-down

def _nl_traffic(env):
    write(env, [
        *[ev(M(10) + dt.timedelta(seconds=i), action="deny", direction="inbound", src_ip=f"45.148.10.{i % 3}",
             src_country="Netherlands", dst_ip="203.0.113.5", dst_country="Japan", dst_port=22 if i % 2 else 3389,
             subtype="local") for i in range(9)],
        ev(M(4), dst_country="Netherlands", dst_ip="93.184.216.34", dst_port=443),
        ev(M(3), action="deny", direction="inbound", src_ip="61.82.3.1", src_country="Korea, Republic of"),
    ])


def test_country_detail_totals_ips_ports_recent(env):
    _nl_traffic(env)
    d = soc_dashboard.country_detail("Netherlands", "24h", now=NOW)
    assert d["place"]["iso2"] == "NL"
    assert d["directions"]["inbound"]["events"] == 9 and d["directions"]["inbound"]["blocked"] == 9
    assert d["directions"]["inbound"]["remote_ips"] == 3
    assert d["directions"]["outbound"]["events"] == 1 and d["directions"]["outbound"]["bytes"] == 300
    top = {(x["ip"], x["dir"]): x for x in d["top_ips"]}
    assert top[("45.148.10.0", "inbound")]["events"] == 3 and set(top[("45.148.10.0", "inbound")]["ports"]) <= {22, 3389}
    assert ("93.184.216.34", "outbound") in top
    assert {(p["port"], p["dir"]) for p in d["top_ports"]} >= {(22, "inbound"), (3389, "inbound"), (443, "outbound")}
    assert len(d["recent"]) == 10 and d["recent"][0]["dst_ip"] == "93.184.216.34"   # newest first
    assert sum(b["inbound"] for b in d["timeline"]) == 9
    assert all(r["src_ip"] != "61.82.3.1" for r in d["recent"])                     # other countries excluded


def test_country_detail_lists_related_cases(env):
    _nl_traffic(env)
    con = soc_cases._db()
    for cid, countries in (("case_00000000000b", ["Netherlands"]), ("case_00000000000c", ["China"])):
        con.execute("INSERT INTO soc_cases (id, rule, entity, title_en, rule_severity, status, last_seen_ms, "
                    "event_count, stats, triage_status) VALUES (?,?,?,?,?,?,?,?,?,?)",
                    (cid, "inbound_port_scan", "[]", "t", "low", "open", int(M(5).timestamp() * 1000), 9,
                     json.dumps({"src_countries": countries}), "pending"))
    con.commit()
    con.close()
    d = soc_dashboard.country_detail("Netherlands", "24h", now=NOW)
    assert [c["id"] for c in d["cases"]] == ["case_00000000000b"]


def test_country_detail_ignores_non_countries_and_is_exact_match(env):
    _nl_traffic(env)
    assert soc_dashboard.country_detail("Reserved", "24h", now=NOW)["recent"] == []
    assert soc_dashboard.country_detail("Nether%", "24h", now=NOW)["recent"] == []      # no LIKE wildcards
    assert soc_dashboard.country_detail("' OR 1=1 --", "24h", now=NOW)["recent"] == []


def test_api_country_detail_validation(client, env):
    _nl_traffic(env)
    r = client.get("/api/soc/map/country", params={"country": "Netherlands", "range": "1h"})
    assert r.status_code == 200 and r.json()["directions"]["inbound"]["events"] == 9
    assert client.get("/api/soc/map/country", params={"country": "x" * 81}).status_code == 422
    assert client.get("/api/soc/map/country").status_code == 422
    assert client.get("/api/soc/map/country", params={"country": "Japan", "range": "2y"}).status_code == 422


def test_country_detail_top_lists_are_per_direction(env, monkeypatch):
    monkeypatch.setattr(soc_dashboard, "DETAIL_TOP_IPS", 2)
    monkeypatch.setattr(soc_dashboard, "DETAIL_RECENT", 2)
    write(env, [*[ev(M(20) + dt.timedelta(seconds=i), action="deny", direction="inbound", src_ip=f"9.9.9.{i % 4}",
                     src_country="United States", dst_ip="203.0.113.5", dst_country="Japan") for i in range(40)],
                ev(M(30), dst_ip="8.8.8.8"), ev(M(31), dst_ip="8.8.4.4"), ev(M(32), dst_ip="1.0.0.1")])
    d = soc_dashboard.country_detail("United States", "24h", now=NOW)
    by_dir = lambda xs: {x["dir"] for x in xs}  # noqa: E731
    assert by_dir(d["top_ips"]) == {"inbound", "outbound"} and len(d["top_ips"]) == 4
    assert by_dir(d["recent"]) == {"inbound", "outbound"} and len(d["recent"]) == 4
