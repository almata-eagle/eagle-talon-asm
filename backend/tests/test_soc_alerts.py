"""Tests for SOC alerts (soc_alerts.py): when an alert goes out, what it says,
reminders, quiet hours, acknowledgement and the silent-collector alert.
No network: the channel senders are replaced by recorders.
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

import soc_alerts  # noqa: E402
import soc_cases  # noqa: E402
import soc_logs  # noqa: E402

T0 = dt.datetime(2026, 10, 9, 3, 0, 0, tzinfo=dt.timezone.utc)   # 12:00 in Tokyo


def triage(sev="high", headline="Brute force on SSH from 45.148.10.12 succeeded once", injection=False):
    opt = lambda t, rec: {"id": "x", "action_type": "block_ip", "recommended": rec,  # noqa: E731
                          "en": {"title": t, "detail": "", "impact": ""}, "ja": {"title": "遮断", "detail": "", "impact": ""}}
    return {"verdict": "likely_malicious", "severity": sev, "confidence": "high", "injection_suspected": injection,
            "en": {"headline": headline, "what_happened": "400 failed logins then one success.", "why_it_matters": "",
                   "unknowns": ""},
            "ja": {"headline": "SSH への総当たり攻撃", "what_happened": "失敗400回の後に成功1回。", "why_it_matters": "",
                   "unknowns": ""},
            "options": [opt("Block 45.148.10.12 for 24 hours", True), opt("Watch", False)], "mitre_attack": ["T1110"]}


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setattr(soc_cases, "DB_PATH", tmp_path / "talon.db")
    soc_cases.init_db()
    soc_alerts.init_db()
    for k in list(os.environ):
        if k.startswith(("SOC_ALERT", "SOC_NTFY", "SOC_SLACK")):
            monkeypatch.delenv(k)
    monkeypatch.setenv("SOC_ALERTS", "on")
    monkeypatch.setenv("SOC_NTFY_TOPIC", "talon-test-topic")
    monkeypatch.setenv("SOC_SLACK_WEBHOOK", "https://hooks.slack.invalid/x")
    monkeypatch.setenv("SOC_ALERT_BASE_URL", "http://core:8098")
    monkeypatch.setenv("SOC_ALERT_SECRET", "s3cret-for-tests")
    monkeypatch.setenv("EAGLE_TALON_ENV", "staging")
    monkeypatch.setattr(soc_logs, "status", lambda: {"connected": False})
    sent = []
    monkeypatch.setitem(soc_alerts.SENDERS, "ntfy", lambda m: sent.append(("ntfy", m)) or {"ok": True, "status": 200})
    monkeypatch.setitem(soc_alerts.SENDERS, "slack", lambda m: sent.append(("slack", m)) or {"ok": True, "status": 200})
    return sent


def add_case(sev="high", tri=None, status="done", created=T0, cid="case_aaaaaaaaaaaa"):
    con = soc_cases._db()
    con.execute("INSERT INTO soc_cases (id, rule, entity, title_en, title_ja, rule_severity, status, first_seen_ms, "
                "last_seen_ms, event_count, created_at, updated_at, triage, triage_status) VALUES "
                "(?, 'ssh_brute_force', '[\"45.148.10.12\"]', 'SSH brute force from 45.148.10.12', 'SSH総当たり', ?, 'open', "
                "0, 0, 401, ?, ?, ?, ?)",
                (cid, sev, created.isoformat(), created.isoformat(), json.dumps(tri) if tri else None, status))
    con.commit()
    con.close()
    return cid


def at(minutes):
    return T0 + dt.timedelta(minutes=minutes)


# ------------------------------------------------------------------ when

def test_high_case_alerts_once_on_every_channel(env):
    add_case(tri=triage())
    assert soc_alerts.process(at(1)) == {"alerts_sent": 1}
    assert sorted(c for c, _ in env) == ["ntfy", "slack"]
    assert soc_alerts.process(at(2)) == {"alerts_sent": 0}          # no repeat inside the reminder window


def test_below_threshold_and_off_send_nothing(env, monkeypatch):
    add_case(sev="medium", tri=triage(sev="medium"))
    assert soc_alerts.process(at(1)) == {"alerts_sent": 0}
    monkeypatch.setenv("SOC_ALERT_MIN_SEVERITY", "medium")
    assert soc_alerts.process(at(1)) == {"alerts_sent": 1}
    monkeypatch.setenv("SOC_ALERTS", "off")
    assert soc_alerts.process(at(90)) == {"alerts": "off"}


def test_claude_downgrade_wins_over_rule_severity(env):
    add_case(sev="high", tri=triage(sev="low"))
    assert soc_alerts.process(at(1)) == {"alerts_sent": 0}


def test_waits_for_explanation_then_sends_without_it(env):
    add_case(sev="critical", tri=None, status="pending")
    assert soc_alerts.process(at(2)) == {"alerts_sent": 0}          # give Claude a chance
    assert soc_alerts.process(at(11)) == {"alerts_sent": 1}         # but not forever
    assert "No AI explanation yet." in env[0][1]["body"]


def test_reminders_until_acknowledged_then_stop(env):
    cid = add_case(tri=triage())
    soc_alerts.process(at(0))
    assert soc_alerts.process(at(31)) == {"alerts_sent": 1}
    assert env[-1][1]["title"].startswith("[STAGING] HIGH · Still open:")
    soc_alerts.ack(cid, "eddy")
    assert soc_alerts.process(at(90)) == {"alerts_sent": 0}


def test_reminders_are_capped(env, monkeypatch):
    monkeypatch.setenv("SOC_ALERT_MAX_SENDS", "2")
    add_case(tri=triage())
    soc_alerts.process(at(0))
    soc_alerts.process(at(31))
    assert soc_alerts.process(at(62)) == {"alerts_sent": 0}


def test_escalation_alerts_again_even_after_cap(env, monkeypatch):
    monkeypatch.setenv("SOC_ALERT_MAX_SENDS", "1")
    cid = add_case(tri=triage(sev="high"))
    soc_alerts.process(at(0))
    con = soc_cases._db()
    con.execute("UPDATE soc_cases SET triage = ? WHERE id = ?", (json.dumps(triage(sev="critical")), cid))
    con.commit()
    con.close()
    assert soc_alerts.process(at(5)) == {"alerts_sent": 1}
    assert "Severity raised" in env[-1][1]["title"]


def test_resolved_cases_never_alert(env):
    cid = add_case(tri=triage())
    soc_cases.set_status(cid, "resolved")
    assert soc_alerts.process(at(1)) == {"alerts_sent": 0}


def test_ack_before_any_alert_prevents_it(env):
    cid = add_case(tri=triage())
    soc_alerts.ack(cid, "talon-ui")
    assert soc_alerts.process(at(1)) == {"alerts_sent": 0}


def test_failed_channel_is_retried_next_run(env, monkeypatch):
    add_case(tri=triage())
    monkeypatch.setitem(soc_alerts.SENDERS, "ntfy", lambda m: {"ok": False, "status": 500})
    monkeypatch.setitem(soc_alerts.SENDERS, "slack", lambda m: (_ for _ in ()).throw(ConnectionError()))
    assert soc_alerts.process(at(1)) == {"alerts_sent": 0}
    log = soc_alerts.recent()
    assert log[0]["results"]["slack"] == {"ok": False, "error": "ConnectionError"}
    monkeypatch.setitem(soc_alerts.SENDERS, "ntfy", lambda m: {"ok": True, "status": 200})
    assert soc_alerts.process(at(2)) == {"alerts_sent": 1}


# ------------------------------------------------------------------ quiet hours

def test_quiet_hours_hold_high_but_not_critical(env, monkeypatch):
    monkeypatch.setenv("SOC_ALERT_QUIET", "23:00-07:00")
    night = dt.datetime(2026, 10, 9, 15, 30, tzinfo=dt.timezone.utc)          # 00:30 in Tokyo
    assert soc_alerts.in_quiet_hours(night) and not soc_alerts.in_quiet_hours(T0)
    add_case(tri=triage(sev="high"))
    assert soc_alerts.process(night) == {"alerts_sent": 0}
    add_case(tri=triage(sev="critical"), cid="case_bbbbbbbbbbbb")
    assert soc_alerts.process(night) == {"alerts_sent": 1}
    morning = dt.datetime(2026, 10, 9, 22, 5, tzinfo=dt.timezone.utc)          # 07:05 in Tokyo
    assert soc_alerts.process(morning) == {"alerts_sent": 2}                  # held one + reminder for the critical


def test_quiet_hours_parsing():
    noon = T0
    assert soc_alerts.in_quiet_hours(noon, "11:00-13:00", "Asia/Tokyo")
    assert not soc_alerts.in_quiet_hours(noon, "13:00-11:00", "Asia/Tokyo")
    assert not soc_alerts.in_quiet_hours(noon, "nonsense", "Asia/Tokyo")
    assert not soc_alerts.in_quiet_hours(noon, "11:00-13:00", "Not/AZone")


# ------------------------------------------------------------------ what it says

def test_message_content_and_links(env):
    cid = add_case(tri=triage())
    m = soc_alerts.build_message(soc_cases.get_case(cid), "new")
    assert m["title"] == "[STAGING] HIGH · Brute force on SSH from 45.148.10.12 succeeded once"
    assert "400 failed logins" in m["body"] and "Suggested: Block 45.148.10.12 for 24 hours" in m["body"]
    assert m["url"] == f"http://core:8098/#case={cid}"


def test_minimal_detail_sends_no_case_text(env, monkeypatch):
    monkeypatch.setenv("SOC_ALERT_DETAIL", "minimal")
    cid = add_case(tri=triage())
    m = soc_alerts.build_message(soc_cases.get_case(cid), "new")
    assert "400" not in m["body"] and "Suggested" not in m["body"]


def test_japanese_and_injection_warning(env, monkeypatch):
    monkeypatch.setenv("SOC_ALERT_LANG", "ja")
    cid = add_case(tri=triage(injection=True))
    m = soc_alerts.build_message(soc_cases.get_case(cid), "new")
    assert "SSH への総当たり攻撃" in m["title"] and "失敗400回" in m["body"]
    assert "text aimed at the AI" in m["body"]


def test_hostile_text_is_plain_and_capped(env):
    evil = "<!channel> <https://evil.example|click> \x1b[31m" + "A" * 900
    cid = add_case(tri=triage(headline=evil))
    m = soc_alerts.build_message(soc_cases.get_case(cid), "new")
    assert "\x1b" not in m["title"] and len(m["title"]) <= 200
    esc = soc_alerts.slack_escape(m["title"])
    assert "<!channel>" not in esc and "&lt;!channel&gt;" in esc and "<https" not in esc


def test_slack_payload_escapes(env, monkeypatch):
    captured = {}

    class R:
        ok, status_code = True, 200
    monkeypatch.setattr(soc_alerts.requests, "post", lambda url, **kw: captured.update(kw) or R())
    soc_alerts._post_slack({"title": "<!here> x", "body": "a & <b>", "url": "http://core:8098/#case=case_aaaaaaaaaaaa"})
    text = captured["json"]["text"]
    assert text.startswith("*&lt;!here&gt; x*") and "a &amp; &lt;b&gt;" in text and captured["json"]["unfurl_links"] is False


def test_ntfy_payload_has_view_and_ack_actions(env, monkeypatch):
    captured = {}

    class R:
        ok, status_code = True, 200
    monkeypatch.setattr(soc_alerts.requests, "post", lambda url, **kw: captured.update(url=url, **kw) or R())
    cid = add_case(tri=triage())
    soc_alerts._post_ntfy(soc_alerts.build_message(soc_cases.get_case(cid), "new"))
    body = json.loads(captured["data"].decode())
    assert captured["url"] == "https://ntfy.sh" and body["topic"] == "talon-test-topic" and body["priority"] == 4
    view, ack = body["actions"]
    assert view["action"] == "view" and ack["action"] == "http" and ack["method"] == "POST"
    assert ack["url"] == f"http://core:8098/api/soc/alerts/ack/{cid}?token={soc_alerts.ack_token(cid)}"


# ------------------------------------------------------------------ ack tokens + API

def test_ack_token():
    os.environ["SOC_ALERT_SECRET"] = "k"
    try:
        tok = soc_alerts.ack_token("case_aaaaaaaaaaaa")
        assert len(tok) == 32 and soc_alerts.check_token("case_aaaaaaaaaaaa", tok)
        assert not soc_alerts.check_token("case_bbbbbbbbbbbb", tok) and not soc_alerts.check_token("case_aaaaaaaaaaaa", "0" * 32)
    finally:
        del os.environ["SOC_ALERT_SECRET"]
    assert soc_alerts.ack_token("case_aaaaaaaaaaaa") is None and not soc_alerts.check_token("case_aaaaaaaaaaaa", "")


def test_api_ack_and_status(env):
    import main
    from fastapi.testclient import TestClient
    cl = TestClient(main.app)
    cid = add_case(tri=triage())
    tok = soc_alerts.ack_token(cid)
    assert cl.post(f"/api/soc/alerts/ack/{cid}?token={'0' * 32}").status_code == 403
    assert cl.post(f"/api/soc/alerts/ack/{cid}?token=nothex").status_code == 422
    assert cl.post(f"/api/soc/alerts/ack/{cid}?token={tok}").json() == {"acked": True}
    assert cl.get("/api/soc/cases?status=open").json()["cases"][0]["alert"]["acked_by"] == "phone"
    st = cl.get("/api/soc/alerts").json()
    assert st["enabled"] and st["channels"] == {"ntfy": True, "slack": True} and st["ack_links"]
    assert cl.post("/api/soc/alerts/test").json()["results"]["ntfy"]["ok"]
    assert cl.post("/api/soc/cases/case_cccccccccccc/ack").status_code == 404


# ------------------------------------------------------------------ silent collector

def test_silent_collector_alerts_once_and_recovers(env, monkeypatch):
    monkeypatch.setattr(soc_logs, "status", lambda: {"connected": True, "newest_file_age_s": 3600})
    assert soc_alerts.process(at(0)) == {"alerts_sent": 1}
    assert "No logs arriving" in env[-1][1]["title"]
    assert soc_alerts.process(at(5)) == {"alerts_sent": 0}
    monkeypatch.setattr(soc_logs, "status", lambda: {"connected": True, "newest_file_age_s": 40})
    assert soc_alerts.process(at(10)) == {"alerts_sent": 1}
    assert "arriving again" in env[-1][1]["title"]


def test_alert_errors_never_break_detection(env, monkeypatch):
    monkeypatch.setattr(soc_cases, "list_cases", lambda **k: (_ for _ in ()).throw(RuntimeError("db gone")))
    assert soc_alerts.process(at(1)) == {"alerts_error": "RuntimeError"}
