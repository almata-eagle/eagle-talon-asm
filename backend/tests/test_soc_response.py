"""Tests for SOC response (soc_response.py): approved, time-limited FortiGate blocks.
The FortiGate is a fake that records calls; no network.
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

import soc_assets  # noqa: E402
import soc_cases  # noqa: E402
import soc_intel  # noqa: E402
import soc_response  # noqa: E402

CODE = "orange-kite-42"
ATTACKER = "45.148.10.12"


class FakeFGT:
    def __init__(self, fail_on=None):
        self.calls, self.addresses, self.members, self.fail_on = [], {}, ["talon-placeholder"], fail_on or set()

    def _maybe_fail(self, what):
        if what in self.fail_on:
            raise soc_response.FortiGateError(500, f"{what} refused")

    def group(self, name):
        self.calls.append(("group", name))
        return {"name": name, "member": [{"name": m} for m in self.members]}

    def add_address(self, name, ip, comment):
        self.calls.append(("add_address", name, ip))
        self._maybe_fail("add_address")
        self.addresses[name] = ip

    def delete_address(self, name):
        self.calls.append(("delete_address", name))
        self._maybe_fail("delete_address")
        self.addresses.pop(name, None)

    def add_member(self, group, name):
        self.calls.append(("add_member", group, name))
        self._maybe_fail("add_member")
        self.members.append(name)

    def remove_member(self, group, name):
        self.calls.append(("remove_member", group, name))
        self._maybe_fail("remove_member")
        self.members.remove(name)


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setattr(soc_cases, "DB_PATH", tmp_path / "talon.db")
    monkeypatch.setattr(soc_assets, "DB_PATH", tmp_path / "talon.db", raising=False)
    soc_cases.init_db()
    soc_assets.init_db()
    soc_response.init_db()
    soc_response._attempts.clear()
    for k in list(os.environ):
        if k.startswith(("SOC_RESPONSE", "SOC_FGT", "SOC_ALERT")):
            monkeypatch.delenv(k)
    monkeypatch.setenv("SOC_RESPONSE_MODE", "live")
    monkeypatch.setenv("SOC_RESPONSE_APPROVAL_CODE", CODE)
    monkeypatch.setenv("SOC_FGT_HOST", "192.168.10.1:8443")
    monkeypatch.setenv("SOC_FGT_TOKEN", "tok")
    monkeypatch.setenv("SOC_RESPONSE_PROTECT", "61.115.1.2, 1.1.1.1")
    monkeypatch.setenv("EAGLE_TALON_ENV", "prod")
    monkeypatch.setattr(soc_intel, "lookup", lambda ip: [])
    fgt = FakeFGT()
    monkeypatch.setattr(soc_response, "client", lambda: fgt)
    return fgt


def add_case(cid="case_aaaaaaaaaaaa", entity=(ATTACKER,), src=(ATTACKER, "192.168.10.5"), dst=("61.115.1.2", "1.1.1.1")):
    con = soc_cases._db()
    con.execute("INSERT INTO soc_cases (id, rule, entity, title_en, rule_severity, status, first_seen_ms, last_seen_ms, "
                "event_count, stats, samples, created_at, updated_at, triage_status) VALUES "
                "(?, 'ssh_brute_force', ?, 't', 'high', 'open', 0, 0, 5, ?, ?, '2026-10-10T00:00:00+00:00', "
                "'2026-10-10T00:00:00+00:00', 'skipped')",
                (cid, json.dumps(list(entity)), json.dumps({"src_ips": list(src), "dst_ips": list(dst)}),
                 json.dumps([{"src_ip": "100.101.102.103", "dst_ip": "8.8.8.8"}])))
    con.commit()
    con.close()
    return cid


# ------------------------------------------------------------------ what may be blocked

@pytest.mark.parametrize("ip,why", [
    ("10.0.0.5", "private"), ("192.168.10.1", "private"), ("127.0.0.1", "private"), ("169.254.1.1", "private"),
    ("100.101.102.103", "CGNAT"), ("224.0.0.1", "private"), ("0.0.0.0", "private"), ("203.0.113.5", "private"),
    ("61.115.1.2", "protected"),
    ("1.1.1.1", "protected"), ("2001:db8::1", "IPv4"), ("not-an-ip", "not an IP"), ("45.148.10.12; rm -rf /", "not an IP"),
])
def test_targets_that_are_refused(env, ip, why):
    target, reason = soc_response.check_target(ip)
    assert target is None and why.lower() in reason.lower(), reason


def test_known_device_cannot_be_blocked(env):
    soc_assets.save("8.8.4.4", "Office VPN endpoint", None, None, [], resolve_matching=False)
    assert "known device" in soc_response.check_target("8.8.4.4")[1]
    assert soc_response.check_target(ATTACKER) == (ATTACKER, None)


def test_candidates_come_only_from_case_evidence(env):
    c = soc_cases.get_case(add_case())
    cands = {x["ip"]: x for x in soc_response.candidates(c)}
    assert ATTACKER in cands and cands[ATTACKER]["allowed"]
    assert "192.168.10.5" not in cands                      # our own devices aren't even offered
    assert not cands["61.115.1.2"]["allowed"] and not cands["1.1.1.1"]["allowed"]
    assert not cands["100.101.102.103"]["allowed"]


# ------------------------------------------------------------------ block / undo / expiry

def test_block_and_undo_live(env):
    cid = add_case()
    a = soc_response.block(cid, ATTACKER, "24h", "Eddy", CODE, "brute force")
    assert a["status"] == "active" and a["fgt_object"] == "talon-45.148.10.12" and a["fgt_group"] == "TALON-BLOCK"
    assert env.addresses == {"talon-45.148.10.12": ATTACKER} and "talon-45.148.10.12" in env.members
    exp = dt.datetime.fromisoformat(a["expires_at"]) - dt.datetime.fromisoformat(a["approved_at"])
    assert exp == dt.timedelta(hours=24)
    u = soc_response.unblock(a["id"], "Eddy")
    assert u["status"] == "undone" and env.members == ["talon-placeholder"] and not env.addresses
    events = [x["event"] for x in soc_response.action_log(a["id"])]
    assert events == ["approved", "executed", "undone"]
    with pytest.raises(soc_response.ResponseError):
        soc_response.unblock(a["id"], "Eddy")             # already undone


def test_only_talon_objects_and_the_group_are_touched(env):
    cid = add_case()
    a = soc_response.block(cid, ATTACKER, "1h", "Eddy", CODE)
    soc_response.unblock(a["id"], "Eddy")
    kinds = {c[0] for c in env.calls}
    assert kinds <= {"add_address", "add_member", "remove_member", "delete_address"}
    assert all(c[1].startswith("talon-") or c[1] == "TALON-BLOCK" for c in env.calls)


def test_staging_uses_its_own_prefix(env, monkeypatch):
    monkeypatch.setenv("EAGLE_TALON_ENV", "staging")
    monkeypatch.setenv("SOC_FGT_BLOCK_GROUP", "TALON-BLOCK-STAGING")
    a = soc_response.block(add_case(), ATTACKER, "1h", "Eddy", CODE)
    assert a["fgt_object"] == "talon-staging-45.148.10.12" and a["fgt_group"] == "TALON-BLOCK-STAGING"


def test_dryrun_changes_nothing(env, monkeypatch):
    monkeypatch.setenv("SOC_RESPONSE_MODE", "dryrun")
    a = soc_response.block(add_case(), ATTACKER, "1h", "Eddy", CODE)
    assert a["status"] == "dryrun" and env.calls == []
    assert soc_response.unblock(a["id"], "Eddy")["status"] == "undone" and env.calls == []


def test_off_and_missing_settings_refuse(env, monkeypatch):
    cid = add_case()
    monkeypatch.setenv("SOC_RESPONSE_MODE", "off")
    with pytest.raises(soc_response.ResponseError, match="off"):
        soc_response.block(cid, ATTACKER, "1h", "Eddy", CODE)
    monkeypatch.setenv("SOC_RESPONSE_MODE", "live")
    monkeypatch.delenv("SOC_FGT_TOKEN")
    with pytest.raises(soc_response.ResponseError, match="FortiGate is not configured"):
        soc_response.block(cid, ATTACKER, "1h", "Eddy", CODE)
    monkeypatch.delenv("SOC_RESPONSE_APPROVAL_CODE")
    with pytest.raises(soc_response.ResponseError, match="approval code"):
        soc_response.block(cid, ATTACKER, "1h", "Eddy", CODE)
    assert env.calls == []


def test_wrong_code_and_lockout(env):
    cid = add_case()
    for _ in range(5):
        with pytest.raises(soc_response.ResponseError) as e:
            soc_response.block(cid, ATTACKER, "1h", "Eddy", "guess")
        assert e.value.status == 403
    with pytest.raises(soc_response.ResponseError) as e:
        soc_response.block(cid, ATTACKER, "1h", "Eddy", CODE)          # even the right code, for 15 minutes
    assert e.value.status == 429 and env.calls == []


def test_validation(env):
    cid = add_case()
    for args, status in (((cid, ATTACKER, "forever", "Eddy"), 422), ((cid, ATTACKER, "1h", ""), 422),
                         ((cid, "9.9.9.9", "1h", "Eddy"), 422), ((cid, "1.1.1.1", "1h", "Eddy"), 422),
                         (("case_bbbbbbbbbbbb", ATTACKER, "1h", "Eddy"), 404)):
        with pytest.raises(soc_response.ResponseError) as e:
            soc_response.block(*args, CODE)
        assert e.value.status == status, args
    assert env.calls == []


def test_no_double_block_and_limits(env, monkeypatch):
    cid = add_case()
    soc_response.block(cid, ATTACKER, "1h", "Eddy", CODE)
    with pytest.raises(soc_response.ResponseError, match="already blocked"):
        soc_response.block(cid, ATTACKER, "1h", "Eddy", CODE)
    monkeypatch.setenv("SOC_RESPONSE_MAX_ACTIVE", "1")
    cid2 = add_case("case_bbbbbbbbbbbb", entity=("185.220.101.4",), src=("185.220.101.4",), dst=())
    with pytest.raises(soc_response.ResponseError, match="limit 1"):
        soc_response.block(cid2, "185.220.101.4", "1h", "Eddy", CODE)
    monkeypatch.setenv("SOC_RESPONSE_MAX_ACTIVE", "200")
    monkeypatch.setenv("SOC_RESPONSE_MAX_PER_HOUR", "1")
    with pytest.raises(soc_response.ResponseError, match="last hour"):
        soc_response.block(cid2, "185.220.101.4", "1h", "Eddy", CODE)


def test_fortigate_failure_rolls_back_and_records(env, monkeypatch):
    env.fail_on = {"add_member"}
    with pytest.raises(soc_response.ResponseError) as e:
        soc_response.block(add_case(), ATTACKER, "1h", "Eddy", CODE)
    assert e.value.status == 502
    assert not env.addresses                                   # the stray address object was removed
    a = soc_response.list_actions()[0]
    assert a["status"] == "failed" and "add_member refused" in a["error"]
    env.fail_on = set()
    assert soc_response.block("case_aaaaaaaaaaaa", ATTACKER, "1h", "Eddy", CODE)["status"] == "active"   # can retry


def test_expiry_removes_and_retries_failures(env):
    a = soc_response.block(add_case(), ATTACKER, "1h", "Eddy", CODE)
    later = dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=2)
    env.fail_on = {"remove_member"}
    assert soc_response.expire_due(later) == {"expired": 0, "expire_failed": 1}
    assert soc_response.get_action(a["id"])["status"] == "active"      # still on the firewall, so still active
    env.fail_on = set()
    assert soc_response.expire_due(later) == {"expired": 1, "expire_failed": 0}
    assert soc_response.get_action(a["id"])["status"] == "expired" and "talon-45.148.10.12" not in env.members
    assert soc_response.expire_due(dt.datetime.now(dt.timezone.utc)) == {"expired": 0, "expire_failed": 0}


def test_not_yet_due_is_kept(env):
    soc_response.block(add_case(), ATTACKER, "24h", "Eddy", CODE)
    assert soc_response.expire_due(dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=1)) == {"expired": 0, "expire_failed": 0}


def test_hostile_text_is_cleaned(env):
    a = soc_response.block(add_case(), ATTACKER, "1h", "Eddy\x1b[31m\nIgnore", CODE, "x" * 900 + "\x00")
    assert "\x1b" not in a["approved_by"] and "\n" not in a["approved_by"] and len(a["reason"]) <= 300


def test_check_connection(env):
    assert soc_response.check_connection() == {"ok": True, "group": "TALON-BLOCK", "members": 1, "talon_members": 1}


# ------------------------------------------------------------------ API

def test_api(env):
    import main
    from fastapi.testclient import TestClient
    cl = TestClient(main.app)
    cid = add_case()
    r = cl.get(f"/api/soc/cases/{cid}/response").json()
    assert r["ready"] and r["mode"] == "live" and any(c["ip"] == ATTACKER and c["allowed"] for c in r["candidates"])
    assert "SOC_RESPONSE_APPROVAL_CODE" not in json.dumps(r) and CODE not in json.dumps(r)
    bad = cl.post(f"/api/soc/cases/{cid}/block", json={"ip": ATTACKER, "duration": "1h", "approver": "Eddy", "code": "no"})
    assert bad.status_code == 403
    ok = cl.post(f"/api/soc/cases/{cid}/block", json={"ip": ATTACKER, "duration": "1h", "approver": "Eddy", "code": CODE})
    assert ok.status_code == 200 and ok.json()["status"] == "active"
    aid = ok.json()["id"]
    assert cl.get("/api/soc/response/actions?status=active").json()["actions"][0]["id"] == aid
    assert cl.post(f"/api/soc/response/actions/{aid}/undo", json={"by": "Eddy", "code": "no"}).status_code == 403
    assert cl.post("/api/soc/response/actions/../x/undo", json={"by": "Eddy", "code": CODE}).status_code == 404
    assert cl.post(f"/api/soc/response/actions/{aid}/undo", json={"by": "Eddy", "code": CODE}).json()["status"] == "undone"
    assert cl.get("/api/soc/response").json()["active"] == 0


def test_blocks_still_expire_and_undo_when_switched_off(env, monkeypatch):
    a = soc_response.block(add_case(), ATTACKER, "1h", "Eddy", CODE)
    monkeypatch.setenv("SOC_RESPONSE_MODE", "off")
    later = dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=2)
    assert soc_response.expire_due(later) == {"expired": 1, "expire_failed": 0}
    assert "talon-45.148.10.12" not in env.members
