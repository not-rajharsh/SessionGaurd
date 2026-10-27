"""Tests for the dashboard data API: auth, no session-id leakage, rationale present."""
from app.main import session_ref
from conftest import HEADERS, NYC, SID, evaluate, login_bound


def test_admin_endpoints_require_the_service_key(l2):
    assert l2.get("/admin/sessions").status_code == 401
    assert l2.get(f"/admin/sessions/{'a' * 12}").status_code == 401


def test_sessions_list_shows_hash_not_session_id(l2):
    login_bound(l2)
    evaluate(l2)
    evaluate(l2, ip=NYC, ua="Other", kind="write", route="POST /transfer")
    r = l2.get("/admin/sessions", headers=HEADERS)
    assert SID not in r.text                                   # the bearer token never leaves the engine
    (row,) = r.json()["sessions"]
    assert row["ref"] == session_ref(SID) and row["status"] == "terminated" and row["events"] == 3


def test_session_detail_has_timeline_signals_and_rationale(l2):
    login_bound(l2)
    evaluate(l2, ip=NYC, ua="Other", kind="write", route="POST /transfer")
    ev = l2.get(f"/admin/sessions/{session_ref(SID)}", headers=HEADERS).json()["events"]
    assert [e["action"] for e in ev] == ["allow", "terminate"]
    assert ev[1]["route"] == "POST /transfer" and ev[1]["signals"] and ev[1]["rationale"]
    assert SID not in str(ev)


def test_ref_is_validated(l2):
    assert l2.get("/admin/sessions/../../etc", headers=HEADERS).status_code in (404, 422)
    assert l2.get("/admin/sessions/XYZ", headers=HEADERS).status_code == 422
