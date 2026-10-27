"""Tests for passkey step-up state: elevation window, failure, timeout."""
from conftest import HEADERS, SID, body, evaluate, login_bound, names


def outcome(client, success, sid=SID):
    return client.post("/stepup/outcome", json={**body(sid), "success": success}, headers=HEADERS).json()


def test_passed_stepup_grants_an_elevated_window_then_expires(l2, clock):
    login_bound(l2)
    assert evaluate(l2, kind="write")["action"] == "challenge"
    assert outcome(l2, True)["elevated_seconds"] == 300
    during = evaluate(l2, kind="write")                    # still no proof, but recently stepped up
    assert during["action"] == "allow" and "stepup_elevated" in names(during)
    clock.advance(301)
    assert evaluate(l2, kind="write")["action"] == "challenge"


def test_elevation_never_downgrades_a_terminate(l2):
    from conftest import DeviceKey, proof_for
    login_bound(l2)
    evaluate(l2, kind="write")
    outcome(l2, True)
    forged = proof_for(l2, DeviceKey(), "POST /transfer")
    assert evaluate(l2, kind="write", proof=forged)["action"] == "terminate"


def test_failed_stepup_terminates_the_session(l2):
    login_bound(l2)
    evaluate(l2, kind="write")
    assert outcome(l2, False)["action"] == "terminate"
    r = evaluate(l2)
    assert r["action"] == "terminate" and names(r) == {"session_terminated"}


def test_unanswered_stepup_times_out_and_terminates(l2, clock):
    login_bound(l2)
    assert evaluate(l2, kind="write")["action"] == "challenge"   # step-up requested, never answered
    clock.advance(61)
    r = evaluate(l2, kind="auth")                                # ANY later request ends the session
    assert r["action"] == "terminate" and names(r) == {"stepup_timeout"}


def test_passing_stepup_cancels_the_timeout(l2, clock):
    login_bound(l2)
    evaluate(l2, kind="write")
    outcome(l2, True)
    clock.advance(120)
    assert evaluate(l2, kind="auth")["action"] != "terminate"
