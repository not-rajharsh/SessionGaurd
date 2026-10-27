"""Tests for layer 2: device-bound key binding, single-use nonces, proof rules, fusion."""
from conftest import DELHI, FP_A, HEADERS, SID, UA_B, DeviceKey, evaluate, login_bound, names, proof_for


def bind(client, key, sid=SID):
    return client.post("/bind", json={"session_id": sid, "public_key": key.spki}, headers=HEADERS)


def test_session_cannot_be_rebound(l2):
    login_bound(l2)
    attacker = DeviceKey()  # attacker holds the stolen cookie and tries to register their own key
    assert bind(l2, attacker).status_code == 409
    assert bind(l2, DeviceKey()).status_code == 409


def test_bind_preconditions(l2):
    key = DeviceKey()
    assert bind(l2, key).status_code == 409                      # no baseline yet
    evaluate(l2)
    assert l2.post("/bind", json={"session_id": SID, "public_key": key.spki}).status_code == 401  # service auth
    bad = l2.post("/bind", json={"session_id": SID, "public_key": "A" * 80}, headers=HEADERS)
    assert bad.status_code == 422                                # garbage is not a P-256 key
    assert bind(l2, key).status_code == 200


def test_valid_per_action_proof_is_allowed_and_lowers_score(l2):
    key = login_bound(l2)
    r = evaluate(l2, kind="write", route="POST /transfer",
                 proof=proof_for(l2, key, "POST /transfer"))
    assert r["action"] == "allow" and r["score"] == 0 and "proof_valid" in names(r)


def test_write_without_proof_forces_stepup(l2):
    login_bound(l2)
    r = evaluate(l2, kind="write")
    assert r["action"] == "challenge" and names(r) == {"proof_missing"} and r["score"] == 50


def test_nonce_is_single_use(l2):
    key = login_bound(l2)
    p = proof_for(l2, key, "POST /transfer")
    assert evaluate(l2, kind="write", proof=p)["action"] == "allow"
    replay = evaluate(l2, kind="write", proof=p)  # same nonce + signature again
    assert replay["action"] == "challenge" and "proof_expired" in names(replay)


def test_nonce_expires_after_30_seconds(l2, clock):
    key = login_bound(l2)
    p = proof_for(l2, key, "POST /transfer")
    clock.advance(31)
    r = evaluate(l2, kind="write", proof=p)
    assert r["action"] == "challenge" and "proof_expired" in names(r)


def test_signature_from_wrong_key_terminates(l2):
    login_bound(l2)
    forged = proof_for(l2, DeviceKey(), "POST /transfer")  # attacker signs with their own key
    r = evaluate(l2, kind="write", proof=forged)
    assert r["action"] == "terminate" and names(r) == {"proof_invalid"}


def test_proof_is_bound_to_the_action(l2):
    key = login_bound(l2)
    p = proof_for(l2, key, "GET /api/me")  # valid signature, but for a different action
    r = evaluate(l2, kind="write", proof={**p, "purpose": "POST /transfer"})
    assert r["action"] == "terminate" and "proof_invalid" in names(r)


def test_nonce_cannot_be_used_from_another_session(l2):
    key = login_bound(l2)
    other = "sess-other-9999"
    login_bound(l2, DeviceKey(), sid=other)
    p = proof_for(l2, key, "POST /transfer")  # issued to SID, presented on `other`
    r = evaluate(l2, sid=other, kind="write", proof=p)
    assert r["action"] == "terminate" and "proof_invalid" in names(r)


def test_read_needs_presence_every_30_seconds(l2, clock):
    key = login_bound(l2)
    assert evaluate(l2)["action"] == "allow"                     # bind counts as first presence
    clock.advance(31)
    stale = evaluate(l2)
    assert stale["action"] == "challenge" and names(stale) == {"proof_stale"}
    # presence heartbeat is an 'auth' request carrying a proof; it must stay reachable
    assert evaluate(l2, kind="auth", proof=proof_for(l2, key, "presence"))["action"] == "allow"
    assert evaluate(l2)["action"] == "allow"


def test_auth_requests_without_proof_stay_reachable(l2, clock):
    login_bound(l2)
    clock.advance(120)
    assert evaluate(l2, kind="auth")["action"] == "allow"        # needed to fetch a challenge


def test_unbound_session_behaves_like_phase1(client):
    evaluate(client)
    assert evaluate(client, kind="write")["action"] == "allow"


def test_valid_proof_strongly_lowers_the_score(l2, client):
    login_bound(l2)
    with_proof = evaluate(l2, ua=UA_B)           # UA mismatch (+30) but device presence is fresh (-25)
    evaluate(client)
    without = evaluate(client, ua=UA_B)          # same mismatch on an unbound session
    assert (with_proof["score"], with_proof["action"]) == (5, "allow")
    assert (without["score"], without["action"]) == (30, "challenge")


def test_bound_session_never_silently_rebaselines(l2):
    login_bound(l2)
    del l2.store._d[f"risk:baseline:{SID}"]       # simulate partially expired state
    r = evaluate(l2)
    assert r["action"] == "terminate" and names(r) == {"state_expired"}
