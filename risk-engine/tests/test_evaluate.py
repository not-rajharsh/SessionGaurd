"""API-level tests for POST /evaluate: legit session allowed, replay blocked."""
from conftest import DELHI, DELHI_2, FP_B, HEADERS, NYC, UA_A, UA_B, body


def post(client, **kw):
    return client.post("/evaluate", json=body(**kw), headers=HEADERS)


def test_legitimate_session_is_allowed(client):
    for _ in range(3):  # login baseline + two follow-up requests
        r = post(client)
        assert r.status_code == 200
        assert r.json() == {"score": 0, "signals": [], "action": "allow"}


def test_replayed_session_is_blocked(client):
    post(client)  # baseline at login (Delhi, browser A)
    assert post(client).json()["action"] == "allow"  # legit follow-up
    r = post(client, ip=NYC, ua=UA_B)  # replay: new UA + different network
    data = r.json()
    assert data["action"] == "terminate" and data["score"] > 70
    got = {s["name"] for s in data["signals"]}
    assert {"user_agent_mismatch", "ip_change", "asn_change", "impossible_travel"} <= got


def test_terminated_session_stays_terminated_even_for_legit_context(client):
    post(client)
    post(client, ip=NYC, ua=UA_B)
    r = post(client)  # now even the original context is refused
    assert r.json()["action"] == "terminate"
    assert r.json()["signals"][0]["name"] == "session_terminated"


def test_ip_change_within_same_isp_is_allowed(client):
    post(client)
    r = post(client, ip=DELHI_2).json()
    assert r["action"] == "allow" and r["score"] == 10


def test_single_strong_signal_triggers_challenge(client):
    post(client)
    r = post(client, ua=UA_B).json()
    assert r["action"] == "challenge" and r["score"] == 30


def test_blocked_request_does_not_advance_last_seen(client):
    post(client)
    assert post(client, ua=UA_B, fp=FP_B).json()["action"] == "challenge"  # 65
    # Original context still clean: the challenged request must not become the new normal.
    assert post(client).json() == {"score": 0, "signals": [], "action": "allow"}


def test_unauthorized_and_invalid_input(client):
    assert client.post("/evaluate", json=body()).status_code == 401
    bad = client.post("/evaluate", json=body(ip="not-an-ip"), headers=HEADERS)
    assert bad.status_code == 422


def test_events_are_logged(client, events):
    post(client)
    post(client, ip=NYC, ua=UA_B)
    actions = [e["action"] for e in events.recent()]
    assert actions == ["terminate", "allow"]
