"""The adaptive attacker: valid cookie, IDENTICAL user-agent, headers and IP as the victim."""
import pytest

from conftest import DeviceKey, evaluate, login_bound, names, proof_for


@pytest.mark.layer1_gap
def test_A3_adaptive_replay_passes_layer1_must_be_stopped_by_layer2(client):
    """KNOWN GAP. With layer 1 only (no device key) a replay that copies the victim's
    UA, headers and IP is indistinguishable from the victim: score 0, allowed.
    It passes layer 1; layer 2 (device-bound proof) must stop it - see B5 below."""
    evaluate(client)                                   # victim logs in
    replay = evaluate(client, kind="write", route="POST /transfer")  # attacker, identical context
    assert replay == {"score": 0, "signals": [], "action": "allow"}


def test_B5_adaptive_replay_is_forced_to_stepup_by_device_proof(l2):
    login_bound(l2)
    replay = evaluate(l2, kind="write", route="POST /transfer")  # identical context, no key
    assert replay["action"] == "challenge"
    assert names(replay) == {"proof_missing"}          # layer 1 saw nothing: layer 2 did the work


def test_B5_attacker_who_fetches_a_challenge_still_cannot_sign_it(l2):
    login_bound(l2)
    # The attacker can ask the app for a nonce (they hold the cookie) but signs with their own key.
    forged = proof_for(l2, DeviceKey(), "POST /transfer")
    replay = evaluate(l2, kind="write", route="POST /transfer", proof=forged)
    assert replay["action"] == "terminate" and names(replay) == {"proof_invalid"}


def test_B5_after_the_presence_window_even_reads_need_stepup(l2, clock):
    login_bound(l2)
    clock.advance(31)  # victim's device stopped proving presence (tab closed / attacker acting alone)
    assert evaluate(l2)["action"] == "challenge"
