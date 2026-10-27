"""Tests for scoring: threshold boundaries and the 100 cap."""
from app.checks import Signal
from app.scoring import decide


def sig(w):
    return [Signal("x", w, "")]


def test_thresholds():
    assert decide([]) == (0, "allow")
    assert decide(sig(29)) == (29, "allow")
    assert decide(sig(30)) == (30, "challenge")
    assert decide(sig(70)) == (70, "challenge")
    assert decide(sig(71)) == (71, "terminate")


def test_score_is_capped_at_100():
    assert decide(sig(80) + sig(80)) == (100, "terminate")
