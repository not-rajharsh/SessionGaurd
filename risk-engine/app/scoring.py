"""scoring: signals -> 0-100 score -> action.

Phase 1 stand-in for the fusion layer: a capped sum of signal weights.
Policy: score < 30 allow; 30..70 challenge (Passkey step-up arrives later,
for now the middleware returns 403); > 70 terminate.
"""
from __future__ import annotations

from typing import Iterable

from .checks import Signal

ALLOW_BELOW = 30
TERMINATE_ABOVE = 70


def decide(signals: Iterable[Signal]) -> tuple[int, str]:
    score = min(100, sum(s.weight for s in signals))
    if score < ALLOW_BELOW:
        return score, "allow"
    if score > TERMINATE_ABOVE:
        return score, "terminate"
    return score, "challenge"
