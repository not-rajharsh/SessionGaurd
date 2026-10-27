"""scoring: the fusion layer. Signals -> 0-100 score -> action.

Score = clamped sum of signal weights. Risk signals add; a valid device proof
(layer 2) carries a NEGATIVE weight, so it strongly lowers the score, while a
failed proof alone lands in step-up (missing/expired) or terminate (invalid).
Policy: score < 30 allow; 30..70 challenge (passkey step-up); > 70 terminate.
"""
from __future__ import annotations

from typing import Iterable

from .checks import Signal

ALLOW_BELOW = 30
TERMINATE_ABOVE = 70


def decide(signals: Iterable[Signal]) -> tuple[int, str]:
    score = max(0, min(100, sum(s.weight for s in signals)))
    if score < ALLOW_BELOW:
        return score, "allow"
    if score > TERMINATE_ABOVE:
        return score, "terminate"
    return score, "challenge"
