"""Evidence fusion and the three-state decision policy.

PRD v3.0 sections 7.3 (F22-F24), 14.

Two properties matter here, and they are the reason this module exists as its
own unit with its own tests.

1. We fuse evidence about ONE message (section 14.1). Signals are only combined
   when they describe the same artifact, so the aggregate means something.

2. **Only deterministic signals may raise a RED verdict** (section 14.2).
   Model outputs are capped at AMBER no matter how confident they are.

The rationale for (2) is section 14.3's arithmetic. A user receiving roughly 40
messages a day cannot tolerate frequent wrong red alerts: at two red alerts per
day and 90% precision she sees a false alarm every five days, and the app is
uninstalled within a month. Deterministic rules ("this link ends in .apk",
"DKIM hard-failed") are near-100% precision, so they are allowed to interrupt.
A classifier at 0.91 confidence is not. Models inform; rules interrupt.

This costs recall on RED, and that trade is deliberate: AMBER plus the "Ask
family" escalation still routes the user to safety, whereas a wrong RED costs
the install permanently.
"""

from __future__ import annotations

from .schemas import Band, Severity, Signal

# --------------------------------------------------------------------------
# Tuning constants
# --------------------------------------------------------------------------

# Saturating denominator for the risk score. Chosen so that a single
# deterministic CRITICAL signal lands above RED_SCORE_MIN while a single HIGH
# signal does not, keeping score and gate broadly consistent.
_SCORE_K = 5.0

# A RED verdict needs BOTH the deterministic gate and this score floor.
RED_SCORE_MIN = 45.0

# Below this, the message is GREEN.
AMBER_SCORE_MIN = 18.0

# Number of deterministic HIGH signals that together authorise RED, standing in
# for a single CRITICAL. Section 14.2 lists such pairings explicitly, e.g.
# "DKIM/SPF failure plus display-name spoofing" or "brand homoglyph plus
# payment request".
HIGH_SIGNALS_FOR_RED = 2


def risk_score(signals: list[Signal]) -> float:
    """Map accumulated evidence onto 0-100.

    Saturating rather than linear so that a message with many weak signals
    cannot outrank one with a single conclusive signal, and so the scale has no
    hard ceiling behaviour to special-case.
    """
    raw = sum(signal.contribution for signal in signals)
    if raw <= 0:
        return 0.0
    return round(100.0 * raw / (raw + _SCORE_K), 1)


def is_red_eligible(signals: list[Signal]) -> bool:
    """Whether any deterministic evidence authorises a screen-takeover alert.

    This is the enforcement point for the section 14.2 guarantee. Note that
    `signal.deterministic` is required in both branches: no combination of model
    outputs, however numerous or confident, can satisfy this predicate.
    """
    deterministic = [s for s in signals if s.deterministic]

    if any(s.severity >= Severity.CRITICAL for s in deterministic):
        return True

    high_count = sum(1 for s in deterministic if s.severity >= Severity.HIGH)
    return high_count >= HIGH_SIGNALS_FOR_RED


def decide_band(signals: list[Signal]) -> tuple[Band, float, bool]:
    """Resolve signals into a verdict band, score and RED-eligibility flag.

    Returns:
        (band, score, red_eligible)
    """
    score = risk_score(signals)
    red_eligible = is_red_eligible(signals)

    if red_eligible and score >= RED_SCORE_MIN:
        return Band.RED, score, red_eligible
    if score >= AMBER_SCORE_MIN:
        return Band.AMBER, score, red_eligible
    return Band.GREEN, score, red_eligible


def rank_signals(signals: list[Signal]) -> list[Signal]:
    """Order signals for presentation: most severe first, deterministic ahead.

    Drives the order of reasons shown to the user, so the most legible and most
    conclusive evidence appears at the top of the explanation.
    """
    return sorted(
        signals,
        key=lambda s: (-int(s.severity), not s.deterministic, -s.weight, s.code),
    )
