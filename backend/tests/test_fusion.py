"""Tests for the decision policy.

The tests in `TestRuleGatedRed` guard the single most important safety property
in this codebase (PRD v3.0 section 14.2): a probabilistic model must never be
able to raise a RED verdict and take over a frightened user's screen.

If one of those tests ever fails, the correct response is to fix the policy, not
the test.
"""

from __future__ import annotations

from app import fusion
from app.schemas import Band, Pillar, Severity, Signal


def det(severity: Severity, weight: float = 1.0, code: str = "RULE") -> Signal:
    """A deterministic rule hit."""
    return Signal(
        code=code,
        pillar=Pillar.URL,
        severity=severity,
        deterministic=True,
        weight=weight,
    )


def model(severity: Severity, weight: float = 1.0, code: str = "MODEL") -> Signal:
    """A probabilistic model output."""
    return Signal(
        code=code,
        pillar=Pillar.TEXT,
        severity=severity,
        deterministic=False,
        weight=weight,
    )


class TestRiskScore:
    def test_no_signals_scores_zero(self):
        assert fusion.risk_score([]) == 0.0

    def test_score_is_monotonic_in_evidence(self):
        one = fusion.risk_score([det(Severity.MEDIUM)])
        two = fusion.risk_score([det(Severity.MEDIUM), det(Severity.MEDIUM)])
        assert two > one

    def test_score_saturates_below_one_hundred(self):
        many = [det(Severity.CRITICAL, weight=5.0, code=f"R{i}") for i in range(50)]
        assert fusion.risk_score(many) < 100.0

    def test_severity_dominates_over_count(self):
        """One conclusive signal should outrank a pile of trivial ones."""
        critical = fusion.risk_score([det(Severity.CRITICAL, weight=1.5)])
        trivia = fusion.risk_score(
            [det(Severity.LOW, weight=0.6, code=f"L{i}") for i in range(3)]
        )
        assert critical > trivia


class TestRuleGatedRed:
    """PRD section 14.2: only deterministic signals may authorise RED."""

    def test_single_deterministic_critical_authorises_red(self):
        band, score, eligible = fusion.decide_band([det(Severity.CRITICAL, 1.5)])
        assert eligible is True
        assert band is Band.RED

    def test_two_deterministic_high_authorise_red(self):
        signals = [
            det(Severity.HIGH, 1.4, "RULE_A"),
            det(Severity.HIGH, 1.3, "RULE_B"),
        ]
        band, _, eligible = fusion.decide_band(signals)
        assert eligible is True
        assert band is Band.RED

    def test_single_deterministic_high_is_only_amber(self):
        """One HIGH rule is suggestive, not conclusive. Must not interrupt."""
        band, _, eligible = fusion.decide_band([det(Severity.HIGH, 1.4)])
        assert eligible is False
        assert band is Band.AMBER

    def test_model_signal_at_max_confidence_cannot_reach_red(self):
        band, _, eligible = fusion.decide_band([model(Severity.CRITICAL, 5.0)])
        assert eligible is False
        assert band is Band.AMBER

    def test_overwhelming_model_evidence_still_cannot_reach_red(self):
        """The core invariant, stated as forcefully as possible.

        Twenty CRITICAL model signals at maximum weight produce a very high
        score, and must still be capped at AMBER.
        """
        signals = [
            model(Severity.CRITICAL, 5.0, code=f"MODEL_{i}") for i in range(20)
        ]
        band, score, eligible = fusion.decide_band(signals)
        assert score > 90.0, "expected the score to be high"
        assert eligible is False, "model output must never authorise RED"
        assert band is Band.AMBER, "model output must be capped at AMBER"

    def test_one_deterministic_high_plus_model_pile_stays_amber(self):
        """Models must not be able to top up a rule to reach the RED gate."""
        signals = [det(Severity.HIGH, 1.4)] + [
            model(Severity.CRITICAL, 3.0, code=f"MODEL_{i}") for i in range(10)
        ]
        band, _, eligible = fusion.decide_band(signals)
        assert eligible is False
        assert band is Band.AMBER

    def test_red_requires_score_floor_as_well_as_gate(self):
        """A CRITICAL rule with negligible weight should not alone hit RED."""
        band, score, eligible = fusion.decide_band(
            [det(Severity.CRITICAL, weight=0.05)]
        )
        assert eligible is True, "the gate opens"
        assert score < fusion.RED_SCORE_MIN, "but the score floor is not met"
        assert band is not Band.RED


class TestBands:
    def test_no_signals_is_green(self):
        band, score, eligible = fusion.decide_band([])
        assert band is Band.GREEN
        assert score == 0.0
        assert eligible is False

    def test_trivial_evidence_stays_green(self):
        band, _, _ = fusion.decide_band([det(Severity.LOW, weight=0.6)])
        assert band is Band.GREEN

    def test_interrupts_only_on_red(self):
        from app.pipeline import _finalise
        from app.schemas import Language

        red = _finalise([det(Severity.CRITICAL, 1.5)], Language.EN, False)
        amber = _finalise([det(Severity.HIGH, 1.4)], Language.EN, False)
        green = _finalise([], Language.EN, False)

        assert red.interrupts is True
        assert amber.interrupts is False
        assert green.interrupts is False


class TestRanking:
    def test_most_severe_first(self):
        signals = [
            det(Severity.LOW, code="LOW"),
            det(Severity.CRITICAL, code="CRIT"),
            det(Severity.MEDIUM, code="MED"),
        ]
        ranked = fusion.rank_signals(signals)
        assert [s.code for s in ranked] == ["CRIT", "MED", "LOW"]

    def test_deterministic_precedes_model_at_equal_severity(self):
        ranked = fusion.rank_signals(
            [model(Severity.HIGH, code="MODEL"), det(Severity.HIGH, code="RULE")]
        )
        assert ranked[0].code == "RULE"
