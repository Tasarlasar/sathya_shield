"""Tests for the trained models and, critically, their confinement.

The point of these tests is not that the models are accurate. It is that they
are *contained*: no matter how confident a classifier becomes, it must not be
able to produce a screen-takeover alert (PRD section 14.2).

`test_fusion.py` already proves that property against synthetic signals. These
tests prove it against the real models, which is the version that matters,
because a synthetic signal cannot drift and a model can.
"""

from __future__ import annotations

import pytest

from app import pipeline
from app.models import text_model, url_model
from app.schemas import Band, MessageInput, Severity

pytestmark = pytest.mark.filterwarnings("ignore::UserWarning")

MODELS_PRESENT = url_model.is_available() and text_model.is_available()
requires_models = pytest.mark.skipif(
    not MODELS_PRESENT,
    reason="model artifacts absent; run python -m ml.train_url and ml.train_text",
)


class TestGracefulDegradation:
    """The service must work on a checkout that never trained a model."""

    def test_url_model_absent_returns_no_signals(self, monkeypatch):
        monkeypatch.setattr(url_model, "is_available", lambda: False)
        assert url_model.analyse_urls(["http://sbi-rewards.xyz/login"]) == []

    def test_text_model_absent_returns_no_signals(self, monkeypatch):
        monkeypatch.setattr(text_model, "_load", lambda: None)
        assert text_model.analyse_text("win a free prize now") == []

    def test_pipeline_works_without_models(self, monkeypatch):
        monkeypatch.setattr(url_model, "is_available", lambda: False)
        monkeypatch.setattr(text_model, "_load", lambda: None)
        verdict = pipeline.check_message(
            MessageInput(text="Install http://x.co/a.apk now")
        )
        # The deterministic APK rule alone must still produce RED.
        assert verdict.band is Band.RED
        assert verdict.red_eligible is True


@requires_models
class TestModelOutputIsNonDeterministic:
    """Every model-produced signal must be flagged non-deterministic."""

    def test_url_model_signals_are_non_deterministic(self):
        # A domain shaped like throwaway phishing infrastructure.
        signals = url_model.analyse_urls(
            ["http://secure-sbi-verify-login.xyz/account"]
        )
        for signal in signals:
            assert signal.deterministic is False, signal.code

    def test_text_model_signals_are_non_deterministic(self):
        signals = text_model.analyse_text(
            "Congratulations! You have WON a FREE prize. Call now to claim your cash."
        )
        for signal in signals:
            assert signal.deterministic is False, signal.code

    def test_no_model_signal_is_ever_critical(self):
        """CRITICAL from a model would satisfy the RED gate on its own."""
        probes = [
            "http://secure-sbi-verify-login.xyz/account",
            "http://free-prize-claim-now-winner.top/gift",
        ]
        for signal in url_model.analyse_urls(probes):
            assert signal.severity < Severity.CRITICAL
        text_signals = text_model.analyse_text(
            "WINNER! Claim your FREE cash prize now, txt STOP to opt out. Call 09061701461."
        )
        for signal in text_signals:
            assert signal.severity < Severity.CRITICAL


@requires_models
class TestModelsCannotCauseRed:
    """The containment property, exercised end to end with real models."""

    def test_model_only_message_cannot_reach_red(self):
        """Text that only a model objects to must cap at AMBER.

        Deliberately contains no APK link, no brand lookalike, no credential
        request and no risky-TLD URL, so the deterministic engine has nothing
        conclusive to say. Whatever the classifiers think, the verdict must not
        interrupt the user.
        """
        verdict = pipeline.check_message(
            MessageInput(
                text=(
                    "WINNER!! As a valued network customer you have been selected "
                    "to receive a prize reward. Call 09061701461 to claim."
                )
            )
        )
        assert verdict.band is not Band.RED
        assert verdict.red_eligible is False
        assert verdict.interrupts is False

    def test_model_signals_present_but_gate_stays_shut(self):
        verdict = pipeline.check_message(
            MessageInput(text="Claim your free cash prize at http://prize-winner-claim.top/")
        )
        model_signals = [s for s in verdict.signals if not s.deterministic]
        # If the models fired at all, they must not have opened the gate on
        # their own; any RED here has to be justified by deterministic evidence.
        if model_signals and verdict.band is Band.RED:
            deterministic = [s for s in verdict.signals if s.deterministic]
            assert any(s.severity >= Severity.HIGH for s in deterministic), (
                "RED was reached without sufficient deterministic evidence"
            )


@requires_models
class TestModelsDoNotIntroduceFalsePositives:
    """Regression tests for the cost of adding models to a working rule engine.

    Wiring the classifiers in initially turned a genuine HDFC transaction SMS
    from GREEN into AMBER, because the text model scores real bank messages at
    ~0.75: they resemble the promotional spam in the UCI corpus. Section 14.3
    treats that as the fastest way to lose the install, so the model thresholds
    were raised to the operating points where measured precision is high.
    """

    LEGITIMATE = [
        "HDFC Bank: Rs.2500 debited from a/c XX1234. Never share your OTP or PIN. "
        "https://www.hdfcbank.com",
        "Your Amazon order has been delivered. Rate your experience.",
        "OTP for your transaction is 449120. Do not share it with anyone.",
        "Beta I am reaching home by 7 pm, is dinner ready",
        "Meeting moved to 3pm tomorrow",
    ]

    # Bank and delivery messages arrive from shortcodes that are never saved as
    # contacts, so sender_known=False is the realistic case and the harder one:
    # it adds the SENDER_UNKNOWN amplifier on top of everything else.
    @pytest.mark.parametrize("text", LEGITIMATE)
    @pytest.mark.parametrize("sender_known", [True, False])
    def test_legitimate_messages_do_not_reach_amber(
        self, text: str, sender_known: bool
    ):
        verdict = pipeline.check_message(
            MessageInput(text=text, sender_known=sender_known)
        )
        assert verdict.band is Band.GREEN, (
            f"false positive (sender_known={sender_known}): {verdict.band.value} "
            f"score={verdict.score} signals={[s.code for s in verdict.signals]}"
        )

    def test_real_bank_domain_is_not_flagged_by_the_url_model(self):
        for domain in ("hdfcbank.com", "icicibank.com", "onlinesbi.sbi", "irctc.co.in"):
            probability = url_model.score_domain(domain)
            assert probability is not None
            assert probability < url_model.MIN_PROBABILITY, (
                f"{domain} scored {probability:.3f}, above the surfacing threshold"
            )


@requires_models
class TestModelsAddValue:
    """Sanity checks that the models are actually doing something."""

    def test_url_model_separates_obvious_cases(self):
        junk = url_model.score_domain("secure-verify-login-account-update.xyz")
        real = url_model.score_domain("hdfcbank.com")
        assert junk is not None and real is not None
        assert junk > real, f"junk={junk:.3f} real={real:.3f}"

    def test_text_model_separates_obvious_cases(self):
        spam = text_model.score_text(
            "URGENT! You have won a 1 week FREE membership. Call 09061701461 now!"
        )
        ham = text_model.score_text("Beta I am reaching home by 7 pm, is dinner ready")
        assert spam is not None and ham is not None
        assert spam > ham, f"spam={spam:.3f} ham={ham:.3f}"

    def test_metrics_are_recorded_with_the_artifact(self):
        """Artifacts must carry their own evaluation numbers.

        A model whose measured performance is not stored alongside it invites
        someone to quote an optimistic figure from memory.
        """
        assert "roc_auc" in url_model.model_metrics()
        text_metrics = text_model.model_metrics()
        assert "roc_auc" in text_metrics
        # The Indian-language gap is recorded deliberately; see section 12.3.
        assert "indian_scam_recall" in text_metrics
