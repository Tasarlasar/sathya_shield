"""End-to-end pipeline, explanation and API tests."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app import explain, pipeline
from app.main import app
from app.schemas import Band, Language, MessageInput, Source

client = TestClient(app)


# ==========================================================================
# Explanation layer
# ==========================================================================


class TestExplanations:
    def test_every_signal_code_is_translated_in_all_languages(self):
        """A missing translation must fail the build, not silently show English."""
        gaps = explain.check_coverage()
        assert gaps == {}, f"untranslated signal codes: {gaps}"

    def test_all_emitted_codes_have_templates(self):
        """Any code a pillar can emit must have an explanation entry.

        Catches the case where a new rule is added without user-facing text,
        which would otherwise produce a verdict with no visible reason.
        """
        from app.pillars import email_headers, text_intent, url_rules

        emitted: set[str] = set()
        samples = [
            "http://sbi-rewards.xyz/login",
            "http://45.9.12.7/kyc",
            "https://cdn.x.com/a.apk",
            "http://sbi.co.in@evil.ru/x",
            "https://xn--sb-tka.com/verify",
            "https://bit.ly/x",
            "http://a.b.c.d.e.example.com/",
        ]
        for url in samples:
            emitted |= {s.code for s in url_rules.analyse_url(url)}
        emitted |= {
            s.code for s in url_rules.analyse_upi("pay a@okaxis", sender_known=False)
        }

        emails = [
            'From: "HDFC Bank" <x@gmail.com>\nReply-To: y@mail.ru\n'
            "Return-Path: <z@sendgrid.net>\nSubject: s\n"
            "Authentication-Results: mx; spf=fail; dkim=fail\n\nbody\n",
            'From: "support@hdfcbank.com" <a@evil.ru>\nSubject: s\n'
            'Content-Disposition: attachment; filename="x.pdf.exe"\n\nb\n',
            'From: a@b.com\nSubject: s\nContent-Disposition: attachment; '
            'filename="m.docm"\n\nb\n',
            'From: a@b.com\nSubject: s\nContent-Disposition: attachment; '
            'filename="p.html"\n\nb\n',
            "Subject: no from header\n\nbody\n",
        ]
        for raw in emails:
            emitted |= {s.code for s in email_headers.analyse_email(raw)}

        texts = [
            "CBI police arrest warrant, pay penalty immediately",
            "share the OTP now",
            "you won lottery, pay processing fee to claim your prize",
            "turant paise bhejo, KYC pending, account will be blocked",
            "work from home earn daily, pay registration fee",
            "your otp is 123456",
        ]
        for text in texts:
            emitted |= {s.code for s in text_intent.analyse_text(text)}
        emitted.add(text_intent.attach_model_score(0.9).code)

        missing = sorted(
            code for code in emitted if explain._REASONS.get(code) is None
        )
        assert missing == [], f"signal codes with no explanation template: {missing}"

    @pytest.mark.parametrize("language", list(Language))
    def test_verdict_explained_in_every_language(self, language: Language):
        verdict = pipeline.check_message(
            MessageInput(
                text="Download update from http://sbi-secure.top/app.apk",
                language=language,
            )
        )
        assert verdict.explanation.language is language
        assert verdict.explanation.headline
        assert verdict.explanation.action
        assert verdict.explanation.reasons
        assert verdict.explanation.spoken

    def test_no_banned_jargon_in_user_facing_text(self):
        """PRD section 8.4 bans security jargon from user-facing output."""
        banned = (
            "phishing", "deepfake", "url", "malicious", "vishing",
            "credential", "authenticate",
        )
        offenders: list[tuple[str, str]] = []
        for code, entry in explain._REASONS.items():
            text = (entry.get(Language.EN) or "").lower()
            for word in banned:
                if word in text:
                    offenders.append((code, word))
        assert offenders == [], f"banned jargon in explanations: {offenders}"

    def test_reasons_are_capped(self):
        verdict = pipeline.check_message(
            MessageInput(
                text=(
                    "URGENT CBI arrest warrant! Pay penalty at "
                    "http://sbi-verify.top/netbanking/login and install "
                    "http://x.co/a.apk and share your OTP now! You won lottery!"
                )
            )
        )
        assert len(verdict.explanation.reasons) <= explain.MAX_REASONS

    def test_media_prompt_appended(self):
        verdict = pipeline.check_message(
            MessageInput(text="see this", has_media=True, language=Language.HI)
        )
        assert verdict.media_present is True
        assert any("वीडियो" in r for r in verdict.explanation.reasons)


# ==========================================================================
# Pipeline
# ==========================================================================


class TestPipeline:
    def test_apk_message_is_red(self):
        verdict = pipeline.check_message(
            MessageInput(text="Wedding invite: http://shaadi-card.xyz/invite.apk")
        )
        assert verdict.band is Band.RED
        assert verdict.red_eligible is True
        assert verdict.interrupts is True

    def test_phishing_email_is_red(self):
        raw = (
            'From: "ICICI Bank" <alerts@gmail.com>\n'
            "Reply-To: x@mail.ru\nTo: v@e.com\nSubject: blocked\n"
            "Authentication-Results: mx; spf=fail; dkim=fail; dmarc=fail\n\n"
            "Your account will be blocked. Verify at http://icici-kyc.top/login\n"
        )
        verdict = pipeline.check_email(raw)
        assert verdict.band is Band.RED

    def test_benign_message_is_green(self):
        verdict = pipeline.check_message(
            MessageInput(text="Beta, I reached home safely. Call when free.")
        )
        assert verdict.band is Band.GREEN
        assert verdict.score == 0.0
        assert verdict.explanation.reasons == []

    def test_legitimate_bank_sms_is_not_red(self):
        """A real bank message must not interrupt the user."""
        verdict = pipeline.check_message(
            MessageInput(
                text=(
                    "HDFC Bank: Rs.2,500 debited from a/c XX1234. "
                    "Never share your OTP or PIN. Visit https://www.hdfcbank.com"
                ),
                sender_known=True,
            )
        )
        assert verdict.band is not Band.RED
        assert verdict.interrupts is False

    def test_suspicious_but_unproven_lands_on_amber(self):
        verdict = pipeline.check_message(
            MessageInput(text="Claim your reward here https://bit.ly/x3Yz")
        )
        assert verdict.band is Band.AMBER

    def test_email_body_reaches_text_pillar(self):
        raw = (
            "From: a@b.com\nTo: v@e.com\nSubject: hi\n\n"
            "Please share the OTP sent to your phone.\n"
        )
        verdict = pipeline.check_email(raw)
        assert "TEXT_CREDENTIAL_REQUEST" in {s.code for s in verdict.signals}

    def test_pasted_email_does_not_trust_auth_headers(self):
        raw = (
            "From: a@b.com\nSubject: hi\n"
            "Authentication-Results: mx; spf=fail; dkim=fail\n\nbody\n"
        )
        trusted = pipeline.check_email(raw, trusted_source=True)
        pasted = pipeline.check_email(raw, trusted_source=False)
        codes_trusted = {s.code for s in trusted.signals}
        codes_pasted = {s.code for s in pasted.signals}
        assert "EMAIL_AUTH_HARD_FAIL" in codes_trusted
        assert "EMAIL_AUTH_HARD_FAIL" not in codes_pasted

    def test_signals_are_ranked_most_severe_first(self):
        verdict = pipeline.check_message(
            MessageInput(text="install http://sbi-x.xyz/a.apk and share OTP urgently")
        )
        severities = [int(s.severity) for s in verdict.signals]
        assert severities == sorted(severities, reverse=True)

    def test_empty_input_is_green_not_an_error(self):
        verdict = pipeline.check_message(MessageInput(text=""))
        assert verdict.band is Band.GREEN


# ==========================================================================
# API
# ==========================================================================


class TestApi:
    def test_health(self):
        response = client.get("/health")
        assert response.status_code == 200
        assert response.json()["status"] == "ok"

    def test_check_message_endpoint(self):
        response = client.post(
            "/check/message",
            json={
                "text": "Install http://sbi-rewards.xyz/update.apk now",
                "sender_known": False,
                "source": Source.NOTIFICATION.value,
                "language": "hi",
            },
        )
        assert response.status_code == 200
        body = response.json()
        assert body["band"] == "red"
        assert body["red_eligible"] is True
        assert body["explanation"]["language"] == "hi"
        assert body["explanation"]["spoken"]

    def test_check_url_endpoint(self):
        response = client.post(
            "/check/url", json={"url": "http://icici-verify.top/netbanking"}
        )
        assert response.status_code == 200
        assert response.json()["band"] in {"amber", "red"}

    def test_check_url_rejects_empty(self):
        assert client.post("/check/url", json={"url": ""}).status_code == 422

    def test_check_email_endpoint(self):
        response = client.post(
            "/check/email",
            json={
                "raw_email": (
                    'From: "SBI" <x@gmail.com>\nSubject: kyc\n'
                    "Authentication-Results: mx; spf=fail; dkim=fail\n\n"
                    "Verify now at http://sbi-kyc.top/login\n"
                ),
                "language": "ta",
            },
        )
        assert response.status_code == 200
        body = response.json()
        assert body["band"] == "red"
        assert body["explanation"]["language"] == "ta"

    def test_long_text_is_truncated_not_rejected(self):
        response = client.post(
            "/check/message", json={"text": "hello " * 10_000}
        )
        assert response.status_code == 200

    def test_openapi_schema_available(self):
        assert client.get("/openapi.json").status_code == 200
