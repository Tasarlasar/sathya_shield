"""Tests for the individual detection pillars.

Beyond checking that scams are caught, these tests assert the inverse: that
ordinary legitimate content produces no signals. Section 14.3 argues false
positives destroy this product faster than false negatives, so the negative
cases matter at least as much.
"""

from __future__ import annotations

from app.pillars import email_headers, text_intent, url_rules
from app.schemas import Severity


def codes(signals) -> set[str]:
    return {s.code for s in signals}


# ==========================================================================
# URL pillar
# ==========================================================================


class TestUrlRules:
    def test_apk_link_is_critical(self):
        signals = url_rules.analyse_url("https://cdn.example.com/invite.apk")
        apk = [s for s in signals if s.code == "URL_APK_DOWNLOAD"]
        assert apk and apk[0].severity is Severity.CRITICAL
        assert apk[0].deterministic is True

    def test_brand_lookalike_detected(self):
        signals = url_rules.analyse_url("http://sbi-rewards.xyz/login")
        assert "URL_BRAND_LOOKALIKE" in codes(signals)

    def test_legitimate_bank_domain_is_clean(self):
        """The allowlist must stop us flagging the real thing."""
        for url in (
            "https://onlinesbi.sbi/",
            "https://www.hdfcbank.com/",
            "https://www.icicibank.com/",
            "https://uidai.gov.in/",
            "https://www.irctc.co.in/",
        ):
            assert url_rules.analyse_url(url) == [], f"false positive on {url}"

    def test_userinfo_obfuscation_is_critical(self):
        signals = url_rules.analyse_url("http://sbi.co.in@evil.ru/pay")
        obf = [s for s in signals if s.code == "URL_USERINFO_OBFUSCATION"]
        assert obf and obf[0].severity is Severity.CRITICAL

    def test_ip_host_flagged(self):
        assert "URL_IP_HOST" in codes(url_rules.analyse_url("http://45.9.12.7/kyc"))

    def test_punycode_flagged(self):
        assert "URL_PUNYCODE_HOST" in codes(
            url_rules.analyse_url("https://xn--sb-tka.com/")
        )

    def test_shortener_flagged(self):
        assert "URL_SHORTENER" in codes(url_rules.analyse_url("https://bit.ly/3xY"))

    def test_credential_path_escalates_with_brand(self):
        with_brand = url_rules.analyse_url("http://icici-verify.top/netbanking")
        plain = url_rules.analyse_url("https://example.com/login")

        cred_brand = next(s for s in with_brand if s.code == "URL_CREDENTIAL_PATH")
        cred_plain = next(s for s in plain if s.code == "URL_CREDENTIAL_PATH")

        assert cred_brand.severity is Severity.HIGH
        assert cred_plain.severity is Severity.LOW

    def test_url_extraction(self):
        text = "Pay at www.sbi-verify.top/kyc or https://x.co/a. Thanks!"
        found = url_rules.extract_urls(text)
        assert "http://www.sbi-verify.top/kyc" in found
        assert "https://x.co/a" in found

    def test_trailing_punctuation_stripped(self):
        assert url_rules.extract_urls("go to https://example.com/x.") == [
            "https://example.com/x"
        ]

    def test_upi_handle_detected_but_email_is_not(self):
        handles = url_rules.extract_upi_handles(
            "send to ramesh@okhdfcbank, mail me at a.b@gmail.com"
        )
        assert handles == ["ramesh@okhdfcbank"]

    def test_upi_from_known_sender_is_not_flagged(self):
        text = "pay ramesh@okhdfcbank"
        assert url_rules.analyse_upi(text, sender_known=True) == []
        assert url_rules.analyse_upi(text, sender_known=False)

    def test_brand_word_boundary_avoids_false_positive(self):
        """`trai` must not match inside `straight`."""
        assert url_rules.brand_tokens_in_display_name("Straight Talk Ltd") == []
        assert "trai" in url_rules.brand_tokens_in_display_name("TRAI Notice")

    def test_run_together_brand_name_still_matches(self):
        assert "hdfc" in url_rules.brand_tokens_in_display_name("HDFCBank Alerts")


# ==========================================================================
# Email pillar
# ==========================================================================

PHISH_EMAIL = """From: "HDFC Bank Support" <secure.alerts@gmail.com>
Reply-To: recovery-desk@mail.ru
To: victim@example.com
Subject: Your account will be blocked
Authentication-Results: mx.example.com; spf=fail; dkim=fail; dmarc=fail
Content-Type: text/plain

Dear customer, your KYC has expired. Verify at http://hdfc-verify.top/login
"""

LEGIT_EMAIL = """From: "HDFC Bank" <alerts@hdfcbank.com>
To: customer@example.com
Subject: Statement ready
Received: from mx.hdfcbank.com (mx.hdfcbank.com [1.2.3.4]) by mx.example.com
Authentication-Results: mx.example.com; spf=pass; dkim=pass; dmarc=pass
Content-Type: text/plain

Your monthly statement is ready in netbanking.
"""


class TestEmailHeaders:
    def test_brand_from_freemail_is_critical(self):
        signals = email_headers.analyse_email(PHISH_EMAIL)
        hit = [s for s in signals if s.code == "EMAIL_BRAND_FROM_FREEMAIL"]
        assert hit and hit[0].severity is Severity.CRITICAL

    def test_auth_hard_fail_detected(self):
        assert "EMAIL_AUTH_HARD_FAIL" in codes(email_headers.analyse_email(PHISH_EMAIL))

    def test_reply_to_mismatch_detected(self):
        assert "EMAIL_REPLY_TO_MISMATCH" in codes(
            email_headers.analyse_email(PHISH_EMAIL)
        )

    def test_legitimate_email_produces_no_signals(self):
        assert email_headers.analyse_email(LEGIT_EMAIL) == []

    def test_auth_headers_ignored_when_untrusted(self):
        """User-pasted headers are attacker-controllable and must not be believed."""
        trusted = codes(email_headers.analyse_email(PHISH_EMAIL, trust_auth_headers=True))
        untrusted = codes(
            email_headers.analyse_email(PHISH_EMAIL, trust_auth_headers=False)
        )
        assert "EMAIL_AUTH_HARD_FAIL" in trusted
        assert "EMAIL_AUTH_HARD_FAIL" not in untrusted
        # The header-independent findings must survive.
        assert "EMAIL_BRAND_FROM_FREEMAIL" in untrusted

    def test_executable_attachment_is_critical(self):
        raw = (
            'From: x@y.com\nTo: v@e.com\nSubject: invoice\n'
            'Content-Type: application/octet-stream; name="invoice.exe"\n'
            'Content-Disposition: attachment; filename="invoice.exe"\n\ndata\n'
        )
        hit = [
            s
            for s in email_headers.analyse_email(raw)
            if s.code == "EMAIL_ATTACHMENT_EXECUTABLE"
        ]
        assert hit and hit[0].severity is Severity.CRITICAL

    def test_double_extension_is_critical(self):
        raw = (
            'From: x@y.com\nTo: v@e.com\nSubject: doc\n'
            'Content-Disposition: attachment; filename="statement.pdf.scr"\n\ndata\n'
        )
        assert "EMAIL_ATTACHMENT_DOUBLE_EXTENSION" in codes(
            email_headers.analyse_email(raw)
        )

    def test_address_in_display_name_flagged(self):
        raw = (
            'From: "support@hdfcbank.com" <attacker@evil.ru>\n'
            "To: v@e.com\nSubject: hi\n\nbody\n"
        )
        assert "EMAIL_ADDRESS_IN_DISPLAY_NAME" in codes(
            email_headers.analyse_email(raw)
        )

    def test_body_extraction(self):
        body = email_headers.email_body_text(PHISH_EMAIL)
        assert "KYC has expired" in body

    def test_empty_input_is_safe(self):
        assert email_headers.analyse_email("") == []
        assert email_headers.email_body_text("") == ""


# ==========================================================================
# Text pillar
# ==========================================================================


class TestTextIntent:
    def test_digital_arrest_pattern(self):
        text = (
            "This is CBI cyber cell. An arrest warrant has been issued against you. "
            "Pay penalty immediately or legal action will follow."
        )
        hit = [
            s
            for s in text_intent.analyse_text(text)
            if s.code == "TEXT_DIGITAL_ARREST_PATTERN"
        ]
        assert hit and hit[0].severity is Severity.HIGH

    def test_credential_request_detected(self):
        assert "TEXT_CREDENTIAL_REQUEST" in codes(
            text_intent.analyse_text("Please share the OTP to complete verification")
        )

    def test_bank_otp_warning_is_not_a_request(self):
        """`never share your OTP` is legitimate and must not fire the rule.

        Without negation handling this single case would generate false
        positives on a large share of real bank messages.
        """
        signals = text_intent.analyse_text(
            "HDFC Bank: Never share your OTP or PIN with anyone."
        )
        assert "TEXT_CREDENTIAL_REQUEST" not in codes(signals)

    def test_negation_variants(self):
        for phrase in (
            "Do not share your OTP with anyone",
            "Bank will never ask you to share OTP",
            "Don't share the OTP",
        ):
            assert "TEXT_CREDENTIAL_REQUEST" not in codes(
                text_intent.analyse_text(phrase)
            ), phrase

    def test_advance_fee_pattern(self):
        assert "TEXT_ADVANCE_FEE_PATTERN" in codes(
            text_intent.analyse_text(
                "Congratulations you won lottery! Pay processing fee to claim your prize."
            )
        )

    def test_hinglish_is_handled(self):
        signals = text_intent.analyse_text(
            "Turant paise bhejo warna account band kar diya jayega. KYC pending hai."
        )
        assert codes(signals) & {"TEXT_URGENT_MONEY_REQUEST", "TEXT_KYC_PRESSURE"}

    def test_devanagari_is_handled(self):
        signals = text_intent.analyse_text(
            "तुरंत पैसे भेजो वरना खाता बंद कर दिया जाएगा"
        )
        assert signals, "expected Devanagari scam text to produce signals"

    def test_benign_message_produces_nothing(self):
        for text in (
            "Hi beta, reaching home by 7pm. Dinner ready?",
            "Meeting moved to 3pm tomorrow.",
            "Happy birthday! Have a great year ahead.",
        ):
            assert text_intent.analyse_text(text) == [], f"false positive on: {text}"

    def test_no_text_signal_is_critical(self):
        """Language alone must never authorise a red alert."""
        aggressive = (
            "URGENT! CBI police arrest warrant! Pay penalty now! Share OTP "
            "immediately! You won lottery! KYC expired! Account will be blocked!"
        )
        for signal in text_intent.analyse_text(aggressive):
            assert signal.severity < Severity.CRITICAL, signal.code

    def test_unknown_sender_amplifier_only_with_other_signals(self):
        assert text_intent.analyse_text("hello there", sender_known=False) == []
        signals = text_intent.analyse_text("share the OTP now", sender_known=False)
        assert "SENDER_UNKNOWN" in codes(signals)

    def test_model_score_is_non_deterministic(self):
        signal = text_intent.attach_model_score(0.99)
        assert signal.deterministic is False
        assert signal.severity is Severity.HIGH
