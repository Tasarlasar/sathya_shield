package com.satyashield.app.detect

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * On-device email header forensics.
 *
 * Mirrors the backend tests/test_pillars.py email cases. The negative cases
 * matter as much as the positive: a legitimate bank email must produce nothing,
 * because a false positive here (section 14.3) costs the install.
 */
class EmailRulesTest {

    private fun codes(signals: List<Signal>) = signals.map { it.code }.toSet()

    private val PHISH = """
        From: "HDFC Bank Support" <secure.alerts@gmail.com>
        Reply-To: recovery-desk@mail.ru
        To: victim@example.com
        Subject: Your account will be blocked
        Authentication-Results: mx.example.com; spf=fail; dkim=fail; dmarc=fail

        Dear customer, your KYC has expired. Verify at http://hdfc-verify.top/login
    """.trimIndent()

    private val LEGIT = """
        From: "HDFC Bank" <alerts@hdfcbank.com>
        To: customer@example.com
        Subject: Statement ready

        Your monthly statement is ready in netbanking.
    """.trimIndent()

    @Test
    fun `looksLikeEmail distinguishes email from sms`() {
        assertTrue(EmailRules.looksLikeEmail(PHISH))
        assertTrue(EmailRules.looksLikeEmail("From: a@b.com\nSubject: hi\n\nbody"))
        assertFalse(EmailRules.looksLikeEmail("Turant paise bhejo warna account band"))
        assertFalse(EmailRules.looksLikeEmail("http://sbi-rewards.xyz/login"))
    }

    @Test
    fun `brand name from freemail is critical`() {
        val signals = EmailRules.analyse(PHISH)
        val hit = signals.first { it.code == "EMAIL_BRAND_FROM_FREEMAIL" }
        assertEquals(Severity.CRITICAL, hit.severity)
        assertTrue(hit.deterministic)
    }

    @Test
    fun `reply-to divergence detected`() {
        assertTrue(codes(EmailRules.analyse(PHISH)).contains("EMAIL_REPLY_TO_MISMATCH"))
    }

    @Test
    fun `auth headers ignored when untrusted, honoured when trusted`() {
        assertFalse(codes(EmailRules.analyse(PHISH, trustAuthHeaders = false)).contains("EMAIL_AUTH_HARD_FAIL"))
        assertTrue(codes(EmailRules.analyse(PHISH, trustAuthHeaders = true)).contains("EMAIL_AUTH_HARD_FAIL"))
        // The header-independent findings survive either way.
        assertTrue(codes(EmailRules.analyse(PHISH, trustAuthHeaders = false)).contains("EMAIL_BRAND_FROM_FREEMAIL"))
    }

    @Test
    fun `legitimate bank email produces no header signals`() {
        assertTrue(
            "false positive on legit email: ${codes(EmailRules.analyse(LEGIT))}",
            EmailRules.analyse(LEGIT).isEmpty(),
        )
    }

    @Test
    fun `sender domain lookalike detected`() {
        val raw = "From: ICICI <alerts@icici-verify.top>\nSubject: hi\n\nbody"
        assertTrue(codes(EmailRules.analyse(raw)).contains("EMAIL_SENDER_DOMAIN_LOOKALIKE"))
    }

    @Test
    fun `phishing email reaches RED end to end`() {
        // Header forensics + the body's lookalike URL together.
        val verdict = LocalRules.analyseEmail(PHISH, trustAuthHeaders = false)
        assertEquals(Band.RED, verdict.band)
        assertTrue(verdict.interrupts)
        // The raw email is carried for quoting.
        assertTrue(verdict.sourceText.contains("HDFC"))
    }

    @Test
    fun `legit email stays green end to end`() {
        val verdict = LocalRules.analyseEmail(LEGIT, trustAuthHeaders = false)
        assertEquals(Band.GREEN, verdict.band)
    }

    @Test
    fun `body extraction returns text after header block`() {
        assertTrue(EmailRules.bodyText(PHISH).contains("KYC has expired"))
    }
}
