package com.satyashield.app.detect

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * On-device rule engine tests.
 *
 * The negative cases matter at least as much as the positive ones. PRD section
 * 14.3: one wrong red alert on a genuine family video and the app is
 * uninstalled, so flagging real bank messages is a worse failure than missing a
 * scam.
 */
class LocalRulesTest {

    private fun codes(signals: List<Signal>) = signals.map { it.code }.toSet()

    // ---------------------------------------------------------------- URL ----

    @Test
    fun `apk link is critical and deterministic`() {
        val signals = LocalRules.analyseUrl("https://cdn.example.com/invite.apk")
        val apk = signals.first { it.code == "URL_APK_DOWNLOAD" }
        assertEquals(Severity.CRITICAL, apk.severity)
        assertTrue(apk.deterministic)
    }

    @Test
    fun `brand lookalike detected`() {
        assertTrue(
            codes(LocalRules.analyseUrl("http://sbi-rewards.xyz/login"))
                .contains("URL_BRAND_LOOKALIKE")
        )
    }

    @Test
    fun `real bank domains produce no signals`() {
        val clean = listOf(
            "https://onlinesbi.sbi/",
            "https://www.hdfcbank.com/",
            "https://www.icicibank.com/",
            "https://uidai.gov.in/",
            "https://www.irctc.co.in/",
        )
        clean.forEach { url ->
            assertTrue("false positive on $url", LocalRules.analyseUrl(url).isEmpty())
        }
    }

    @Test
    fun `registrable domain handles indian multi label suffixes`() {
        assertEquals("sbi.co.in", LocalRules.registrableDomain("onlinesbi.sbi.co.in"))
        assertEquals("uidai.gov.in", LocalRules.registrableDomain("resident.uidai.gov.in"))
        assertEquals("example.com", LocalRules.registrableDomain("a.b.example.com"))
    }

    @Test
    fun `userinfo obfuscation is critical`() {
        val signals = LocalRules.analyseUrl("http://sbi.co.in@evil.ru/pay")
        assertEquals(
            Severity.CRITICAL,
            signals.first { it.code == "URL_USERINFO_OBFUSCATION" }.severity,
        )
    }

    @Test
    fun `bare ip host flagged`() {
        assertTrue(codes(LocalRules.analyseUrl("http://45.9.12.7/kyc")).contains("URL_IP_HOST"))
    }

    @Test
    fun `credential path escalates only with a lookalike host`() {
        val withBrand = LocalRules.analyseUrl("http://icici-verify.top/netbanking")
            .first { it.code == "URL_CREDENTIAL_PATH" }
        val plain = LocalRules.analyseUrl("https://example.com/login")
            .first { it.code == "URL_CREDENTIAL_PATH" }
        assertEquals(Severity.HIGH, withBrand.severity)
        assertEquals(Severity.LOW, plain.severity)
    }

    @Test
    fun `legit bank homepages produce no signals`() {
        // The backend text model scored these 0.6-0.9 and pushed them to AMBER.
        // The on-device engine has no text model and its URL rules allowlist the
        // real domains, so these must be silent.
        listOf(
            "https://www.axisbank.com/",
            "https://www.icicibank.com/",
            "https://www.hdfcbank.com/personal/pay",
            "https://retail.onlinesbi.sbi/retail/login.htm",
            "https://www.irctc.co.in/",
        ).forEach { url ->
            val verdict = LocalRules.analyse(url, senderKnown = false)
            assertEquals(
                "false positive on legit bank URL: $url -> ${verdict.signals.map { it.code }}",
                Band.GREEN,
                verdict.band,
            )
        }
    }

    @Test
    fun `verdict carries the triggering message`() {
        val text = "SBI KYC expired. Verify at http://sbi-rewards.xyz/login"
        val verdict = LocalRules.analyse(text, senderKnown = false)
        assertEquals(text, verdict.sourceText)
    }

    @Test
    fun `stripUrls removes links and keeps prose`() {
        assertEquals("Pay now", LocalRules.stripUrls("Pay now https://x.top/a").trim())
        assertEquals("", LocalRules.stripUrls("https://www.axisbank.com/"))
        assertEquals("", LocalRules.stripUrls("www.icicibank.com"))
    }

    @Test
    fun `url extraction handles bare www and trailing punctuation`() {
        val found = LocalRules.extractUrls("Pay at www.sbi-verify.top/kyc or https://x.co/a.")
        assertTrue(found.contains("http://www.sbi-verify.top/kyc"))
        assertTrue(found.contains("https://x.co/a"))
    }

    // --------------------------------------------------------------- UPI ----

    @Test
    fun `upi handle from unknown sender flagged but not from a contact`() {
        val text = "send to ramesh@okhdfcbank"
        assertTrue(LocalRules.analyseUpi(text, senderKnown = false).isNotEmpty())
        assertTrue(LocalRules.analyseUpi(text, senderKnown = true).isEmpty())
    }

    @Test
    fun `plain email address is not treated as a upi handle`() {
        assertTrue(LocalRules.analyseUpi("mail me at a.b@gmail.com", false).isEmpty())
    }

    // -------------------------------------------------------------- TEXT ----

    @Test
    fun `credential request detected`() {
        assertTrue(LocalRules.isCredentialRequest("Please share the OTP to verify"))
    }

    @Test
    fun `bank otp warning is not a credential request`() {
        // Without negation handling this fires on a large share of real bank SMS.
        assertFalse(
            LocalRules.isCredentialRequest("HDFC Bank: Never share your OTP or PIN with anyone.")
        )
        assertFalse(LocalRules.isCredentialRequest("Do not share your OTP with anyone"))
        assertFalse(LocalRules.isCredentialRequest("Don't share the OTP"))
    }

    @Test
    fun `digital arrest pattern is high`() {
        val verdict = LocalRules.analyse(
            "This is CBI cyber cell. Arrest warrant issued. Pay penalty immediately " +
                "or legal action will follow."
        )
        assertTrue(codes(verdict.signals).contains("TEXT_DIGITAL_ARREST_PATTERN"))
    }

    @Test
    fun `hinglish scam is detected`() {
        val verdict = LocalRules.analyse(
            "Turant paise bhejo warna account band kar diya jayega. KYC pending hai."
        )
        assertTrue(verdict.signals.isNotEmpty())
    }

    @Test
    fun `devanagari scam is detected`() {
        val verdict = LocalRules.analyse("तुरंत पैसे भेजो वरना खाता बंद कर दिया जाएगा")
        assertTrue(verdict.signals.isNotEmpty())
    }

    @Test
    fun `benign family message is green`() {
        listOf(
            "Hi beta, reaching home by 7pm. Dinner ready?",
            "Meeting moved to 3pm tomorrow.",
            "Happy birthday! Have a great year ahead.",
        ).forEach { text ->
            val verdict = LocalRules.analyse(text, senderKnown = true)
            assertEquals("false positive on: $text", Band.GREEN, verdict.band)
        }
    }

    @Test
    fun `real bank sms produces no signals at all`() {
        // Asserting GREEN rather than merely "does not interrupt". The backend
        // has the same expectation in tests/test_models.py, and the two engines
        // must agree: the same message may be judged on-device or server-side,
        // and a user must never see the two disagree.
        //
        // sender_known=false is the realistic case: bank shortcodes are never
        // saved as contacts.
        listOf(
            "HDFC Bank: Rs.2,500 debited from a/c XX1234. Never share your OTP or PIN. " +
                "Visit https://www.hdfcbank.com",
            "OTP for your transaction is 449120. Do not share it with anyone.",
            "Your Amazon order has been delivered. Rate your experience.",
        ).forEach { text ->
            val verdict = LocalRules.analyse(text, senderKnown = false)
            assertEquals(
                "false positive on legitimate message: $text -> ${verdict.signals.map { it.code }}",
                Band.GREEN,
                verdict.band,
            )
            assertFalse(verdict.interrupts)
        }
    }

    @Test
    fun `no text signal is ever critical`() {
        val aggressive = "URGENT! CBI police arrest warrant! Pay penalty now! " +
            "Share OTP immediately! You won lottery! KYC expired!"
        val textSignals = LocalRules.analyse(aggressive).signals
            .filter { it.pillar == Pillar.TEXT }
        assertTrue(textSignals.isNotEmpty())
        textSignals.forEach {
            assertTrue(
                "${it.code} must not be CRITICAL: language alone cannot interrupt",
                it.severity.value < Severity.CRITICAL.value,
            )
        }
    }

    // ------------------------------------------------------- END TO END ----

    @Test
    fun `self test sample produces a red verdict`() {
        // The setup flow's credibility depends on this specific string tripping
        // a deterministic CRITICAL rule.
        val verdict = LocalRules.analyse(
            "SBI KYC expired. Verify urgently at http://sbi-rewards.xyz/netbanking/login " +
                "and install http://update-sbi.top/app.apk to continue."
        )
        assertEquals(Band.RED, verdict.band)
        assertTrue(verdict.redEligible)
        assertTrue(verdict.interrupts)
    }

    @Test
    fun `media placeholder is detected for the one tap prompt`() {
        assertTrue(LocalRules.looksLikeMedia("photo"))
        assertTrue(LocalRules.looksLikeMedia("sent you a video"))
        assertFalse(LocalRules.looksLikeMedia("see you tomorrow"))
    }
}
