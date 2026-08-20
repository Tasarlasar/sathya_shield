package com.satyashield.app.detect

import com.satyashield.app.R

/**
 * On-device deterministic rule engine.
 *
 * PRD v3.0 section 11.2: the cheap tier runs entirely on the phone. That is not
 * only a latency choice, it is what makes the privacy claim true. Passively
 * captured message text is judged here and never leaves the device; the network
 * is used only for the deeper server-side pillars, and only on explicit user
 * action.
 *
 * This is a subset of the backend's rules, carrying the high-precision ones that
 * can raise a RED verdict. Anything requiring a network round trip (WHOIS domain
 * age, blocklists, page fetch) stays server-side by design.
 *
 * Every signal produced here is deterministic. There is no model in this file.
 */
object LocalRules {

    /**
     * Indian brand tokens mapped to the registrable domains that legitimately
     * own them. The allowlist is what keeps the lookalike rule precise enough
     * to be RED-eligible: without it we would flag the real bank too.
     */
    private val BRAND_DOMAINS: Map<String, Set<String>> = mapOf(
        "sbi" to setOf("sbi.co.in", "onlinesbi.sbi", "sbi", "sbicard.com"),
        "hdfc" to setOf("hdfcbank.com", "hdfc.com", "hdfclife.com"),
        "icici" to setOf("icicibank.com", "icicidirect.com", "icicilombard.com"),
        "axis" to setOf("axisbank.com", "axisbank.co.in"),
        "kotak" to setOf("kotak.com"),
        "pnb" to setOf("pnbindia.in", "netpnb.com"),
        "canara" to setOf("canarabank.com", "canarabank.in"),
        "npci" to setOf("npci.org.in"),
        "upi" to setOf("npci.org.in", "bhimupi.org.in"),
        "irctc" to setOf("irctc.co.in", "irctc.com"),
        "indiapost" to setOf("indiapost.gov.in"),
        "aadhaar" to setOf("uidai.gov.in"),
        "uidai" to setOf("uidai.gov.in"),
        "trai" to setOf("trai.gov.in"),
        "epfo" to setOf("epfindia.gov.in"),
        "paytm" to setOf("paytm.com", "paytmbank.com"),
        "phonepe" to setOf("phonepe.com"),
        "digilocker" to setOf("digilocker.gov.in"),
        "incometax" to setOf("incometax.gov.in", "incometaxindia.gov.in"),
    )

    private val RISKY_TLDS = setOf(
        "xyz", "top", "tk", "ml", "ga", "cf", "gq", "buzz", "click", "link",
        "work", "fit", "loan", "win", "bid", "review", "stream", "download",
        "racing", "party", "rest", "icu", "cyou", "sbs", "quest", "monster",
        "cam", "surf", "online", "site", "website", "shop",
    )

    private val SHORTENERS = setOf(
        "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
        "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy", "tiny.cc", "bl.ink",
        "t.ly", "short.io", "surl.li", "clck.ru", "v.gd", "s.id", "adf.ly",
        "wa.link",
    )

    private val UPI_PSP = setOf(
        "ybl", "okaxis", "oksbi", "okhdfcbank", "okicici", "paytm", "apl", "axl",
        "ibl", "upi", "airtel", "freecharge", "jio", "sbi", "hdfcbank", "icici",
        "axisbank", "kotak", "yesbank", "idfcbank", "indus", "barodampay",
    )

    private val SENSITIVE_PATH_TOKENS = setOf(
        "login", "signin", "verify", "verification", "kyc", "update", "secure",
        "account", "netbanking", "otp", "wallet", "payment", "pay", "refund",
        "reward", "prize", "claim", "unblock", "reactivate", "confirm",
        "password", "pin", "card", "cvv", "billdesk",
    )

    // Two-label public suffixes we care about, so `sbi.co.in` resolves to
    // itself rather than to `co.in`. A full public-suffix list is overkill on
    // device; this covers the Indian and common global cases we key rules on.
    private val MULTI_LABEL_SUFFIXES = setOf(
        "co.in", "gov.in", "org.in", "net.in", "ac.in", "res.in", "nic.in",
        "firm.in", "gen.in", "ind.in", "co.uk", "org.uk", "com.au", "co.jp",
    )

    private val URL_REGEX = Regex(
        """(?:https?://|www\.)[^\s<>"'\[\]{}|\\^`]+""",
        RegexOption.IGNORE_CASE,
    )

    private val UPI_REGEX = Regex(
        """\b([a-z0-9][a-z0-9._-]{1,64})@(${UPI_PSP.joinToString("|")})\b(?!\.)""",
        RegexOption.IGNORE_CASE,
    )

    private val APK_REGEX = Regex("""\.apk(?:$|[?#/])""", RegexOption.IGNORE_CASE)

    private val CREDENTIAL_REQUEST_REGEX = Regex(
        """(share|send|sent|give|tell|forward|provide|submit|enter|confirm)""" +
            """(?:\s+(?:me|us|your|the|this|that|it))*""" +
            """\s+(otp|one[\s-]?time[\s-]?password|pin|cvv|password)""",
        RegexOption.IGNORE_CASE,
    )

    private val NEGATION_REGEX = Regex(
        """\b(never|not|dont|don't|do not|avoid|kabhi nahi|mat|nahi)\b""",
        RegexOption.IGNORE_CASE,
    )

    private const val NEGATION_WINDOW = 45

    // Scam-script vocabulary. Hand-authored per language, including
    // Roman-script Hinglish and Devanagari, because Indian scam SMS mixes
    // scripts inside a single message.
    private val URGENCY = listOf(
        "urgent", "immediately", "last warning", "final notice", "expires today",
        "act now", "within 24 hours", "turant", "abhi", "jaldi", "तुरंत", "अभी",
        "जल्दी", "உடனே", "அவசரம்",
    )
    private val PAYMENT = listOf(
        "send money", "transfer", "pay now", "make payment", "processing fee",
        "registration fee", "penalty", "fine", "customs duty", "scan qr",
        "paise bhejo", "paisa bhej", "पैसे भेजो", "भुगतान", "शुल्क",
        "பணம் அனுப்ப", "கட்டணம்",
    )
    private val CREDENTIAL = listOf(
        "otp", "one time password", "cvv", "atm pin", "netbanking password",
        "aadhaar number", "ओटीपी", "पिन", "पासवर्ड", "ஓடிபி",
    )
    private val AUTHORITY = listOf(
        "police", "cbi", "customs department", "income tax department",
        "enforcement directorate", "cyber cell", "cyber crime", "court notice",
        "arrest warrant", "warrant", "legal notice", "giraftari",
        "पुलिस", "गिरफ्तारी", "अदालत", "वारंट", "காவல்", "நீதிமன்றம்",
    )
    private val PRIZE = listOf(
        "you have won", "you won", "lucky winner", "lottery", "jackpot",
        "prize money", "lucky draw", "claim your prize", "claim your reward",
        "इनाम", "लॉटरी", "बधाई हो", "பரிசு",
    )
    private val KYC = listOf(
        "kyc", "complete your kyc", "kyc expired", "verify your account",
        "account will be blocked", "account has been suspended",
        "reactivate your account", "sim will be blocked",
        "खाता बंद", "केवाईसी", "கணக்கு முடக்கம்",
    )
    private val THREAT = listOf(
        "legal action", "you will be arrested", "arrest you",
        "case registered", "will be blocked", "will be suspended",
        "non-bailable", "kanooni karyavahi", "band kar diya jayega",
        "कानूनी कार्रवाई", "गिरफ्तार", "சட்ட நடவடிக்கை",
    )
    private val JOB = listOf(
        "work from home", "part time job", "earn daily", "daily income",
        "easy money", "ghar baithe kamao", "घर बैठे कमाओ",
    )

    /** Media placeholders WhatsApp and SMS clients put in notification text. */
    private val MEDIA_PLACEHOLDERS = listOf(
        "photo", "video", "audio", "voice message", "document", "sticker", "gif",
        "\uD83D\uDCF7", "\uD83C\uDFA5", "\uD83C\uDFA4",
    )

    // ----------------------------------------------------------------------
    // Public API
    // ----------------------------------------------------------------------

    /** Analyse a message entirely on-device. Returns in well under 100ms. */
    fun analyse(text: String, senderKnown: Boolean = false): LocalVerdict {
        val signals = mutableListOf<Signal>()
        val lower = text.lowercase()

        extractUrls(text).forEach { signals += analyseUrl(it) }
        signals += analyseUpi(text, senderKnown)
        signals += analyseText(text, lower, senderKnown)

        return Fusion.decide(signals, mediaPresent = looksLikeMedia(lower))
    }

    fun extractUrls(text: String): List<String> =
        URL_REGEX.findAll(text)
            .map { it.value.trimEnd('.', ',', ';', ':', '!', '?', ')') }
            .map { if (it.lowercase().startsWith("www.")) "http://$it" else it }
            .distinct()
            .toList()

    fun looksLikeMedia(lowerText: String): Boolean =
        MEDIA_PLACEHOLDERS.any { lowerText.contains(it) }

    // ----------------------------------------------------------------------
    // URL rules
    // ----------------------------------------------------------------------

    fun analyseUrl(rawUrl: String): List<Signal> {
        val signals = mutableListOf<Signal>()
        val url = if (rawUrl.contains("://")) rawUrl else "http://$rawUrl"

        val authority = url.substringAfter("://").substringBefore('/')
        val host = authority.substringAfterLast('@').substringBefore(':').lowercase()
        if (host.isEmpty()) return signals

        val pathAndQuery = url.substringAfter("://")
            .substringAfter('/', "")
            .lowercase()
        val registrable = registrableDomain(host)

        if (APK_REGEX.containsMatchIn(url)) {
            signals += Signal(
                code = "URL_APK_DOWNLOAD",
                pillar = Pillar.URL,
                severity = Severity.CRITICAL,
                deterministic = true,
                weight = 1.5f,
                reasonRes = R.string.reason_apk,
            )
        }

        if (authority.contains('@')) {
            signals += Signal(
                code = "URL_USERINFO_OBFUSCATION",
                pillar = Pillar.URL,
                severity = Severity.CRITICAL,
                deterministic = true,
                weight = 1.3f,
                reasonRes = R.string.reason_userinfo,
            )
        }

        if (host.matches(Regex("""\d{1,3}(\.\d{1,3}){3}"""))) {
            signals += Signal(
                code = "URL_IP_HOST",
                pillar = Pillar.URL,
                severity = Severity.HIGH,
                deterministic = true,
                weight = 1.2f,
                reasonRes = R.string.reason_ip_host,
            )
        }

        if (host.contains("xn--")) {
            signals += Signal(
                code = "URL_PUNYCODE_HOST",
                pillar = Pillar.URL,
                severity = Severity.HIGH,
                deterministic = true,
                weight = 1.2f,
                reasonRes = R.string.reason_punycode,
            )
        }

        val brands = brandLookalikes(host, registrable)
        if (brands.isNotEmpty()) {
            signals += Signal(
                code = "URL_BRAND_LOOKALIKE",
                pillar = Pillar.URL,
                severity = Severity.HIGH,
                deterministic = true,
                weight = 1.4f,
                reasonRes = R.string.reason_brand,
                reasonArg = brands.first().uppercase(),
            )
        }

        if (registrable in SHORTENERS) {
            signals += Signal(
                code = "URL_SHORTENER",
                pillar = Pillar.URL,
                severity = Severity.MEDIUM,
                deterministic = true,
                reasonRes = R.string.reason_shortener,
            )
        }

        if (suffixOf(host) in RISKY_TLDS) {
            signals += Signal(
                code = "URL_RISKY_TLD",
                pillar = Pillar.URL,
                severity = Severity.LOW,
                deterministic = true,
                reasonRes = R.string.reason_risky_tld,
            )
        }

        val tokens = pathAndQuery.split(Regex("""[^a-z0-9]+""")).filter { it.isNotEmpty() }
        if (tokens.any { it in SENSITIVE_PATH_TOKENS }) {
            // A credential path is ordinary on its own; paired with a lookalike
            // host it is what a real harvest page looks like.
            signals += Signal(
                code = "URL_CREDENTIAL_PATH",
                pillar = Pillar.URL,
                severity = if (brands.isNotEmpty()) Severity.HIGH else Severity.LOW,
                deterministic = true,
                reasonRes = R.string.reason_credential_path,
            )
        }

        if (url.startsWith("http://")) {
            signals += Signal(
                code = "URL_NO_TLS",
                pillar = Pillar.URL,
                severity = Severity.LOW,
                deterministic = true,
                reasonRes = R.string.reason_no_tls,
            )
        }

        return signals
    }

    fun registrableDomain(host: String): String {
        val labels = host.split('.').filter { it.isNotEmpty() }
        if (labels.size <= 2) return host
        val lastTwo = labels.takeLast(2).joinToString(".")
        return if (lastTwo in MULTI_LABEL_SUFFIXES) {
            labels.takeLast(3).joinToString(".")
        } else {
            lastTwo
        }
    }

    private fun suffixOf(host: String): String = host.substringAfterLast('.', "")

    fun brandLookalikes(host: String, registrable: String): List<String> =
        BRAND_DOMAINS.entries
            .filter { (brand, owners) ->
                host.contains(brand) &&
                    registrable !in owners &&
                    owners.none { registrable.endsWith(".$it") }
            }
            .map { it.key }

    // ----------------------------------------------------------------------
    // UPI
    // ----------------------------------------------------------------------

    fun analyseUpi(text: String, senderKnown: Boolean): List<Signal> {
        if (senderKnown) return emptyList()
        if (!UPI_REGEX.containsMatchIn(text)) return emptyList()
        return listOf(
            Signal(
                code = "UPI_HANDLE_FROM_UNKNOWN",
                pillar = Pillar.URL,
                severity = Severity.HIGH,
                deterministic = true,
                weight = 1.2f,
                reasonRes = R.string.reason_upi_unknown,
            )
        )
    }

    // ----------------------------------------------------------------------
    // Text rules
    // ----------------------------------------------------------------------

    private fun List<String>.presentIn(lower: String): Boolean = any { lower.contains(it) }

    fun analyseText(text: String, lower: String, senderKnown: Boolean): List<Signal> {
        if (text.isBlank()) return emptyList()
        val signals = mutableListOf<Signal>()

        val urgency = URGENCY.presentIn(lower)
        val payment = PAYMENT.presentIn(lower)
        val credential = CREDENTIAL.presentIn(lower)
        val authority = AUTHORITY.presentIn(lower)
        val prize = PRIZE.presentIn(lower)
        val kyc = KYC.presentIn(lower)
        val threat = THREAT.presentIn(lower)
        val job = JOB.presentIn(lower)

        if (isCredentialRequest(text)) {
            signals += Signal(
                code = "TEXT_CREDENTIAL_REQUEST",
                pillar = Pillar.TEXT,
                severity = Severity.HIGH,
                deterministic = true,
                weight = 1.3f,
                reasonRes = R.string.reason_credential_request,
            )
        }

        if (authority && (threat || payment)) {
            signals += Signal(
                code = "TEXT_DIGITAL_ARREST_PATTERN",
                pillar = Pillar.TEXT,
                severity = if (threat && payment) Severity.HIGH else Severity.MEDIUM,
                deterministic = true,
                weight = 1.3f,
                reasonRes = R.string.reason_digital_arrest,
            )
        }

        if (prize && payment) {
            signals += Signal(
                code = "TEXT_ADVANCE_FEE_PATTERN",
                pillar = Pillar.TEXT,
                severity = Severity.HIGH,
                deterministic = true,
                weight = 1.2f,
                reasonRes = R.string.reason_advance_fee,
            )
        }

        if (urgency && (payment || credential)) {
            signals += Signal(
                code = "TEXT_URGENT_MONEY_REQUEST",
                pillar = Pillar.TEXT,
                severity = Severity.MEDIUM,
                deterministic = true,
                weight = 1.1f,
                reasonRes = R.string.reason_urgent_money,
            )
        }

        if (kyc && (urgency || threat)) {
            signals += Signal(
                code = "TEXT_KYC_PRESSURE",
                pillar = Pillar.TEXT,
                severity = Severity.MEDIUM,
                deterministic = true,
                weight = 1.1f,
                reasonRes = R.string.reason_kyc_pressure,
            )
        }

        if (job && (payment || urgency)) {
            signals += Signal(
                code = "TEXT_JOB_BAIT",
                pillar = Pillar.TEXT,
                severity = Severity.MEDIUM,
                deterministic = true,
                reasonRes = R.string.reason_job_bait,
            )
        }

        if (signals.isNotEmpty() && !senderKnown) {
            signals += Signal(
                code = "SENDER_UNKNOWN",
                pillar = Pillar.SENDER,
                severity = Severity.LOW,
                deterministic = true,
                weight = 0.8f,
                reasonRes = R.string.reason_sender_unknown,
            )
        }

        return signals
    }

    /**
     * True only for a genuine demand for a secret.
     *
     * Legitimate bank messages routinely say "never share your OTP". Without
     * this negation window the rule would fire on a large share of real bank
     * traffic, which is exactly the false-positive pattern that gets the app
     * uninstalled.
     */
    fun isCredentialRequest(text: String): Boolean {
        for (match in CREDENTIAL_REQUEST_REGEX.findAll(text)) {
            val start = (match.range.first - NEGATION_WINDOW).coerceAtLeast(0)
            val preceding = text.substring(start, match.range.first)
            if (NEGATION_REGEX.containsMatchIn(preceding)) continue
            return true
        }
        return false
    }
}
