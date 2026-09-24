package com.satyashield.app.detect

import com.satyashield.app.R

/**
 * On-device email header forensics.
 *
 * A faithful (if smaller) port of the backend `app/pillars/email_headers.py`,
 * so the phone can judge an email without a server round trip. The substance of
 * email phishing is in the headers, and headers are cheap, deterministic and
 * highly explainable ("the name says HDFC Bank but it was sent from a Gmail
 * account"), which is exactly what PS clause 12 asks for.
 *
 * DEGRADED-INPUT REALITY. On a phone the usual source is "share this email" from
 * a mail app, which hands over the body text and sometimes a From line, but
 * almost never the full RFC 822 header block with Authentication-Results. So:
 *
 *   - Signals that need only From / Reply-To / Return-Path work whenever those
 *     lines are present, and degrade to silence when they are not.
 *   - SPF/DKIM/DMARC evaluation only runs when real Authentication-Results
 *     headers are present AND the caller says they can be trusted. A user-pasted
 *     or app-shared blob has attacker-controllable headers, so those are ignored
 *     rather than believed — identical to the backend's `trust_auth_headers`.
 *   - Whatever the header forensics find, the body still flows through the
 *     normal URL and text rules via LocalRules.
 *
 * Every signal here is deterministic.
 */
object EmailRules {

    private val EXECUTABLE_EXTENSIONS = setOf(
        "apk", "exe", "scr", "com", "pif", "bat", "cmd", "js", "jse", "vbs",
        "vbe", "wsf", "wsh", "hta", "jar", "msi", "ps1", "reg", "lnk", "iso",
        "img", "vhd", "dll", "cpl", "msc",
    )
    private val MACRO_EXTENSIONS = setOf("docm", "xlsm", "pptm", "dotm", "xltm", "potm", "xlsb")
    private val HTML_ATTACHMENT_EXTENSIONS = setOf("html", "htm", "shtml", "mht", "mhtml")

    // Outcomes meaning the sender could not be proven.
    private val FAIL_STATES = setOf("fail", "softfail", "permerror", "temperror", "none", "neutral")
    private val HARD_FAIL_STATES = setOf("fail", "permerror")

    private val AUTH_RESULT_RE = Regex("""\b(spf|dkim|dmarc)\s*=\s*([a-z]+)""", RegexOption.IGNORE_CASE)
    private val DOUBLE_EXT_RE = Regex(
        """\.(pdf|doc|docx|xls|xlsx|jpg|jpeg|png|txt|zip)\.([a-z0-9]{2,4})$""",
        RegexOption.IGNORE_CASE,
    )
    private val ADDR_IN_ANGLE_RE = Regex("""<([^>]+)>""")
    private val EMAIL_ADDR_RE = Regex("""[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}""")

    /**
     * Heuristic: does this shared text look like an email rather than an SMS?
     *
     * Used to decide whether to run the email pillar at all. A real header block
     * ("From:", "Subject:") or an angle-bracketed address are the tells.
     */
    fun looksLikeEmail(text: String): Boolean {
        if (text.isBlank()) return false
        val head = text.take(2000)
        val hasHeaderLine = Regex(
            """(?im)^(from|subject|to|reply-to|return-path|date)\s*:""",
        ).containsMatchIn(head)
        val hasAngleAddr = ADDR_IN_ANGLE_RE.containsMatchIn(head) && head.contains("@")
        return hasHeaderLine || hasAngleAddr
    }

    private data class Header(val name: String, val value: String)

    /** Parse the leading header block. Stops at the first blank line (body start). */
    private fun parseHeaders(raw: String): List<Header> {
        val headers = mutableListOf<Header>()
        var current: Header? = null
        for (line in raw.lineSequence()) {
            if (line.isBlank()) break // end of header block
            if (line.first().isWhitespace() && current != null) {
                // RFC 822 folded continuation line.
                current = current.copy(value = current.value + " " + line.trim())
                headers[headers.size - 1] = current
                continue
            }
            val idx = line.indexOf(':')
            if (idx <= 0) {
                // Not a header line; if we have not seen headers yet, this is not
                // a header block at all.
                if (headers.isEmpty()) break else continue
            }
            current = Header(line.take(idx).trim().lowercase(), line.substring(idx + 1).trim())
            headers += current
        }
        return headers
    }

    private fun firstHeader(headers: List<Header>, name: String): String? =
        headers.firstOrNull { it.name == name }?.value

    /** "Display Name <addr@host>" -> Pair(display, address). Either may be blank. */
    private fun parseAddress(value: String): Pair<String, String> {
        val angle = ADDR_IN_ANGLE_RE.find(value)
        if (angle != null) {
            val addr = angle.groupValues[1].trim()
            val name = value.substring(0, angle.range.first).trim().trim('"')
            return name to addr
        }
        val bare = EMAIL_ADDR_RE.find(value)?.value ?: ""
        val name = if (bare.isEmpty()) value.trim().trim('"') else ""
        return name to bare
    }

    private fun domainOf(address: String): String {
        if (!address.contains('@')) return ""
        val host = address.substringAfterLast('@').trim().lowercase()
        return LocalRules.registrableDomain(host)
    }

    /**
     * Analyse an email's headers.
     *
     * @param raw the shared/pasted email text.
     * @param trustAuthHeaders whether Authentication-Results can be believed.
     *   Almost always false on a phone, where headers are user-supplied.
     */
    fun analyse(raw: String, trustAuthHeaders: Boolean = false): List<Signal> {
        val signals = mutableListOf<Signal>()
        if (raw.isBlank()) return signals

        val headers = parseHeaders(raw)
        if (headers.isEmpty()) return signals

        val fromRaw = firstHeader(headers, "from")
        val (fromName, fromAddr) = fromRaw?.let { parseAddress(it) } ?: ("" to "")
        val fromDomain = domainOf(fromAddr)

        // --- Display-name brand claim vs actual sending domain ---
        val impersonated = LocalRules.brandTokensInDisplayName(fromName)
            .filter { fromDomain.isNotEmpty() && !LocalRules.brandOwnsDomain(it, fromDomain) }

        if (impersonated.isNotEmpty() && fromDomain in LocalRules.FREEMAIL_DOMAINS) {
            // Near-conclusive: a bank never mails you from Gmail.
            signals += Signal(
                code = "EMAIL_BRAND_FROM_FREEMAIL",
                pillar = Pillar.EMAIL,
                severity = Severity.CRITICAL,
                deterministic = true,
                weight = 1.5f,
                reasonRes = R.string.reason_email_brand_freemail,
                reasonArg = impersonated.first().uppercase(),
            )
        } else if (impersonated.isNotEmpty()) {
            signals += Signal(
                code = "EMAIL_DISPLAY_NAME_SPOOF",
                pillar = Pillar.EMAIL,
                severity = Severity.HIGH,
                deterministic = true,
                weight = 1.3f,
                reasonRes = R.string.reason_email_display_spoof,
                reasonArg = impersonated.first().uppercase(),
            )
        }

        // --- Sender domain itself is a brand lookalike ---
        if (fromAddr.contains('@')) {
            val senderHost = fromAddr.substringAfterLast('@').lowercase()
            val lookalikes = LocalRules.brandLookalikes(senderHost, LocalRules.registrableDomain(senderHost))
            if (lookalikes.isNotEmpty()) {
                signals += Signal(
                    code = "EMAIL_SENDER_DOMAIN_LOOKALIKE",
                    pillar = Pillar.EMAIL,
                    severity = Severity.HIGH,
                    deterministic = true,
                    weight = 1.3f,
                    reasonRes = R.string.reason_email_sender_lookalike,
                    reasonArg = lookalikes.first().uppercase(),
                )
            }
        }

        // --- Reply-To divergence ---
        val replyDomain = firstHeader(headers, "reply-to")?.let { domainOf(parseAddress(it).second) } ?: ""
        if (replyDomain.isNotEmpty() && fromDomain.isNotEmpty() && replyDomain != fromDomain) {
            val severity =
                if (impersonated.isNotEmpty() || (replyDomain in LocalRules.FREEMAIL_DOMAINS && fromName.isNotBlank())) {
                    Severity.HIGH
                } else {
                    Severity.MEDIUM
                }
            signals += Signal(
                code = "EMAIL_REPLY_TO_MISMATCH",
                pillar = Pillar.EMAIL,
                severity = severity,
                deterministic = true,
                weight = 1.1f,
                reasonRes = R.string.reason_email_reply_to,
            )
        }

        // --- Return-Path / envelope mismatch ---
        val returnDomain = firstHeader(headers, "return-path")?.let { domainOf(parseAddress(it).second) } ?: ""
        if (returnDomain.isNotEmpty() && fromDomain.isNotEmpty() && returnDomain != fromDomain) {
            signals += Signal(
                code = "EMAIL_RETURN_PATH_MISMATCH",
                pillar = Pillar.EMAIL,
                severity = Severity.LOW,
                deterministic = true,
                reasonRes = R.string.reason_email_return_path,
            )
        }

        // --- SPF / DKIM / DMARC, only if trustworthy headers exist ---
        if (trustAuthHeaders) {
            val authValues = headers
                .filter { it.name == "authentication-results" || it.name == "arc-authentication-results" }
                .joinToString(" ") { it.value }
            val outcomes = AUTH_RESULT_RE.findAll(authValues)
                .associate { it.groupValues[1].lowercase() to it.groupValues[2].lowercase() }
            val hardFailed = outcomes.filterValues { it in HARD_FAIL_STATES }.keys
            val failed = outcomes.filterValues { it in FAIL_STATES }.keys
            if (hardFailed.isNotEmpty()) {
                signals += Signal(
                    code = "EMAIL_AUTH_HARD_FAIL",
                    pillar = Pillar.EMAIL,
                    severity = Severity.HIGH,
                    deterministic = true,
                    weight = 1.4f,
                    reasonRes = R.string.reason_email_auth_fail,
                )
            } else if (failed.isNotEmpty()) {
                signals += Signal(
                    code = "EMAIL_AUTH_WEAK",
                    pillar = Pillar.EMAIL,
                    severity = Severity.MEDIUM,
                    deterministic = true,
                    reasonRes = R.string.reason_email_auth_weak,
                )
            }
        }

        return signals
    }

    /**
     * Best-effort body extraction for handing to the URL and text rules.
     *
     * If a header block is present, the body is everything after the first blank
     * line. Otherwise the whole thing is treated as body.
     */
    fun bodyText(raw: String): String {
        val idx = raw.indexOf("\n\n").let { if (it >= 0) it else raw.indexOf("\r\n\r\n") }
        return if (idx >= 0) raw.substring(idx).trim() else raw.trim()
    }
}
