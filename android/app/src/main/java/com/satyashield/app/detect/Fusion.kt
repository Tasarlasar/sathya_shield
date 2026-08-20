package com.satyashield.app.detect

/**
 * On-device evidence fusion and the three-state decision policy.
 *
 * This is a faithful port of the backend `app/fusion.py`. The constants and the
 * gate logic are intentionally identical, and `FusionTest` asserts the same
 * invariant the Python suite does:
 *
 *   **Only deterministic signals may raise a RED verdict.**
 *
 * A classifier is never allowed to take over a frightened user's screen. At two
 * red alerts a day and 90% precision, a user sees a false alarm every five days
 * and uninstalls the app within a month; deterministic rules ("this link ends
 * in .apk") are near-100% precision, so they may interrupt. Models inform,
 * rules interrupt.
 */
object Fusion {

    /** Saturating denominator, matching the backend's `_SCORE_K`. */
    private const val SCORE_K = 5f

    const val RED_SCORE_MIN = 45f
    const val AMBER_SCORE_MIN = 18f

    /** Deterministic HIGH signals that together stand in for one CRITICAL. */
    const val HIGH_SIGNALS_FOR_RED = 2

    fun riskScore(signals: List<Signal>): Float {
        val raw = signals.fold(0f) { acc, signal -> acc + signal.contribution }
        if (raw <= 0f) return 0f
        val score = 100f * raw / (raw + SCORE_K)
        return Math.round(score * 10f) / 10f
    }

    /**
     * Whether any deterministic evidence authorises a screen-takeover alert.
     *
     * Note that `deterministic` is required in both branches. No quantity of
     * model output, however confident, can satisfy this predicate.
     */
    fun isRedEligible(signals: List<Signal>): Boolean {
        val deterministic = signals.filter { it.deterministic }
        if (deterministic.any { it.severity == Severity.CRITICAL }) return true
        val highCount = deterministic.count { it.severity.value >= Severity.HIGH.value }
        return highCount >= HIGH_SIGNALS_FOR_RED
    }

    fun decide(signals: List<Signal>, mediaPresent: Boolean = false): LocalVerdict {
        val score = riskScore(signals)
        val redEligible = isRedEligible(signals)
        val band = when {
            redEligible && score >= RED_SCORE_MIN -> Band.RED
            score >= AMBER_SCORE_MIN -> Band.AMBER
            else -> Band.GREEN
        }
        return LocalVerdict(
            band = band,
            score = score,
            redEligible = redEligible,
            signals = rank(signals),
            mediaPresent = mediaPresent,
        )
    }

    /** Most severe first, deterministic ahead of model output at equal severity. */
    fun rank(signals: List<Signal>): List<Signal> = signals.sortedWith(
        compareByDescending<Signal> { it.severity.value }
            .thenBy { if (it.deterministic) 0 else 1 }
            .thenByDescending { it.weight }
            .thenBy { it.code }
    )
}
