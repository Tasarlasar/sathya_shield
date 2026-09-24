package com.satyashield.app.detect

import androidx.annotation.StringRes

/**
 * On-device detection model types.
 *
 * Mirrors the backend `app/schemas.py` deliberately. The two implementations
 * must agree on the meaning of [Signal.deterministic] and on the RED gate,
 * because the same message may be judged locally (offline, instant) or remotely
 * (deeper pillars) and the user must not see the two disagree about whether to
 * interrupt.
 */

enum class Severity(val value: Int) {
    INFO(0),
    LOW(1),
    MEDIUM(2),
    HIGH(3),
    CRITICAL(4),
}

enum class Band {
    GREEN,
    AMBER,
    RED,
}

enum class Pillar {
    URL,
    TEXT,
    SENDER,
    EMAIL,
}

/**
 * One piece of evidence.
 *
 * [deterministic] carries the same contract as the backend: true only when a
 * rule fired on a directly observed fact, false when a model produced a score.
 * Only deterministic signals can open the RED gate (see [Fusion.isRedEligible]).
 */
data class Signal(
    val code: String,
    val pillar: Pillar,
    val severity: Severity,
    val deterministic: Boolean,
    val weight: Float = 1f,
    @StringRes val reasonRes: Int,
    /** Substituted into [reasonRes] when the string takes a format argument. */
    val reasonArg: String? = null,
) {
    val contribution: Float get() = severity.value * weight
}

/** Result of analysing one message on-device. */
data class LocalVerdict(
    val band: Band,
    val score: Float,
    val redEligible: Boolean,
    val signals: List<Signal>,
    val mediaPresent: Boolean = false,
    /**
     * The message that triggered this verdict.
     *
     * Shown back to the user in the alert so they can see exactly what set it
     * off ("this is the message we are warning you about"), rather than a
     * disembodied warning. Stays on-device with the verdict and is never logged.
     */
    val sourceText: String = "",
) {
    /** Only RED may take over the screen. AMBER badges quietly (F34). */
    val interrupts: Boolean get() = band == Band.RED
}
