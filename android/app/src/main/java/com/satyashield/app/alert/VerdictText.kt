package com.satyashield.app.alert

import android.content.Context
import com.satyashield.app.R
import com.satyashield.app.detect.Band
import com.satyashield.app.detect.LocalVerdict
import com.satyashield.app.settings.AppPrefs

/** User-facing strings for a verdict. */
data class RenderedVerdict(
    val headline: String,
    val action: String,
    val reasons: List<String>,
    val spoken: String,
    /** The triggering message, trimmed for display. Empty if none. */
    val quoted: String,
)

/**
 * Turns a verdict into localised, jargon-free text (PRD 8.3, 8.4).
 *
 * Strings come from the localised `strings.xml` resource sets, so the correct
 * language is chosen by the Android resource system from the context's
 * configuration. That keeps per-language wording authored rather than
 * translated at runtime.
 */
object VerdictText {

    /** At most three reasons: a longer list is overwhelming, not convincing. */
    const val MAX_REASONS = 3

    /** Longest quoted message shown in the alert; longer is truncated. */
    const val MAX_QUOTE_CHARS = 220

    /** Collapse whitespace and truncate the triggering message for display. */
    fun quoteFor(sourceText: String): String {
        val collapsed = sourceText.replace(Regex("""\s+"""), " ").trim()
        return if (collapsed.length <= MAX_QUOTE_CHARS) {
            collapsed
        } else {
            collapsed.take(MAX_QUOTE_CHARS).trimEnd() + "\u2026"
        }
    }

    fun render(context: Context, verdict: LocalVerdict): RenderedVerdict {
        // Resolve strings in the user's chosen language, not the device's.
        // See AppPrefs.localizedContext for why this is not optional.
        @Suppress("NAME_SHADOWING")
        val context = AppPrefs.localizedContext(context)

        val headline = context.getString(
            when (verdict.band) {
                Band.RED -> R.string.band_red_headline
                Band.AMBER -> R.string.band_amber_headline
                Band.GREEN -> R.string.band_green_headline
            }
        )
        val action = context.getString(
            when (verdict.band) {
                Band.RED -> R.string.band_red_action
                Band.AMBER -> R.string.band_amber_action
                Band.GREEN -> R.string.band_green_action
            }
        )

        val reasons = verdict.signals
            .asSequence()
            .map { signal ->
                signal.reasonArg
                    ?.let { context.getString(signal.reasonRes, it) }
                    ?: context.getString(signal.reasonRes)
            }
            .distinct()
            .take(MAX_REASONS)
            .toMutableList()

        if (verdict.mediaPresent) {
            reasons += context.getString(R.string.reason_media_prompt)
        }

        return RenderedVerdict(
            headline = headline,
            action = action,
            reasons = reasons,
            // Headline plus instruction only. The evidence is on screen to be
            // read, not recited.
            spoken = "$headline. $action",
            quoted = quoteFor(verdict.sourceText),
        )
    }
}
