package com.satyashield.app.alert

import android.content.Context
import android.content.Intent
import android.speech.tts.TextToSpeech
import android.util.Log
import java.util.Locale

/**
 * Spoken verdicts (F28, PRD 8.2).
 *
 * The highest-impact feature in the product: it reaches a user who cannot read
 * the screen at all. Only the headline and instruction are spoken. Reading the
 * evidence list aloud would bury the instruction, and the instruction is the
 * only part that changes what the user does.
 *
 * TWO THINGS MUST BOTH BE TRUE for this to work, and they fail independently:
 *
 * 1. The *text* must be in the chosen language. That is not TTS's job — it comes
 *    from resource resolution, which by default follows the device locale rather
 *    than our setting. See [com.satyashield.app.settings.AppPrefs.localizedContext].
 *
 * 2. The *voice* for that language must be installed. Google TTS ships voices as
 *    downloadable splits, so a phone may have only English. Measured on a real
 *    Pixel 7: only `split_config.en` and `split_config.ja` were present, so
 *    Hindi and Tamil had no voice at all.
 *
 * When (1) fails and (2) succeeds you get English words in an Indian accent.
 * When (1) succeeds and (2) fails you get Devanagari read by an English voice.
 * Neither is acceptable, so both are checked and reported.
 */
object Speaker {

    private const val TAG = "SatyaSpeaker"
    private const val UTTERANCE_ID = "satyashield-verdict"

    @Volatile private var engine: TextToSpeech? = null
    @Volatile private var ready = false
    private var pending: Pair<String, Locale>? = null

    fun init(context: Context) {
        if (engine != null) return
        engine = TextToSpeech(context.applicationContext) { status ->
            ready = status == TextToSpeech.SUCCESS
            if (!ready) {
                Log.w(TAG, "TTS init failed with status $status")
                return@TextToSpeech
            }
            logAvailableVoices()
            pending?.let { (text, locale) ->
                pending = null
                speak(text, locale)
            }
        }
    }

    /** Human-readable name for a TextToSpeech language availability code. */
    private fun statusName(code: Int): String = when (code) {
        TextToSpeech.LANG_NOT_SUPPORTED -> "LANG_NOT_SUPPORTED"
        TextToSpeech.LANG_MISSING_DATA -> "LANG_MISSING_DATA"
        TextToSpeech.LANG_AVAILABLE -> "LANG_AVAILABLE"
        TextToSpeech.LANG_COUNTRY_AVAILABLE -> "LANG_COUNTRY_AVAILABLE"
        TextToSpeech.LANG_COUNTRY_VAR_AVAILABLE -> "LANG_COUNTRY_VAR_AVAILABLE"
        else -> "UNKNOWN($code)"
    }

    /**
     * Whether a usable voice exists for [locale].
     *
     * Callers should surface a false result during setup rather than discovering
     * it when an alert fires silently.
     */
    fun hasVoiceFor(locale: Locale): Boolean {
        val tts = engine ?: return false
        if (!ready) return false
        val status = runCatching { tts.isLanguageAvailable(locale) }
            .getOrDefault(TextToSpeech.LANG_NOT_SUPPORTED)
        return status >= TextToSpeech.LANG_AVAILABLE
    }

    fun voiceStatus(locale: Locale): String {
        val tts = engine ?: return "engine not ready"
        val status = runCatching { tts.isLanguageAvailable(locale) }
            .getOrDefault(TextToSpeech.LANG_NOT_SUPPORTED)
        return statusName(status)
    }

    private fun logAvailableVoices() {
        val tts = engine ?: return
        for (tag in listOf("en", "hi", "ta")) {
            val locale = Locale.forLanguageTag(tag)
            val status = runCatching { tts.isLanguageAvailable(locale) }
                .getOrDefault(TextToSpeech.LANG_NOT_SUPPORTED)
            Log.i(TAG, "voice[$tag] = ${statusName(status)}")
        }
    }

    /**
     * Speak a verdict, interrupting anything already queued.
     *
     * If no voice exists for [locale] we log it loudly and speak anyway: a
     * mispronounced warning still conveys urgency, and staying silent would
     * remove the only channel that reaches a non-reading user. The visual alert
     * is unaffected either way.
     */
    fun speak(text: String, locale: Locale) {
        val tts = engine
        if (tts == null || !ready) {
            pending = text to locale
            return
        }
        try {
            val status = tts.isLanguageAvailable(locale)
            if (status >= TextToSpeech.LANG_AVAILABLE) {
                tts.language = locale
            } else {
                Log.w(
                    TAG,
                    "no voice for ${locale.toLanguageTag()} (${statusName(status)}); " +
                        "speaking with the default voice, pronunciation will be wrong",
                )
            }
            tts.speak(text, TextToSpeech.QUEUE_FLUSH, null, UTTERANCE_ID)
        } catch (t: Throwable) {
            Log.w(TAG, "speak failed", t)
        }
    }

    /**
     * Intent that opens the system flow for downloading TTS voice data.
     *
     * Needed as a setup step: on a phone with only the English voice, the spoken
     * verdict silently degrades, and the user has no way to know.
     */
    fun installVoiceDataIntent(): Intent =
        Intent(TextToSpeech.Engine.ACTION_INSTALL_TTS_DATA)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)

    fun stop() {
        runCatching { engine?.stop() }
    }

    fun shutdown() {
        runCatching { engine?.shutdown() }
        engine = null
        ready = false
    }
}
