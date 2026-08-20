package com.satyashield.app.settings

import android.content.Context
import com.satyashield.app.detect.Band
import com.satyashield.app.detect.LocalVerdict
import java.util.concurrent.CopyOnWriteArrayList

/**
 * In-memory record of recent checks (F45), plus the signal the self-test waits on.
 *
 * Deliberately not persisted to disk. These entries contain message text, and
 * PRD section 15.1 commits to not retaining content. Keeping them in memory only
 * means the record dies with the process, which is the correct default for a
 * prototype that reads someone's messages.
 */
object VerdictLog {

    data class Entry(
        val excerpt: String,
        val band: Band,
        val score: Float,
        val at: Long = System.currentTimeMillis(),
    )

    private const val MAX_ENTRIES = 30
    private const val EXCERPT_CHARS = 140

    private val entries = CopyOnWriteArrayList<Entry>()

    @Volatile
    private var listener: ((Entry) -> Unit)? = null

    fun record(context: Context, text: String, verdict: LocalVerdict) {
        val entry = Entry(
            excerpt = text.take(EXCERPT_CHARS),
            band = verdict.band,
            score = verdict.score,
        )
        entries.add(0, entry)
        while (entries.size > MAX_ENTRIES) {
            entries.removeAt(entries.size - 1)
        }
        listener?.invoke(entry)
    }

    fun recent(): List<Entry> = entries.toList()

    /** Used by the self-test to observe that the listener actually fired. */
    fun observe(callback: ((Entry) -> Unit)?) {
        listener = callback
    }
}
