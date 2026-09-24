package com.satyashield.app.ui

import android.content.Intent
import android.os.Bundle
import android.widget.Toast
import androidx.activity.ComponentActivity
import com.satyashield.app.alert.AlertPresenter
import com.satyashield.app.alert.Speaker
import com.satyashield.app.alert.VerdictText
import com.satyashield.app.detect.Band
import com.satyashield.app.detect.EmailRules
import com.satyashield.app.detect.LocalRules
import com.satyashield.app.service.AskFamily
import com.satyashield.app.settings.AppPrefs
import com.satyashield.app.settings.VerdictLog

/**
 * Share-sheet entry point (F2).
 *
 * Long-press a message or a video, Share, SatyaShield. One gesture, and it
 * replaces copy-paste entirely.
 *
 * This is also the only route by which media can be checked at all: notification
 * capture yields text, never files (see SatyaNotificationListener). Media
 * analysis needs the server-side pillars, so for now a shared image or video is
 * acknowledged and queued rather than silently accepted, which is honest about
 * what is implemented.
 */
class ShareTargetActivity : ComponentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        Speaker.init(this)
        handle(intent)
        finish()
    }

    private fun handle(intent: Intent?) {
        if (intent == null) return

        val sharedText = intent.getStringExtra(Intent.EXTRA_TEXT)
            ?: intent.getCharSequenceExtra(Intent.EXTRA_TEXT)?.toString()
        val hasStream = intent.hasExtra(Intent.EXTRA_STREAM)
        val mime = intent.type.orEmpty()

        if (!sharedText.isNullOrBlank()) {
            checkText(sharedText)
            return
        }

        if (hasStream && (mime.startsWith("image/") || mime.startsWith("video/") ||
                mime.startsWith("audio/"))
        ) {
            // Media pillars are server-side and not yet wired. Say so plainly
            // instead of returning a fabricated verdict.
            Toast.makeText(
                this,
                "Media checking is not available yet in this build",
                Toast.LENGTH_LONG,
            ).show()
            return
        }

        Toast.makeText(this, "Nothing to check", Toast.LENGTH_SHORT).show()
    }

    private fun checkText(text: String) {
        // If the shared content looks like an email (header lines or an
        // angle-bracketed address), run the email pillar too. Auth headers from
        // a shared blob are attacker-controllable, so they are not trusted.
        val verdict = if (EmailRules.looksLikeEmail(text)) {
            LocalRules.analyseEmail(text, trustAuthHeaders = false)
        } else {
            LocalRules.analyse(text, senderKnown = false)
        }
        VerdictLog.record(this, text, verdict)

        if (verdict.band == Band.GREEN) {
            val rendered = VerdictText.render(this, verdict)
            Toast.makeText(this, rendered.headline, Toast.LENGTH_LONG).show()
            Speaker.speak(rendered.spoken, AppPrefs.locale(this))
            return
        }

        AlertPresenter.present(
            context = applicationContext,
            verdict = verdict,
            locale = AppPrefs.locale(this),
            onAskFamily = { AskFamily.send(applicationContext, verdict) },
        )
    }
}
