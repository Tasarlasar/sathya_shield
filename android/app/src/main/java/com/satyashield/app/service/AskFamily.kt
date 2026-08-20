package com.satyashield.app.service

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.util.Log
import android.widget.Toast
import com.satyashield.app.alert.VerdictText
import com.satyashield.app.detect.LocalVerdict
import com.satyashield.app.settings.AppPrefs

/**
 * Trusted-contact escalation (F35, PRD section 9).
 *
 * The failure mode this addresses is not missed detection. It is detecting
 * correctly, warning clearly, and the user proceeding anyway because a live
 * human on the phone is more persuasive than a popup. Social engineering beats
 * UI, so the counter is also social: turn an isolated decision made under
 * pressure into a supported one.
 *
 * MVP transport is an SMS intent to a single registered contact, which needs no
 * server and no account. PRD section 9 notes Truecaller ships a stronger version
 * of this idea, so we do not present it as novel, only as necessary.
 */
object AskFamily {

    private const val TAG = "SatyaAskFamily"
    private const val MAX_FORWARDED_CHARS = 400

    fun send(context: Context, originalText: String, verdict: LocalVerdict) {
        val contact = AppPrefs.trustedContact(context)
        if (contact.isNullOrBlank()) {
            Toast.makeText(context, "No family contact set up yet", Toast.LENGTH_LONG).show()
            return
        }

        val rendered = VerdictText.render(context, verdict)
        val excerpt = originalText.take(MAX_FORWARDED_CHARS)
        val body = buildString {
            append("SatyaShield warning: ")
            append(rendered.headline)
            append("\n\n")
            append("Message received:\n")
            append(excerpt)
            append("\n\nWhy:\n")
            rendered.reasons.forEach { append("- ").append(it).append('\n') }
        }

        val intent = Intent(Intent.ACTION_SENDTO).apply {
            data = Uri.parse("smsto:$contact")
            putExtra("sms_body", body)
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        }

        try {
            context.startActivity(intent)
        } catch (t: Throwable) {
            Log.w(TAG, "no SMS app available", t)
            Toast.makeText(context, "Could not open messaging app", Toast.LENGTH_LONG).show()
        }
    }
}
