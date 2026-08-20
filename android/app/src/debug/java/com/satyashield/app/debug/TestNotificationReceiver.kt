package com.satyashield.app.debug

import android.app.Notification
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Log
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import com.satyashield.app.R
import com.satyashield.app.SatyaShieldApp

/**
 * Debug-only harness for posting arbitrary notifications.
 *
 * Lives in `src/debug` so it is physically absent from release builds.
 *
 * Exists to characterise Android 15's sensitive-notification redaction: the
 * platform replaces the content of notifications its on-device classifier deems
 * sensitive with a placeholder before handing them to untrusted listeners, and
 * `RECEIVE_SENSITIVE_NOTIFICATIONS` is role-managed so a third-party app cannot
 * opt in. We need to know whether that hits every message or only some, because
 * the answer decides how much of passive capture survives.
 *
 * Usage:
 *   adb shell am broadcast -a com.satyashield.app.TEST_NOTIFY \
 *     -n com.satyashield.app/.debug.TestNotificationReceiver \
 *     --es text "message body" [--es style bigtext|plain] [--es title "sender"]
 */
class TestNotificationReceiver : BroadcastReceiver() {

    companion object {
        private const val TAG = "SatyaTestNotify"
        const val ACTION = "com.satyashield.app.TEST_NOTIFY"
        private var counter = 7000
    }

    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != ACTION) return

        val text = intent.getStringExtra("text") ?: return
        val title = intent.getStringExtra("title") ?: "+91 90000 00000"
        val style = intent.getStringExtra("style") ?: "bigtext"

        val builder = NotificationCompat.Builder(context, SatyaShieldApp.CHANNEL_SELFTEST)
            .setSmallIcon(R.drawable.ic_shield_small)
            .setContentTitle(title)
            .setContentText(text)
            .setCategory(Notification.CATEGORY_MESSAGE)
            .setAutoCancel(true)

        if (style == "bigtext") {
            builder.setStyle(NotificationCompat.BigTextStyle().bigText(text))
        }

        val id = counter++
        Log.i(TAG, "posting id=$id style=$style len=${text.length}")
        runCatching {
            NotificationManagerCompat.from(context).notify(id, builder.build())
        }.onFailure { Log.e(TAG, "post failed", it) }
    }
}
