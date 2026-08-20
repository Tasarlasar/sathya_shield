package com.satyashield.app.setup

import android.app.Notification
import android.content.Context
import android.os.Handler
import android.os.Looper
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import com.satyashield.app.R
import com.satyashield.app.SatyaShieldApp
import com.satyashield.app.detect.Band
import com.satyashield.app.settings.VerdictLog

/**
 * "Check that it works" flow (F41).
 *
 * Posts a synthetic scam message as a real notification, which our own listener
 * then picks up through exactly the same path a WhatsApp message would take.
 * This does two useful things:
 *
 * 1. It proves to the user that protection is live, which builds the trust the
 *    product needs to survive on the phone.
 * 2. It verifies that the permission grants actually took effect. On aggressive
 *    OEM builds the notification-access toggle can appear granted while the
 *    service is never bound, and this is the only way to catch that silently
 *    broken state.
 *
 * It also means the whole pipeline is testable on a bare emulator with no
 * WhatsApp installed.
 */
object SelfTest {

    private const val NOTIFICATION_ID = 9911
    private const val TIMEOUT_MS = 6_000L

    /** A message that must trip a deterministic CRITICAL rule (the APK link). */
    const val SAMPLE_SCAM =
        "SBI KYC expired. Verify urgently at http://sbi-rewards.xyz/netbanking/login " +
            "and install http://update-sbi.top/app.apk to continue."

    enum class Result { PASS, FAIL }

    /**
     * Fire the test and report whether the listener produced a non-green verdict.
     *
     * @param onResult invoked on the main thread exactly once.
     */
    fun run(context: Context, onResult: (Result) -> Unit) {
        val main = Handler(Looper.getMainLooper())
        var settled = false

        fun settle(result: Result) {
            if (settled) return
            settled = true
            VerdictLog.observe(null)
            main.post { onResult(result) }
        }

        VerdictLog.observe { entry ->
            if (entry.band != Band.GREEN && entry.excerpt.contains("sbi-rewards")) {
                settle(Result.PASS)
            }
        }

        val notification = NotificationCompat.Builder(context, SatyaShieldApp.CHANNEL_SELFTEST)
            .setSmallIcon(R.drawable.ic_shield_small)
            .setContentTitle("+91 90000 00000")
            .setContentText(SAMPLE_SCAM)
            .setStyle(NotificationCompat.BigTextStyle().bigText(SAMPLE_SCAM))
            .setCategory(Notification.CATEGORY_MESSAGE)
            .setAutoCancel(true)
            .build()

        val ok = runCatching {
            NotificationManagerCompat.from(context).notify(NOTIFICATION_ID, notification)
        }.isSuccess

        if (!ok) {
            settle(Result.FAIL)
            return
        }

        main.postDelayed({ settle(Result.FAIL) }, TIMEOUT_MS)
    }
}
