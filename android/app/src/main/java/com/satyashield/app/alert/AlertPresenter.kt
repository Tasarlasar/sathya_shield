package com.satyashield.app.alert

import android.annotation.SuppressLint
import android.content.Context
import android.graphics.PixelFormat
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.provider.Settings
import android.util.Log
import android.view.Gravity
import android.view.LayoutInflater
import android.view.View
import android.view.WindowManager
import android.widget.Button
import android.widget.ImageView
import android.widget.TextView
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import com.satyashield.app.R
import com.satyashield.app.SatyaShieldApp
import com.satyashield.app.detect.Band
import com.satyashield.app.detect.LocalVerdict
import com.satyashield.app.settings.AppPrefs
import java.util.Locale

/**
 * Shows the screen-takeover alert (F26).
 *
 * Uses `SYSTEM_ALERT_WINDOW` rather than a full-screen-intent notification.
 * Android 14 restricted `USE_FULL_SCREEN_INTENT` to calling and alarm apps by
 * default, and even where granted it tends to only go full-screen on a locked
 * device, degrading to an ordinary heads-up notification otherwise. An overlay
 * is the only reliable way to be unmissable, and the permission is granted once
 * during setup by the adult child.
 *
 * The overlay is added directly from the notification listener's context, so no
 * additional foreground service and no `foregroundServiceType` declaration is
 * needed.
 *
 * Degradation is deliberate: if overlay permission is absent we fall back to a
 * high-priority notification rather than failing silently. A missed warning is
 * worse than an ugly one.
 */
object AlertPresenter {

    private const val TAG = "SatyaAlert"

    private val main = Handler(Looper.getMainLooper())

    private var windowManager: WindowManager? = null
    private var overlay: View? = null

    fun canOverlay(context: Context): Boolean = Settings.canDrawOverlays(context)

    /**
     * Present a verdict. Only RED takes over the screen; AMBER posts a quiet
     * notification and GREEN is not surfaced at all (F34).
     */
    fun present(
        context: Context,
        verdict: LocalVerdict,
        locale: Locale,
        onAskFamily: () -> Unit = {},
    ) {
        when (verdict.band) {
            Band.RED -> main.post { showOverlay(context, verdict, locale, onAskFamily) }
            Band.AMBER -> postQuietNotification(context, verdict, locale)
            Band.GREEN -> Unit
        }
    }

    @SuppressLint("InflateParams")
    private fun showOverlay(
        context: Context,
        verdict: LocalVerdict,
        locale: Locale,
        onAskFamily: () -> Unit,
    ) {
        if (!canOverlay(context)) {
            Log.w(TAG, "overlay permission absent, falling back to notification")
            postQuietNotification(context, verdict, locale, highPriority = true)
            return
        }

        dismiss()

        val text = VerdictText.render(context, verdict)

        // Inflate against a localised context so the button labels come from the
        // user's chosen language too, not the device locale. Layout XML defaults
        // would otherwise resolve in whatever language the phone is set to.
        val localized = AppPrefs.localizedContext(context)
        val view = LayoutInflater.from(localized).inflate(R.layout.overlay_alert, null)

        view.findViewById<TextView>(R.id.alert_headline).text = text.headline
        view.findViewById<TextView>(R.id.alert_action).text = text.action
        view.findViewById<TextView>(R.id.alert_reasons).text =
            text.reasons.joinToString("\n") { "\u2022  $it" }
        view.findViewById<ImageView>(R.id.alert_icon)
            .setImageResource(R.drawable.ic_alert_stop)

        view.findViewById<Button>(R.id.alert_ask_family).apply {
            setText(localized.getString(R.string.alert_ask_family))
            setOnClickListener {
                onAskFamily()
                dismiss()
            }
        }
        view.findViewById<Button>(R.id.alert_repeat).apply {
            setText(localized.getString(R.string.alert_repeat))
            setOnClickListener { Speaker.speak(text.spoken, locale) }
        }
        view.findViewById<Button>(R.id.alert_dismiss).apply {
            setText(localized.getString(R.string.alert_dismiss))
            setOnClickListener {
                Speaker.stop()
                dismiss()
            }
        }

        val type = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            WindowManager.LayoutParams.TYPE_APPLICATION_OVERLAY
        } else {
            @Suppress("DEPRECATION")
            WindowManager.LayoutParams.TYPE_SYSTEM_ALERT
        }

        val params = WindowManager.LayoutParams(
            WindowManager.LayoutParams.MATCH_PARENT,
            WindowManager.LayoutParams.MATCH_PARENT,
            type,
            // Not FLAG_NOT_FOCUSABLE: the alert must receive taps, and turning
            // the screen on matters when a scam message arrives at night.
            WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON or
                WindowManager.LayoutParams.FLAG_TURN_SCREEN_ON or
                WindowManager.LayoutParams.FLAG_SHOW_WHEN_LOCKED,
            PixelFormat.TRANSLUCENT,
        ).apply { gravity = Gravity.CENTER }

        val wm = context.getSystemService(Context.WINDOW_SERVICE) as WindowManager
        try {
            wm.addView(view, params)
            windowManager = wm
            overlay = view
            Speaker.speak(text.spoken, locale)
            Log.i(TAG, "overlay shown for band=${verdict.band} score=${verdict.score}")
        } catch (t: Throwable) {
            Log.e(TAG, "failed to add overlay", t)
            postQuietNotification(context, verdict, locale, highPriority = true)
        }
    }

    fun dismiss() {
        val view = overlay ?: return
        runCatching { windowManager?.removeView(view) }
            .onFailure { Log.w(TAG, "overlay removal failed", it) }
        overlay = null
    }

    fun isShowing(): Boolean = overlay != null

    private fun postQuietNotification(
        context: Context,
        verdict: LocalVerdict,
        locale: Locale,
        highPriority: Boolean = false,
    ) {
        val text = VerdictText.render(context, verdict)
        val builder = NotificationCompat.Builder(context, SatyaShieldApp.CHANNEL_ALERTS)
            .setSmallIcon(R.drawable.ic_shield_small)
            .setContentTitle(text.headline)
            .setContentText(text.action)
            .setStyle(
                NotificationCompat.BigTextStyle().bigText(
                    (listOf(text.action) + text.reasons).joinToString("\n")
                )
            )
            .setAutoCancel(true)
            .setPriority(
                if (highPriority) NotificationCompat.PRIORITY_MAX
                else NotificationCompat.PRIORITY_DEFAULT
            )

        runCatching {
            NotificationManagerCompat.from(context)
                .notify(NOTIFICATION_ID_ALERT, builder.build())
        }.onFailure { Log.w(TAG, "notification post failed (permission?)", it) }

        if (highPriority) Speaker.speak(text.spoken, locale)
    }

    private const val NOTIFICATION_ID_ALERT = 4201
}
