package com.satyashield.app.ui

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.PowerManager
import android.provider.Settings
import com.satyashield.app.service.SatyaNotificationListener

/**
 * Guided permission flow (F39, F43).
 *
 * None of these three can be granted by a runtime dialog. Each requires sending
 * the user into a specific Settings screen, which is precisely why setup is done
 * once by the adult child rather than expected of the primary user.
 */
object Permissions {

    fun notificationAccessGranted(context: Context): Boolean =
        SatyaNotificationListener.isEnabled(context)

    fun overlayGranted(context: Context): Boolean = Settings.canDrawOverlays(context)

    fun batteryExemptionGranted(context: Context): Boolean {
        val pm = context.getSystemService(Context.POWER_SERVICE) as? PowerManager
            ?: return false
        return pm.isIgnoringBatteryOptimizations(context.packageName)
    }

    /** Notification access lives behind a dedicated Settings screen. */
    fun openNotificationAccessSettings(context: Context) {
        val intent = Intent(Settings.ACTION_NOTIFICATION_LISTENER_SETTINGS)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        context.startActivity(intent)
    }

    fun openOverlaySettings(context: Context) {
        val intent = Intent(
            Settings.ACTION_MANAGE_OVERLAY_PERMISSION,
            Uri.parse("package:${context.packageName}"),
        ).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        context.startActivity(intent)
    }

    /**
     * Battery-optimisation exemption.
     *
     * Risk #3 in the PRD register: Xiaomi, Oppo, Vivo and Realme aggressively
     * kill background processes and dominate our target user segment. Without
     * this the listener dies silently, which is the worst kind of failure
     * because the user believes they are protected.
     */
    fun requestBatteryExemption(context: Context) {
        val intent = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            Intent(
                Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS,
                Uri.parse("package:${context.packageName}"),
            )
        } else {
            Intent(Settings.ACTION_SETTINGS)
        }
        runCatching {
            context.startActivity(intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
        }.onFailure {
            // Some OEM builds hide this screen entirely; fall back to the app's
            // own settings page rather than crashing.
            context.startActivity(
                Intent(
                    Settings.ACTION_APPLICATION_DETAILS_SETTINGS,
                    Uri.parse("package:${context.packageName}"),
                ).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            )
        }
    }
}
