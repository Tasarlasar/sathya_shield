package com.satyashield.app

import android.app.Application
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Context
import com.satyashield.app.alert.Speaker

class SatyaShieldApp : Application() {

    companion object {
        const val CHANNEL_STATUS = "satyashield_status"
        const val CHANNEL_ALERTS = "satyashield_alerts"

        /**
         * Channel for the self-test's synthetic scam message (F41).
         *
         * Separate from the alert channel so the notification listener can tell
         * a deliberate test notification apart from our own alert output and
         * avoid analysing its own warnings.
         */
        const val CHANNEL_SELFTEST = "satyashield_selftest"
    }

    override fun onCreate() {
        super.onCreate()
        createChannels()
        Speaker.init(this)
    }

    private fun createChannels() {
        val manager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager

        manager.createNotificationChannel(
            NotificationChannel(
                CHANNEL_STATUS,
                getString(R.string.status_channel_name),
                NotificationManager.IMPORTANCE_LOW,
            ).apply { description = getString(R.string.status_channel_desc) }
        )

        manager.createNotificationChannel(
            NotificationChannel(
                CHANNEL_ALERTS,
                getString(R.string.alert_channel_name),
                NotificationManager.IMPORTANCE_HIGH,
            ).apply { description = getString(R.string.alert_channel_desc) }
        )

        manager.createNotificationChannel(
            NotificationChannel(
                CHANNEL_SELFTEST,
                getString(R.string.selftest_channel_name),
                NotificationManager.IMPORTANCE_DEFAULT,
            )
        )
    }
}
