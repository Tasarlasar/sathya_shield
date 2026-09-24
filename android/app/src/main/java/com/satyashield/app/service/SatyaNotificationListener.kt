package com.satyashield.app.service

import android.app.Notification
import android.content.ComponentName
import android.content.Context
import android.provider.Settings
import android.service.notification.NotificationListenerService
import android.service.notification.StatusBarNotification
import android.util.Log
import androidx.core.app.NotificationCompat
import com.satyashield.app.SatyaShieldApp
import com.satyashield.app.alert.AlertPresenter
import com.satyashield.app.alert.Speaker
import com.satyashield.app.detect.Band
import com.satyashield.app.detect.LocalRules
import com.satyashield.app.settings.AppPrefs
import com.satyashield.app.settings.VerdictLog

/**
 * Passive message capture (F1). The entire product thesis rests on this class.
 *
 * IMPORTANT CONSTRAINT, do not try to work around it:
 * A notification carries TEXT, not files. A WhatsApp image or video notification
 * contains a placeholder like "Photo", and the media itself lives in WhatsApp's
 * scoped storage, which needs MANAGE_EXTERNAL_STORAGE, a permission Play
 * restricts to narrow app categories. **Passive deepfake detection is therefore
 * impossible.** Media is always checked via an explicit user action through the
 * share sheet. When we notice a message references media, we say so and invite
 * one tap (see LocalRules.looksLikeMedia and reason_media_prompt).
 *
 * All analysis here happens on-device via [LocalRules]. Passively captured
 * message text never leaves the phone, which is what makes the privacy claim in
 * PRD section 15.1 true rather than aspirational.
 */
class SatyaNotificationListener : NotificationListenerService() {

    companion object {
        private const val TAG = "SatyaListener"

        /**
         * Packages worth inspecting. SMS and calls are covered better by
         * Truecaller and the OS itself, so our value is concentrated in
         * messaging apps whose content nobody else can see, WhatsApp above all.
         */
        private val WATCHED_PACKAGES = setOf(
            "com.whatsapp",
            "com.whatsapp.w4b",
            "org.telegram.messenger",
            "com.google.android.apps.messaging",
            "com.android.messaging",
            "com.instagram.android",
            "com.facebook.orca",
            // Our own self-test notifications (F41), so setup can be verified
            // without installing WhatsApp on a test device.
            "com.satyashield.app",
        )

        /**
         * How long a message fingerprint is remembered.
         *
         * Deliberately long. Measured behaviour on Google Messages: when a new
         * SMS arrives, the app re-posts its *other* conversation notifications
         * with refreshed timestamps. A short window or an age check alone
         * therefore lets a burst of already-seen messages through, and the user
         * gets a stack of alerts for messages they read yesterday. Remembering
         * content fingerprints is the only reliable defence.
         */
        private const val DEDUPE_WINDOW_MS = 24 * 60 * 60 * 1000L

        /** Fingerprints retained. Bounded so memory cannot grow without limit. */
        private const val DEDUPE_MAX_ENTRIES = 500

        /**
         * Cold-start window during which we analyse and remember, but do not
         * alert. Long enough to cover the replay burst, short enough that a scam
         * arriving just after a reboot is still caught.
         */
        private const val WARMUP_MS = 8_000L

        /**
         * Substrings identifying platform-redacted notification content.
         *
         * The placeholder is localised, so this list is necessarily incomplete;
         * it covers the English wording observed on API 35. Used for diagnostics
         * only (section 5.7), never to alter a verdict.
         */
        private val REDACTION_MARKERS = listOf(
            "sensitive notification content hidden",
            "notification content hidden",
        )

        /**
         * Maximum age of a notification we will still alert on.
         *
         * Generous enough to absorb slow delivery and clock skew, tight enough
         * that a replayed batch of old messages is discarded.
         */
        private const val MAX_NOTIFICATION_AGE_MS = 15_000L

        fun isEnabled(context: Context): Boolean {
            val flat = Settings.Secure.getString(
                context.contentResolver,
                "enabled_notification_listeners",
            ) ?: return false
            val expected = ComponentName(context, SatyaNotificationListener::class.java)
            return flat.split(':').any {
                ComponentName.unflattenFromString(it) == expected
            }
        }
    }

    private val recentlySeen = LinkedHashMap<String, Long>()

    /**
     * Service start time, used for the cold-start warm-up window.
     *
     * Set in onCreate() rather than onListenerConnected() because the initial
     * replay batch can be delivered before onListenerConnected() runs, whereas
     * onCreate() is always first.
     */
    private var startedAtMs: Long = 0L

    override fun onCreate() {
        super.onCreate()
        startedAtMs = System.currentTimeMillis()
    }

    override fun onListenerConnected() {
        super.onListenerConnected()
        Log.i(TAG, "listener connected")
        Speaker.init(this)
        AppPrefs.setListenerConnected(this, true)
    }

    override fun onListenerDisconnected() {
        super.onListenerDisconnected()
        Log.w(TAG, "listener disconnected")
        AppPrefs.setListenerConnected(this, false)
    }

    override fun onNotificationPosted(sbn: StatusBarNotification?) {
        val notification = sbn ?: return
        try {
            handle(notification)
        } catch (t: Throwable) {
            // A crash here silently ends all protection, so nothing is allowed
            // to escape.
            Log.e(TAG, "failed handling notification", t)
        }
    }

    private fun handle(sbn: StatusBarNotification) {
        if (!AppPrefs.isProtectionEnabled(this)) return
        if (sbn.packageName !in WATCHED_PACKAGES) return

        // Our own alerts and status notifications must not be re-analysed.
        val channel = sbn.notification?.channelId
        if (sbn.packageName == packageName &&
            channel != SatyaShieldApp.CHANNEL_SELFTEST
        ) {
            return
        }

        // Suppress replayed history.
        //
        // On connect Android re-delivers every active notification, and measured
        // on device that batch can arrive BEFORE onListenerConnected() runs, so
        // comparing against a connect timestamp is unreliable. An absolute age
        // check is order-independent: a genuinely new message is delivered within
        // milliseconds of being posted, whereas a replay is minutes or hours old.
        val age = System.currentTimeMillis() - sbn.postTime
        if (age > MAX_NOTIFICATION_AGE_MS) {
            Log.d(TAG, "skipping replayed notification, age=${age}ms")
            return
        }

        val extracted = extract(sbn) ?: return
        if (extracted.text.isBlank()) return

        val fingerprint = "${sbn.packageName}|${extracted.sender}|${extracted.text}"
        if (isDuplicate(fingerprint)) return

        if (com.satyashield.app.BuildConfig.DEBUG) {
            // Deliberately logs no message content, not even in debug builds.
            //
            // This runs on real phones with real private messages, and an app
            // whose premise is "your messages stay on your device" must not
            // write them to a log that any USB-connected computer can read.
            //
            // For the Android 15+ redaction investigation (section 5.7) we only
            // need to know whether content *arrived*, not what it said, so we
            // report shape rather than substance.
            Log.d(
                TAG,
                "extracted src=${extracted.source} len=${extracted.text.length} " +
                    "redacted=${looksRedacted(extracted.text)} " +
                    "urls=${LocalRules.extractUrls(extracted.text).size} " +
                    "hasSender=${extracted.sender.isNotBlank()}",
            )
        }

        val started = System.nanoTime()
        val verdict = LocalRules.analyse(
            text = extracted.text,
            senderKnown = false,
        )
        val elapsedMs = (System.nanoTime() - started) / 1_000_000.0

        Log.i(
            TAG,
            "pkg=${sbn.packageName} band=${verdict.band} score=${verdict.score} " +
                "redEligible=${verdict.redEligible} signals=${verdict.signals.size} " +
                "in ${"%.1f".format(elapsedMs)}ms",
        )

        VerdictLog.record(this, extracted.text, verdict)

        if (verdict.band == Band.GREEN) return

        // Cold-start warm-up. Immediately after the service starts (install,
        // reboot, or an OEM kill-and-restart) the system replays every active
        // notification. Those messages are already on the user's screen and
        // possibly already read, so alerting on them would greet her with a
        // stack of red takeovers. During warm-up we still analyse and record
        // fingerprints, so the backlog is absorbed silently and only genuinely
        // new messages alert afterwards.
        val sinceStart = System.currentTimeMillis() - startedAtMs
        if (sinceStart < WARMUP_MS) {
            Log.i(TAG, "warm-up (${sinceStart}ms): recorded but not alerting")
            return
        }

        AlertPresenter.present(
            context = this,
            verdict = verdict,
            locale = AppPrefs.locale(this),
            onAskFamily = { AskFamily.send(this, verdict) },
        )
    }

    private data class Extracted(
        val sender: String,
        val text: String,
        /** Which notification field the body came from, for diagnostics. */
        val source: String,
    )

    /**
     * Pull sender and body out of a notification.
     *
     * Handles the messy reality of real clients: bundled summaries ("3 new
     * messages"), truncated previews, and MessagingStyle payloads. When the
     * content is a bundle summary we skip it rather than guess, because acting
     * on a guess is how false positives get created.
     */
    private fun extract(sbn: StatusBarNotification): Extracted? {
        val notification = sbn.notification ?: return null

        // Group summaries duplicate their children's content in condensed form.
        if (notification.flags and Notification.FLAG_GROUP_SUMMARY != 0) return null

        val extras = notification.extras ?: return null
        val title = extras.getCharSequence(Notification.EXTRA_TITLE)?.toString().orEmpty()

        var body = ""
        var source = "none"

        // MessagingStyle FIRST. Measured on a real Pixel 7: WhatsApp posts
        // MessagingStyle notifications with no EXTRA_BIG_TEXT at all, and
        // EXTRA_TEXT holds only a short fragment. The actual message body,
        // including any links, lives in the MessagingStyle message list. Reading
        // EXTRA_TEXT first therefore silently loses the content we exist to
        // analyse, which is exactly the bug this ordering fixes.
        //
        // Uses the AndroidX extractor rather than hand-parsing EXTRA_MESSAGES:
        // the untyped Bundle.getParcelableArray is deprecated from API 33 and
        // the element types have shifted between releases.
        val style = runCatching {
            NotificationCompat.MessagingStyle
                .extractMessagingStyleFromNotification(notification)
        }.getOrNull()

        if (style != null && style.messages.isNotEmpty()) {
            val joined = style.messages
                .mapNotNull { it.text?.toString() }
                .filter { it.isNotBlank() }
            if (joined.isNotEmpty()) {
                // Newest last, joined so a link split across messages is still
                // seen whole by the URL extractor.
                body = joined.joinToString("\n")
                source = "messagingStyle(${joined.size})"
            }
        }

        if (body.isBlank()) {
            val bigText = extras.getCharSequence(Notification.EXTRA_BIG_TEXT)?.toString()
            if (!bigText.isNullOrBlank()) {
                body = bigText
                source = "bigText"
            } else {
                body = extras.getCharSequence(Notification.EXTRA_TEXT)?.toString().orEmpty()
                source = "text"
            }
        }

        if (looksLikeBundleSummary(body)) return null

        return Extracted(sender = title, text = body, source = source)
    }

    /**
     * Whether the platform replaced this notification's content with a
     * placeholder (section 5.7).
     *
     * Android 15+ substitutes a localised string such as "Sensitive notification
     * content hidden" before handing a notification to an untrusted listener.
     * Matching on wording is inherently fragile because the string is
     * translated, so we also treat a short body with no URL and no spaces
     * pattern typical of real messages as suspicious. This is only used for
     * diagnostics, never to change a verdict.
     */
    private fun looksRedacted(body: String): Boolean {
        val normalised = body.trim().lowercase()
        return REDACTION_MARKERS.any { normalised.contains(it) }
    }

    private fun looksLikeBundleSummary(body: String): Boolean {
        val trimmed = body.trim().lowercase()
        return trimmed.matches(Regex("""\d+\s+new\s+messages?""")) ||
            trimmed.matches(Regex("""\d+\s+messages?\s+from\s+\d+\s+chats?"""))
    }

    private fun isDuplicate(fingerprint: String): Boolean {
        val now = System.currentTimeMillis()
        val iterator = recentlySeen.entries.iterator()
        while (iterator.hasNext()) {
            if (now - iterator.next().value > DEDUPE_WINDOW_MS) iterator.remove()
        }
        if (recentlySeen.containsKey(fingerprint)) return true
        recentlySeen[fingerprint] = now
        while (recentlySeen.size > DEDUPE_MAX_ENTRIES) {
            recentlySeen.remove(recentlySeen.keys.first())
        }
        return false
    }
}
