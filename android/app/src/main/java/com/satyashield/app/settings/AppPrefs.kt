package com.satyashield.app.settings

import android.content.Context
import android.content.SharedPreferences
import android.content.res.Configuration
import java.util.Locale

/**
 * Simple persisted settings.
 *
 * All configuration is written during setup by the secondary persona (the adult
 * child) and is never surfaced to the primary user, per PRD section 8.5.
 */
object AppPrefs {

    private const val FILE = "satyashield_prefs"
    private const val KEY_PROTECTION = "protection_enabled"
    private const val KEY_LANGUAGE = "language"
    private const val KEY_TRUSTED_CONTACT = "trusted_contact"
    private const val KEY_LISTENER_CONNECTED = "listener_connected"

    /** Supported spoken languages (F32). */
    enum class Language(val tag: String, val label: String) {
        EN("en", "English"),
        HI("hi", "हिंदी"),
        TA("ta", "தமிழ்"),
        ;

        companion object {
            fun fromTag(tag: String?): Language =
                entries.firstOrNull { it.tag == tag } ?: EN
        }
    }

    private fun prefs(context: Context): SharedPreferences =
        context.applicationContext.getSharedPreferences(FILE, Context.MODE_PRIVATE)

    /**
     * A Context whose resources resolve in the user's chosen language.
     *
     * Without this, `context.getString()` resolves against the *device* locale,
     * not our setting. Measured on a real Pixel whose system locale was en-JP:
     * selecting हिंदी in the app produced English strings spoken by a Hindi
     * voice, which sounds like English in an accent and is useless to the person
     * this feature exists for.
     *
     * The whole point of section 8.4 is that each language is authored
     * separately, so the app must read from `values-hi` / `values-ta` regardless
     * of how the phone itself is configured.
     */
    fun localizedContext(context: Context, language: Language = language(context)): Context {
        val locale = Locale.forLanguageTag(language.tag)
        val config = Configuration(context.resources.configuration).apply {
            setLocale(locale)
            setLayoutDirection(locale)
        }
        return context.createConfigurationContext(config)
    }

    fun isProtectionEnabled(context: Context): Boolean =
        prefs(context).getBoolean(KEY_PROTECTION, true)

    fun setProtectionEnabled(context: Context, enabled: Boolean) {
        prefs(context).edit().putBoolean(KEY_PROTECTION, enabled).apply()
    }

    fun language(context: Context): Language =
        Language.fromTag(prefs(context).getString(KEY_LANGUAGE, null))

    fun setLanguage(context: Context, language: Language) {
        prefs(context).edit().putString(KEY_LANGUAGE, language.tag).apply()
    }

    fun locale(context: Context): Locale = Locale.forLanguageTag(language(context).tag)

    fun trustedContact(context: Context): String? =
        prefs(context).getString(KEY_TRUSTED_CONTACT, null)

    fun setTrustedContact(context: Context, number: String?) {
        prefs(context).edit().putString(KEY_TRUSTED_CONTACT, number?.trim()).apply()
    }

    /**
     * Whether the system has actually bound our listener.
     *
     * Distinct from "the user granted notification access": on aggressive OEM
     * builds the grant can be present while the service is not running, which is
     * exactly the silent-failure mode the self-test exists to catch.
     */
    fun isListenerConnected(context: Context): Boolean =
        prefs(context).getBoolean(KEY_LISTENER_CONNECTED, false)

    fun setListenerConnected(context: Context, connected: Boolean) {
        prefs(context).edit().putBoolean(KEY_LISTENER_CONNECTED, connected).apply()
    }
}
