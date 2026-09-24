package com.satyashield.app.ui

import android.Manifest
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.FilterChip
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalLifecycleOwner
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import com.satyashield.app.R
import com.satyashield.app.alert.AlertPresenter
import com.satyashield.app.alert.Speaker
import com.satyashield.app.alert.VerdictText
import com.satyashield.app.detect.Band
import com.satyashield.app.detect.LocalRules
import com.satyashield.app.service.AskFamily
import com.satyashield.app.settings.AppPrefs
import com.satyashield.app.settings.VerdictLog
import com.satyashield.app.setup.SelfTest
import java.util.Locale

/**
 * Setup and manual-check surface.
 *
 * Everything complicated lives here, because this screen is operated once by the
 * adult child (PRD section 4). The primary persona normally never opens the app
 * at all: she only ever sees the alert overlay.
 */
class MainActivity : ComponentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        Speaker.init(this)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            val launcher = registerForActivityResult(
                ActivityResultContracts.RequestPermission()
            ) { }
            launcher.launch(Manifest.permission.POST_NOTIFICATIONS)
        }

        setContent {
            SatyaShieldTheme {
                Scaffold { padding ->
                    MainScreen(Modifier.padding(padding))
                }
            }
        }
    }
}

@Composable
private fun MainScreen(modifier: Modifier = Modifier) {
    val context = LocalContext.current
    val lifecycleOwner = LocalLifecycleOwner.current

    // Permission state is re-read on resume because all three are granted in
    // Settings, outside our process, so there is no callback to rely on.
    var refreshKey by remember { mutableStateOf(0) }
    DisposableEffect(lifecycleOwner) {
        val observer = LifecycleEventObserver { _, event ->
            if (event == Lifecycle.Event.ON_RESUME) refreshKey++
        }
        lifecycleOwner.lifecycle.addObserver(observer)
        onDispose { lifecycleOwner.lifecycle.removeObserver(observer) }
    }

    val notificationsGranted = remember(refreshKey) {
        Permissions.notificationAccessGranted(context)
    }
    val overlayGranted = remember(refreshKey) { Permissions.overlayGranted(context) }
    val batteryGranted = remember(refreshKey) {
        Permissions.batteryExemptionGranted(context)
    }
    val protectionLive = notificationsGranted && overlayGranted

    var language by remember { mutableStateOf(AppPrefs.language(context)) }
    var contact by remember { mutableStateOf(AppPrefs.trustedContact(context).orEmpty()) }
    var pasted by remember { mutableStateOf("") }
    var selfTestState by remember { mutableStateOf<String?>(null) }

    Column(
        modifier = modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        StatusBanner(protectionLive)

        SectionTitle(stringRes(R.string.setup_title))
        Text(
            stringRes(R.string.setup_subtitle),
            style = MaterialTheme.typography.bodyMedium,
        )

        PermissionRow(
            title = stringRes(R.string.setup_step_notifications),
            why = stringRes(R.string.setup_step_notifications_why),
            granted = notificationsGranted,
            onGrant = { Permissions.openNotificationAccessSettings(context) },
        )
        PermissionRow(
            title = stringRes(R.string.setup_step_overlay),
            why = stringRes(R.string.setup_step_overlay_why),
            granted = overlayGranted,
            onGrant = { Permissions.openOverlaySettings(context) },
        )
        PermissionRow(
            title = stringRes(R.string.setup_step_battery),
            why = stringRes(R.string.setup_step_battery_why),
            granted = batteryGranted,
            onGrant = { Permissions.requestBatteryExemption(context) },
        )

        SectionTitle(stringRes(R.string.setup_step_language))
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            AppPrefs.Language.entries.forEach { option ->
                FilterChip(
                    selected = language == option,
                    onClick = {
                        language = option
                        AppPrefs.setLanguage(context, option)
                    },
                    label = { Text(option.label) },
                )
            }
        }

        // Voice-data status (F28). A missing voice makes the spoken verdict
        // silently useless, and the user would never find out on their own, so
        // it is surfaced during setup rather than discovered during a scam.
        SectionTitle(stringRes(R.string.voice_title))
        val voiceLocale = remember(language) { Locale.forLanguageTag(language.tag) }
        val voiceReady = remember(language, refreshKey, selfTestState) {
            Speaker.hasVoiceFor(voiceLocale)
        }
        Card(shape = RoundedCornerShape(12.dp), modifier = Modifier.fillMaxWidth()) {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(
                    stringRes(if (voiceReady) R.string.voice_ok else R.string.voice_missing),
                    style = MaterialTheme.typography.bodyMedium,
                    color = if (voiceReady) BandGreen else BandAmber,
                    fontWeight = FontWeight.Bold,
                )
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    OutlinedButton(
                        onClick = {
                            val localized = AppPrefs.localizedContext(context, language)
                            Speaker.speak(
                                localized.getString(R.string.voice_test_line),
                                voiceLocale,
                            )
                        },
                        modifier = Modifier.height(52.dp),
                    ) { Text(stringRes(R.string.voice_test)) }

                    if (!voiceReady) {
                        OutlinedButton(
                            onClick = {
                                runCatching {
                                    context.startActivity(Speaker.installVoiceDataIntent())
                                }
                            },
                            modifier = Modifier.height(52.dp),
                        ) { Text(stringRes(R.string.voice_install)) }
                    }
                }
            }
        }

        SectionTitle(stringRes(R.string.alert_ask_family))
        OutlinedTextField(
            value = contact,
            onValueChange = {
                contact = it
                AppPrefs.setTrustedContact(context, it)
            },
            label = { Text("Family phone number") },
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Phone),
            modifier = Modifier.fillMaxWidth(),
        )

        SectionTitle(stringRes(R.string.selftest_title))
        Text(stringRes(R.string.selftest_body), style = MaterialTheme.typography.bodyMedium)
        Button(
            onClick = {
                selfTestState = stringRes(context, R.string.selftest_waiting)
                SelfTest.run(context) { result ->
                    selfTestState = stringRes(
                        context,
                        if (result == SelfTest.Result.PASS) R.string.selftest_pass
                        else R.string.selftest_fail,
                    )
                }
            },
            enabled = notificationsGranted,
            modifier = Modifier.fillMaxWidth().height(60.dp),
        ) { Text(stringRes(R.string.selftest_run)) }

        selfTestState?.let {
            Text(it, style = MaterialTheme.typography.bodyLarge, fontWeight = FontWeight.Bold)
        }

        SectionTitle(stringRes(R.string.home_check_something))
        OutlinedTextField(
            value = pasted,
            onValueChange = { pasted = it },
            label = { Text(stringRes(R.string.home_paste_hint)) },
            modifier = Modifier.fillMaxWidth(),
            minLines = 3,
        )
        Button(
            onClick = {
                if (pasted.isBlank()) return@Button
                val verdict = LocalRules.analyse(pasted, senderKnown = false)
                VerdictLog.record(context, pasted, verdict)
                if (verdict.band == Band.GREEN) {
                    val rendered = VerdictText.render(context, verdict)
                    Speaker.speak(rendered.spoken, AppPrefs.locale(context))
                } else {
                    AlertPresenter.present(
                        context = context.applicationContext,
                        verdict = verdict,
                        locale = AppPrefs.locale(context),
                        onAskFamily = {
                            AskFamily.send(context.applicationContext, verdict)
                        },
                    )
                }
            },
            modifier = Modifier.fillMaxWidth().height(60.dp),
        ) { Text(stringRes(R.string.home_check_now)) }

        SectionTitle(stringRes(R.string.home_recent))
        val recent = remember(refreshKey, selfTestState, pasted) { VerdictLog.recent() }
        if (recent.isEmpty()) {
            Text(stringRes(R.string.home_no_recent), style = MaterialTheme.typography.bodyMedium)
        } else {
            recent.take(8).forEach { entry ->
                RecentRow(entry.band, entry.score, entry.excerpt)
            }
        }

        Spacer(Modifier.height(24.dp))
    }
}

@Composable
private fun StatusBanner(live: Boolean) {
    Card(
        colors = CardDefaults.cardColors(
            containerColor = if (live) BandGreen else BandAmber
        ),
        shape = RoundedCornerShape(16.dp),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Row(
            modifier = Modifier.padding(20.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Text(if (live) "\u2713" else "!", color = Color.White, fontWeight = FontWeight.Bold)
            Text(
                stringRes(if (live) R.string.home_protected else R.string.home_not_protected),
                color = Color.White,
                style = MaterialTheme.typography.titleLarge,
                fontWeight = FontWeight.Bold,
            )
        }
    }
}

@Composable
private fun PermissionRow(
    title: String,
    why: String,
    granted: Boolean,
    onGrant: () -> Unit,
) {
    Card(shape = RoundedCornerShape(12.dp), modifier = Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(title, style = MaterialTheme.typography.bodyLarge, fontWeight = FontWeight.Bold)
            Text(why, style = MaterialTheme.typography.bodyMedium)
            if (granted) {
                Text(
                    "\u2713 " + stringRes(R.string.setup_granted),
                    color = BandGreen,
                    fontWeight = FontWeight.Bold,
                )
            } else {
                OutlinedButton(onClick = onGrant, modifier = Modifier.height(52.dp)) {
                    Text(stringRes(R.string.setup_open_settings))
                }
            }
        }
    }
}

@Composable
private fun RecentRow(band: Band, score: Float, excerpt: String) {
    val color = when (band) {
        Band.RED -> BandRed
        Band.AMBER -> BandAmber
        Band.GREEN -> BandGreen
    }
    Row(
        modifier = Modifier.fillMaxWidth().padding(vertical = 6.dp),
        horizontalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Column(
            Modifier
                .size(width = 8.dp, height = 48.dp)
                .background(color, RoundedCornerShape(4.dp))
        ) {}
        Column(Modifier.fillMaxWidth()) {
            Text(
                "${band.name}  ${score.toInt()}",
                style = MaterialTheme.typography.labelLarge,
                fontWeight = FontWeight.Bold,
                color = color,
            )
            Text(
                excerpt.take(90),
                style = MaterialTheme.typography.bodyMedium,
                maxLines = 2,
            )
        }
    }
}

@Composable
private fun SectionTitle(text: String) {
    Text(
        text,
        style = MaterialTheme.typography.headlineMedium,
        fontWeight = FontWeight.Bold,
        modifier = Modifier.padding(top = 8.dp),
    )
}

@Composable
private fun stringRes(id: Int): String = LocalContext.current.getString(id)

private fun stringRes(context: android.content.Context, id: Int): String =
    context.getString(id)
