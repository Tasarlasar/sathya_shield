package com.satyashield.app.ui

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Typography
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.unit.sp

val BandRed = Color(0xFFB3261E)
val BandAmber = Color(0xFFB26B00)
val BandGreen = Color(0xFF1B6B3A)
val BrandNavy = Color(0xFF10233F)

private val colors = lightColorScheme(
    primary = BrandNavy,
    onPrimary = Color.White,
    surface = Color(0xFFF7F7F9),
    onSurface = Color(0xFF1A1C1E),
    error = BandRed,
)

/**
 * Type scale is deliberately larger than Material defaults.
 *
 * PRD section 8.5 requires a minimum 20sp body size: the primary persona may
 * read slowly or have uncorrected vision, and default 14sp body text excludes
 * her from her own protection.
 */
private val typography = Typography(
    headlineLarge = TextStyle(fontSize = 34.sp, lineHeight = 42.sp),
    headlineMedium = TextStyle(fontSize = 28.sp, lineHeight = 36.sp),
    titleLarge = TextStyle(fontSize = 24.sp, lineHeight = 32.sp),
    bodyLarge = TextStyle(fontSize = 20.sp, lineHeight = 28.sp),
    bodyMedium = TextStyle(fontSize = 18.sp, lineHeight = 26.sp),
    labelLarge = TextStyle(fontSize = 18.sp, lineHeight = 24.sp),
)

@Composable
fun SatyaShieldTheme(content: @Composable () -> Unit) {
    MaterialTheme(colorScheme = colors, typography = typography, content = content)
}
