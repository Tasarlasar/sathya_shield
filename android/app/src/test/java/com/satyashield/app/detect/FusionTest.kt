package com.satyashield.app.detect

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Guards the rule-gated RED invariant on the client side.
 *
 * The backend has the same tests in `tests/test_fusion.py`. Both must hold: a
 * message may be judged locally (offline) or remotely (deeper pillars), and the
 * two must never disagree about whether it is permissible to take over the
 * user's screen.
 */
class FusionTest {

    private fun det(severity: Severity, weight: Float = 1f, code: String = "RULE") = Signal(
        code = code,
        pillar = Pillar.URL,
        severity = severity,
        deterministic = true,
        weight = weight,
        reasonRes = 0,
    )

    private fun model(severity: Severity, weight: Float = 1f, code: String = "MODEL") = Signal(
        code = code,
        pillar = Pillar.TEXT,
        severity = severity,
        deterministic = false,
        weight = weight,
        reasonRes = 0,
    )

    @Test
    fun `no signals is green`() {
        val verdict = Fusion.decide(emptyList())
        assertEquals(Band.GREEN, verdict.band)
        assertEquals(0f, verdict.score, 0.001f)
        assertFalse(verdict.interrupts)
    }

    @Test
    fun `single deterministic critical authorises red`() {
        val verdict = Fusion.decide(listOf(det(Severity.CRITICAL, 1.5f)))
        assertTrue(verdict.redEligible)
        assertEquals(Band.RED, verdict.band)
        assertTrue(verdict.interrupts)
    }

    @Test
    fun `two deterministic high authorise red`() {
        val verdict = Fusion.decide(
            listOf(det(Severity.HIGH, 1.4f, "A"), det(Severity.HIGH, 1.3f, "B"))
        )
        assertTrue(verdict.redEligible)
        assertEquals(Band.RED, verdict.band)
    }

    @Test
    fun `single deterministic high is only amber`() {
        val verdict = Fusion.decide(listOf(det(Severity.HIGH, 1.4f)))
        assertFalse(verdict.redEligible)
        assertEquals(Band.AMBER, verdict.band)
        assertFalse(verdict.interrupts)
    }

    @Test
    fun `model signal at max confidence cannot reach red`() {
        val verdict = Fusion.decide(listOf(model(Severity.CRITICAL, 5f)))
        assertFalse(verdict.redEligible)
        assertEquals(Band.AMBER, verdict.band)
    }

    @Test
    fun `overwhelming model evidence still cannot reach red`() {
        val signals = (0 until 20).map { model(Severity.CRITICAL, 5f, "MODEL_$it") }
        val verdict = Fusion.decide(signals)
        assertTrue("expected a high score", verdict.score > 90f)
        assertFalse("model output must never authorise RED", verdict.redEligible)
        assertEquals("model output must be capped at AMBER", Band.AMBER, verdict.band)
        assertFalse(verdict.interrupts)
    }

    @Test
    fun `models cannot top up a single rule to reach red`() {
        val signals = listOf(det(Severity.HIGH, 1.4f)) +
            (0 until 10).map { model(Severity.CRITICAL, 3f, "MODEL_$it") }
        val verdict = Fusion.decide(signals)
        assertFalse(verdict.redEligible)
        assertEquals(Band.AMBER, verdict.band)
    }

    @Test
    fun `red needs the score floor as well as the gate`() {
        val verdict = Fusion.decide(listOf(det(Severity.CRITICAL, 0.05f)))
        assertTrue("gate opens", verdict.redEligible)
        assertTrue("score floor not met", verdict.score < Fusion.RED_SCORE_MIN)
        assertFalse(verdict.band == Band.RED)
    }

    @Test
    fun `severity dominates over count`() {
        val critical = Fusion.riskScore(listOf(det(Severity.CRITICAL, 1.5f)))
        val trivia = Fusion.riskScore((0 until 3).map { det(Severity.LOW, 0.6f, "L$it") })
        assertTrue(critical > trivia)
    }

    @Test
    fun `ranking puts most severe first and rules ahead of models`() {
        val ranked = Fusion.rank(
            listOf(
                det(Severity.LOW, code = "LOW"),
                model(Severity.HIGH, code = "MODEL"),
                det(Severity.HIGH, code = "RULE"),
                det(Severity.CRITICAL, code = "CRIT"),
            )
        )
        assertEquals(listOf("CRIT", "RULE", "MODEL", "LOW"), ranked.map { it.code })
    }
}
