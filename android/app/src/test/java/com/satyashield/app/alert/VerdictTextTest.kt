package com.satyashield.app.alert

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** Tests for the message-quoting helper (task 2). */
class VerdictTextTest {

    @Test
    fun `short message is quoted whole`() {
        val text = "Pay now at http://x.top/a"
        assertEquals(text, VerdictText.quoteFor(text))
    }

    @Test
    fun `whitespace is collapsed`() {
        assertEquals(
            "line one line two",
            VerdictText.quoteFor("line one\n\n   line two"),
        )
    }

    @Test
    fun `long message is truncated with an ellipsis`() {
        val long = "x".repeat(500)
        val quoted = VerdictText.quoteFor(long)
        assertTrue(quoted.length <= VerdictText.MAX_QUOTE_CHARS + 1)
        assertTrue(quoted.endsWith("\u2026"))
    }

    @Test
    fun `empty message quotes to empty`() {
        assertEquals("", VerdictText.quoteFor(""))
        assertEquals("", VerdictText.quoteFor("   \n  "))
    }
}
