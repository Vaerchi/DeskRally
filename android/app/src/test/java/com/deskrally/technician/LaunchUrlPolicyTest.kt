package com.deskrally.technician

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class LaunchUrlPolicyTest {
    private val host = "main.deskrally.com"

    @Test
    fun acceptsHttpsUrlsOnTheConsoleHost() {
        assertTrue(LaunchUrlPolicy.isConsoleUrl("https://main.deskrally.com/", host))
        assertTrue(LaunchUrlPolicy.isConsoleUrl("https://main.deskrally.com/support/ABC123?x=1", host))
        assertTrue(LaunchUrlPolicy.isConsoleUrl("HTTPS://MAIN.DESKRALLY.COM/sessions/9", host))
        assertTrue(LaunchUrlPolicy.isConsoleUrl("https://main.deskrally.com:443/", host))
    }

    @Test
    fun rejectsOtherHostsSchemesAndPorts() {
        assertFalse(LaunchUrlPolicy.isConsoleUrl("https://evil.example/", host))
        assertFalse(LaunchUrlPolicy.isConsoleUrl("http://main.deskrally.com/", host))
        assertFalse(LaunchUrlPolicy.isConsoleUrl("https://main.deskrally.com:8443/", host))
        assertFalse(LaunchUrlPolicy.isConsoleUrl("https://main.deskrally.com.evil.example/", host))
        assertFalse(LaunchUrlPolicy.isConsoleUrl("javascript:alert(1)", host))
        assertFalse(LaunchUrlPolicy.isConsoleUrl("intent://x#Intent;end", host))
    }

    @Test
    fun rejectsUserinfoDecoys() {
        assertFalse(LaunchUrlPolicy.isConsoleUrl("https://main.deskrally.com@evil.example/", host))
        assertFalse(LaunchUrlPolicy.isConsoleUrl("https://user:pw@main.deskrally.com/", host))
    }

    @Test
    fun rejectsEmptyAndMalformed() {
        assertFalse(LaunchUrlPolicy.isConsoleUrl(null, host))
        assertFalse(LaunchUrlPolicy.isConsoleUrl("", host))
        assertFalse(LaunchUrlPolicy.isConsoleUrl("https://main.deskrally.com/a b", host))
    }

    @Test
    fun resolveFallsBackToTheStartPage() {
        assertEquals("https://main.deskrally.com/", LaunchUrlPolicy.resolve("https://evil.example/x", host))
        assertEquals("https://main.deskrally.com/", LaunchUrlPolicy.resolve(null, host))
        assertEquals(
            "https://main.deskrally.com/support/ABC",
            LaunchUrlPolicy.resolve("https://main.deskrally.com/support/ABC", host),
        )
    }

    @Test
    fun aTenantHostIsHonoured() {
        assertTrue(LaunchUrlPolicy.isConsoleUrl("https://console.example.com/", "console.example.com"))
        assertFalse(LaunchUrlPolicy.isConsoleUrl("https://main.deskrally.com/", "console.example.com"))
        assertEquals("https://console.example.com/", LaunchUrlPolicy.startUrl("console.example.com"))
    }
}
