package com.deskrally.technician

import org.junit.Assert.assertEquals
import org.junit.Test

class AppPolicyTest {

    @Test
    fun backgroundLimitWarnsThenEndsAtFifteenMinutes() {
        assertEquals(BackgroundLimit.Action.NONE, BackgroundLimit.due(0))
        assertEquals(BackgroundLimit.Action.NONE, BackgroundLimit.due(13 * 60_000L - 1))
        assertEquals(BackgroundLimit.Action.WARN, BackgroundLimit.due(13 * 60_000L))
        assertEquals(BackgroundLimit.Action.WARN, BackgroundLimit.due(15 * 60_000L - 1))
        assertEquals(BackgroundLimit.Action.END, BackgroundLimit.due(15 * 60_000L))
    }

    @Test
    fun bridgeMessagesParseStrictly() {
        assertEquals(BridgeMessage.SessionOn("FRONT-DESK-01"), BridgeMessage.parse("session:on:FRONT-DESK-01"))
        assertEquals(BridgeMessage.SessionOff, BridgeMessage.parse("session:off"))
        assertEquals(BridgeMessage.Unknown, BridgeMessage.parse("session:offline"))
        assertEquals(BridgeMessage.Unknown, BridgeMessage.parse("end"))
        assertEquals(BridgeMessage.Unknown, BridgeMessage.parse(null))
        assertEquals(BridgeMessage.Unknown, BridgeMessage.parse("session:on:" + "x".repeat(300)))
    }

    @Test
    fun machineNamesAreCleanedForTheNotification() {
        assertEquals("a b c d", BridgeMessage.machineName("a\u0000b\nc‮d"))
        assertEquals("a machine", BridgeMessage.machineName("   "))
        assertEquals(60, BridgeMessage.machineName("y".repeat(100)).length)
    }
}
