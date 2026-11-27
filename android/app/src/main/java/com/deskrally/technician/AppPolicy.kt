package com.deskrally.technician

/**
 * docs/78: the app's pure rules (no Android types, covered by plain unit tests).
 *
 * - [BackgroundLimit]: a live session in the background ends after 15 minutes, with a warning shortly before
 *   (the operator's choice, 2026-11-27).
 * - [BridgeMessage]: what the console may tell the app over the one bridge (session on/off + machine name).
 */
object BackgroundLimit {
    const val END_AFTER_MS: Long = 15 * 60_000L
    const val WARN_AFTER_MS: Long = 13 * 60_000L

    enum class Action { NONE, WARN, END }

    /** What is due [elapsedMs] after the app went to the background with a session live. */
    fun due(elapsedMs: Long): Action = when {
        elapsedMs >= END_AFTER_MS -> Action.END
        elapsedMs >= WARN_AFTER_MS -> Action.WARN
        else -> Action.NONE
    }
}

sealed class BridgeMessage {
    data class SessionOn(val machine: String) : BridgeMessage()
    object SessionOff : BridgeMessage()
    object Unknown : BridgeMessage()

    companion object {
        private const val ON = "session:on:"
        private val CONTROL = Regex("[\\u0000-\\u001f\\u007f-\\u009f\\u200b-\\u200f\\u202a-\\u202e\\u2066-\\u2069]")

        /** Parse one message from the console. Anything else is [Unknown] and ignored. */
        fun parse(raw: String?): BridgeMessage = when {
            raw == null || raw.length > 200 -> Unknown
            raw == "session:off" -> SessionOff
            raw.startsWith(ON) -> SessionOn(machineName(raw.substring(ON.length)))
            else -> Unknown
        }

        /** One line, no control or direction characters, at most 60 chars (the notification shows it). */
        fun machineName(name: String): String {
            val clean = CONTROL.replace(name, " ").replace(Regex("\\s+"), " ").trim()
            return (clean.ifEmpty { "a machine" }).take(60)
        }
    }
}
