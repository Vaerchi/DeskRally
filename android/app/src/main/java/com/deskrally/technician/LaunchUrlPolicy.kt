package com.deskrally.technician

import java.net.URI

/**
 * Decides which URLs the app is willing to open inside its Trusted Web Activity.
 *
 * The intent-filter already limits implicit VIEW intents to the console host, but the launcher
 * activity is exported, so any app can also fire an EXPLICIT intent carrying an arbitrary URL.
 * Anything that is not an https URL on the configured console host is replaced with the console
 * start page rather than opened.
 *
 * Pure JVM (java.net.URI, no android.net.Uri) so it is covered by plain unit tests.
 */
object LaunchUrlPolicy {

    fun startUrl(host: String): String = "https://$host/"

    fun isConsoleUrl(url: String?, host: String): Boolean {
        if (url.isNullOrBlank()) return false
        val uri = try {
            URI(url)
        } catch (_: Exception) {
            return false
        }
        // A URL with userinfo ("https://main.deskrally.com@evil.example/") parses with the real
        // host in `host` and the decoy in `userInfo`; refuse it outright.
        if (uri.userInfo != null) return false
        return uri.scheme.equals("https", ignoreCase = true) &&
            uri.host.equals(host, ignoreCase = true) &&
            (uri.port == -1 || uri.port == 443)
    }

    /** The URL to launch: [requested] if it is on the console host, else the start page. */
    fun resolve(requested: String?, host: String): String =
        if (isConsoleUrl(requested, host)) requested!! else startUrl(host)
}
