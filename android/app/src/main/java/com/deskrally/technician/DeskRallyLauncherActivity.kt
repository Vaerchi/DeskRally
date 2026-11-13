package com.deskrally.technician

import android.net.Uri
import com.google.androidbrowserhelper.trusted.LauncherActivity

/**
 * Opens the DeskRally console as a Trusted Web Activity (Chrome, full screen, no URL bar once
 * Digital Asset Links verify), falling back to a Custom Tab where no TWA-capable browser exists.
 *
 * The console is NOT embedded in a WebView on purpose: Google and Microsoft block SSO sign-in in
 * embedded WebViews, and the typing bar and WebRTC stack are proven against Chrome.
 *
 * Everything else (default URL, bar colours, splash) is declared as manifest meta-data and fed by
 * the single `deskrally.consoleHost` Gradle property.
 */
class DeskRallyLauncherActivity : LauncherActivity() {

    override fun getLaunchingUrl(): Uri {
        val requested = super.getLaunchingUrl()
        return Uri.parse(LaunchUrlPolicy.resolve(requested.toString(), BuildConfig.CONSOLE_HOST))
    }
}
