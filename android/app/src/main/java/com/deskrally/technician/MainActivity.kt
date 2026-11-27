package com.deskrally.technician

import android.Manifest
import android.annotation.SuppressLint
import android.app.Activity
import android.content.ActivityNotFoundException
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.Color
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import android.view.KeyEvent
import android.view.View
import android.view.ViewGroup
import android.view.WindowInsets
import android.webkit.CookieManager
import android.webkit.PermissionRequest
import android.webkit.ValueCallback
import android.webkit.WebChromeClient
import android.webkit.WebResourceRequest
import android.webkit.WebSettings
import android.webkit.WebView
import android.webkit.WebViewClient
import android.widget.FrameLayout
import android.window.OnBackInvokedDispatcher
import android.widget.Toast
import androidx.webkit.JavaScriptReplyProxy
import androidx.webkit.WebViewCompat
import androidx.webkit.WebViewFeature

/**
 * docs/78: the DeskRally console in the app's own WebView (replacing the Trusted Web Activity, so the app can keep
 * a live session running while the technician uses another app).
 *
 * Hardening (Chrome gave the TWA these for free; here they are ours):
 * - Only the console's origin loads in the WebView ([LaunchUrlPolicy]); any other link opens in the system browser.
 * - No file:// or content:// access, no mixed content, Safe Browsing on, no debugging in release builds.
 * - ONE bridge object (`window.DeskRallyApp`), injected only into the console origin, carrying only
 *   "session:on:<machine>" / "session:off" in and "end" out ([BridgeMessage]).
 * - Every page permission request (camera, microphone, ...) is denied; the console needs none.
 */
class MainActivity : Activity() {

    private lateinit var container: FrameLayout
    private lateinit var webView: WebView
    private val host = BuildConfig.CONSOLE_HOST
    private val handler = Handler(Looper.getMainLooper())

    /** Where to send "end": the console page that last talked to us. */
    private var replyProxy: JavaScriptReplyProxy? = null
    /** The machine of the live session, or null when none. */
    private var sessionMachine: String? = null
    /** When the app went to the background with a session live (elapsed realtime), or null. */
    private var backgroundedAt: Long? = null

    private var fileCallback: ValueCallback<Array<Uri>>? = null
    private var fullscreenView: View? = null
    /** Kept here: WebView.getWebChromeClient needs API 26 and the app supports 24. */
    private lateinit var chrome: WebChromeClient

    @SuppressLint("SetJavaScriptEnabled")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        WebView.setWebContentsDebuggingEnabled(BuildConfig.DEBUG)
        container = FrameLayout(this).apply { setBackgroundColor(Color.parseColor("#0B0D10")) }
        webView = WebView(this)
        container.addView(webView, ViewGroup.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT))
        setContentView(container)
        applyInsets()

        webView.settings.apply {
            javaScriptEnabled = true
            domStorageEnabled = true
            mediaPlaybackRequiresUserGesture = false
            allowFileAccess = false
            allowContentAccess = false
            mixedContentMode = WebSettings.MIXED_CONTENT_NEVER_ALLOW
            setSupportMultipleWindows(false)
            javaScriptCanOpenWindowsAutomatically = false
            if (Build.VERSION.SDK_INT >= 26) safeBrowsingEnabled = true
        }
        CookieManager.getInstance().apply {
            setAcceptCookie(true)
            setAcceptThirdPartyCookies(webView, false)
        }
        // A hidden WebView's renderer must not be the first thing Android kills while a session runs in the background.
        if (Build.VERSION.SDK_INT >= 26) {
            webView.setRendererPriorityPolicy(WebView.RENDERER_PRIORITY_IMPORTANT, false)
        }

        webView.webViewClient = object : WebViewClient() {
            override fun shouldOverrideUrlLoading(view: WebView, request: WebResourceRequest): Boolean {
                val url = request.url.toString()
                if (LaunchUrlPolicy.isConsoleUrl(url, host)) return false
                openExternally(request.url)
                return true
            }
        }
        chrome = object : WebChromeClient() {
            override fun onPermissionRequest(request: PermissionRequest) = request.deny()

            override fun onShowFileChooser(
                view: WebView, callback: ValueCallback<Array<Uri>>, params: FileChooserParams,
            ): Boolean {
                fileCallback?.onReceiveValue(null)
                fileCallback = callback
                return try {
                    startActivityForResult(params.createIntent(), REQUEST_FILES)
                    true
                } catch (_: ActivityNotFoundException) {
                    fileCallback = null
                    false
                }
            }

            // The console's full screen (Element.requestFullscreen) needs the host to show the custom view.
            override fun onShowCustomView(view: View, callback: CustomViewCallback) {
                fullscreenView = view
                container.addView(view, ViewGroup.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT))
                setFullscreenBars(true)
            }

            override fun onHideCustomView() {
                fullscreenView?.let { container.removeView(it) }
                fullscreenView = null
                setFullscreenBars(false)
            }
        }
        webView.webChromeClient = chrome
        webView.setDownloadListener { url, _, _, _, _ ->
            // An https download on the console host goes to the browser (it carries its own sign-in); in-page blob
            // downloads cannot leave a WebView without more plumbing (docs/78 v1 limitation).
            val uri = Uri.parse(url)
            if (url.startsWith("https://")) openExternally(uri)
            else Toast.makeText(this, "Downloads from the console are not available in the app yet; use a browser.", Toast.LENGTH_LONG).show()
        }

        if (Build.VERSION.SDK_INT >= 33) {
            onBackInvokedDispatcher.registerOnBackInvokedCallback(OnBackInvokedDispatcher.PRIORITY_DEFAULT) { handleBack() }
        }
        installBridge()
        webView.loadUrl(LaunchUrlPolicy.resolve(intent?.dataString, host))
        handleEndIntent(intent)
    }

    private fun installBridge() {
        if (!WebViewFeature.isFeatureSupported(WebViewFeature.WEB_MESSAGE_LISTENER)) return
        WebViewCompat.addWebMessageListener(webView, "DeskRallyApp", setOf("https://$host")) { _, message, origin, isMainFrame, proxy ->
            // Only the console's own top frame may drive the app (the allow-list already limits the origin).
            if (!isMainFrame || origin.toString().trimEnd('/') != "https://$host") return@addWebMessageListener
            replyProxy = proxy
            when (val m = BridgeMessage.parse(message.data)) {
                is BridgeMessage.SessionOn -> sessionStarted(m.machine)
                BridgeMessage.SessionOff -> sessionEnded()
                BridgeMessage.Unknown -> Unit
            }
        }
    }

    private fun sessionStarted(machine: String) {
        sessionMachine = machine
        askForNotifications()
        SessionService.start(this, machine)
    }

    private fun sessionEnded() {
        sessionMachine = null
        cancelBackgroundLimit()
        SessionService.stop(this)
    }

    /** Ask the console to end its session (the notification's End action, or the background limit). */
    private fun endSessionFromApp() {
        val proxy = replyProxy
        if (proxy != null && WebViewFeature.isFeatureSupported(WebViewFeature.WEB_MESSAGE_LISTENER)) {
            proxy.postMessage("end")
        }
        // Whatever the page does, the app stops holding itself up.
        sessionEnded()
    }

    // ---- background: keep running while a session is live, end it after 15 minutes ----

    override fun onStop() {
        super.onStop()
        CookieManager.getInstance().flush()
        // Hidden: the console drops to its background mode (about one frame a second), but its timers keep running so
        // the session lease is renewed. Deliberately NOT pauseTimers().
        webView.onPause()
        if (sessionMachine != null) {
            backgroundedAt = SystemClock.elapsedRealtime()
            scheduleBackgroundLimit()
        }
    }

    override fun onStart() {
        super.onStart()
        webView.onResume()
        cancelBackgroundLimit()
    }

    private val backgroundTick = object : Runnable {
        override fun run() {
            val since = backgroundedAt ?: return
            val machine = sessionMachine ?: return
            when (BackgroundLimit.due(SystemClock.elapsedRealtime() - since)) {
                BackgroundLimit.Action.END -> {
                    endSessionFromApp()
                    return
                }
                BackgroundLimit.Action.WARN -> if (!warned) {
                    warned = true
                    SessionService.warn(this@MainActivity, machine)
                }
                BackgroundLimit.Action.NONE -> Unit
            }
            handler.postDelayed(this, 30_000L)
        }
    }
    private var warned = false

    private fun scheduleBackgroundLimit() {
        warned = false
        handler.removeCallbacks(backgroundTick)
        handler.postDelayed(backgroundTick, 30_000L)
    }

    private fun cancelBackgroundLimit() {
        backgroundedAt = null
        handler.removeCallbacks(backgroundTick)
        if (warned) sessionMachine?.let { SessionService.start(this, it) } // back to the plain notification
        warned = false
    }

    // ---- intents, results, back ----

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        if (handleEndIntent(intent)) return
        val url = intent.dataString
        if (url != null && LaunchUrlPolicy.isConsoleUrl(url, host)) webView.loadUrl(url)
    }

    private fun handleEndIntent(intent: Intent?): Boolean {
        if (intent?.action != ACTION_END_SESSION) return false
        endSessionFromApp()
        return true
    }

    @Deprecated("Activity result API (platform Activity)")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        if (requestCode == REQUEST_FILES) {
            fileCallback?.onReceiveValue(WebChromeClient.FileChooserParams.parseResult(resultCode, data))
            fileCallback = null
            return
        }
        @Suppress("DEPRECATION")
        super.onActivityResult(requestCode, resultCode, data)
    }

    /** Back: leave full screen, then go back in the console; at its start the app goes to the background instead of
     *  closing, so a live session keeps running (docs/78). */
    private fun handleBack() {
        when {
            fullscreenView != null -> chrome.onHideCustomView()
            webView.canGoBack() -> webView.goBack()
            else -> moveTaskToBack(true)
        }
    }

    // Android 12 and older: the back key (Android 13+ uses the OnBackInvokedCallback registered in onCreate).
    override fun onKeyDown(keyCode: Int, event: KeyEvent): Boolean {
        if (Build.VERSION.SDK_INT < 33 && keyCode == KeyEvent.KEYCODE_BACK) {
            handleBack()
            return true
        }
        return super.onKeyDown(keyCode, event)
    }

    override fun onDestroy() {
        handler.removeCallbacks(backgroundTick)
        if (isFinishing) SessionService.stop(this)
        webView.destroy()
        super.onDestroy()
    }

    // ---- helpers ----

    private fun openExternally(uri: Uri) {
        try {
            startActivity(Intent(Intent.ACTION_VIEW, uri).addCategory(Intent.CATEGORY_BROWSABLE))
        } catch (_: ActivityNotFoundException) {
            Toast.makeText(this, "No app can open this link.", Toast.LENGTH_SHORT).show()
        }
    }

    private fun askForNotifications() {
        if (Build.VERSION.SDK_INT >= 33 &&
            checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) {
            requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), REQUEST_NOTIFICATIONS)
        }
    }

    private fun setFullscreenBars(on: Boolean) {
        if (Build.VERSION.SDK_INT >= 30) {
            window.insetsController?.let {
                if (on) it.hide(WindowInsets.Type.systemBars()) else it.show(WindowInsets.Type.systemBars())
            }
        }
    }

    /** Edge-to-edge (target SDK 35+): keep the console clear of the status and navigation bars and the keyboard. */
    private fun applyInsets() {
        container.setOnApplyWindowInsetsListener { v, insets ->
            if (Build.VERSION.SDK_INT >= 30) {
                val bars = insets.getInsets(WindowInsets.Type.systemBars() or WindowInsets.Type.ime())
                v.setPadding(bars.left, bars.top, bars.right, bars.bottom)
            }
            insets
        }
    }

    companion object {
        const val ACTION_END_SESSION = "com.deskrally.technician.END_SESSION"
        private const val REQUEST_FILES = 1
        private const val REQUEST_NOTIFICATIONS = 2
    }
}
