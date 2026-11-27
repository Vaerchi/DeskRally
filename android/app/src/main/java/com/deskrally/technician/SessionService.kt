package com.deskrally.technician

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import android.os.PowerManager

/**
 * docs/78: keeps the app (and so its WebView and the console page in it) running while a session is live and the
 * technician uses another app. Foreground service type `specialUse` ("an active remote-support session"), with an
 * ongoing notification naming the machine and an End action. It holds a partial wake lock so a session survives the
 * screen turning off. It does nothing else: renewing the session lease is still the page's job, so the
 * control plane's revocation window (~32 s) is unchanged.
 */
class SessionService : Service() {

    private var wakeLock: PowerManager.WakeLock? = null

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                stopSelf()
                return START_NOT_STICKY
            }
            ACTION_WARN -> notify(build(intent.getStringExtra(EXTRA_MACHINE) ?: "a machine", warning = true))
            else -> {
                val machine = intent?.getStringExtra(EXTRA_MACHINE) ?: "a machine"
                val n = build(machine, warning = false)
                if (Build.VERSION.SDK_INT >= 34) {
                    startForeground(NOTIFICATION_ID, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
                } else {
                    startForeground(NOTIFICATION_ID, n)
                }
                acquireWakeLock()
            }
        }
        // Not restarted by the system after a kill: a session cannot survive the app process anyway.
        return START_NOT_STICKY
    }

    override fun onDestroy() {
        wakeLock?.let { if (it.isHeld) it.release() }
        wakeLock = null
        super.onDestroy()
    }

    private fun acquireWakeLock() {
        if (wakeLock?.isHeld == true) return
        val pm = getSystemService(Context.POWER_SERVICE) as PowerManager
        // Bounded so a forgotten lock can never drain a phone: the background limit ends a session at 15 minutes,
        // and a session in the foreground keeps the screen on by itself.
        wakeLock = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "DeskRally:session").apply {
            setReferenceCounted(false)
            acquire(4 * 60 * 60_000L)
        }
    }

    private fun notify(n: Notification) {
        (getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager).notify(NOTIFICATION_ID, n)
    }

    private fun build(machine: String, warning: Boolean): Notification {
        val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        if (Build.VERSION.SDK_INT >= 26 && nm.getNotificationChannel(CHANNEL_ID) == null) {
            nm.createNotificationChannel(
                NotificationChannel(CHANNEL_ID, "Active session", NotificationManager.IMPORTANCE_LOW).apply {
                    description = "Shown while a DeskRally session is connected"
                },
            )
        }
        val openApp = PendingIntent.getActivity(
            this, 0, Intent(this, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val end = PendingIntent.getActivity(
            this, 1,
            Intent(this, MainActivity::class.java).setAction(MainActivity.ACTION_END_SESSION)
                .addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val text = if (warning) {
            "This session ends in 2 minutes because DeskRally is in the background. Open it to keep the session."
        } else {
            "Connected to $machine"
        }
        @Suppress("DEPRECATION")
        val b = if (Build.VERSION.SDK_INT >= 26) Notification.Builder(this, CHANNEL_ID) else Notification.Builder(this)
        return b.setSmallIcon(android.R.drawable.ic_menu_view)
            .setContentTitle("DeskRally session active")
            .setContentText(text)
            .setStyle(Notification.BigTextStyle().bigText(text))
            .setOngoing(true)
            .setOnlyAlertOnce(!warning)
            .setContentIntent(openApp)
            .addAction(Notification.Action.Builder(null, "End session", end).build())
            .build()
    }

    companion object {
        const val CHANNEL_ID = "session"
        const val NOTIFICATION_ID = 1
        const val EXTRA_MACHINE = "machine"
        const val ACTION_STOP = "com.deskrally.technician.STOP"
        const val ACTION_WARN = "com.deskrally.technician.WARN"

        fun start(context: Context, machine: String) {
            val i = Intent(context, SessionService::class.java).putExtra(EXTRA_MACHINE, machine)
            if (Build.VERSION.SDK_INT >= 26) context.startForegroundService(i) else context.startService(i)
        }

        fun warn(context: Context, machine: String) {
            context.startService(Intent(context, SessionService::class.java).setAction(ACTION_WARN).putExtra(EXTRA_MACHINE, machine))
        }

        fun stop(context: Context) {
            context.stopService(Intent(context, SessionService::class.java))
        }
    }
}
