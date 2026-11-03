package com.remotelink.platform

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.Handler
import android.os.IBinder
import android.os.Looper

/** Never runs hidden and never starts at boot. Stop always revokes input immediately. */
class SessionIndicatorService : Service() {
    private val handler = Handler(Looper.getMainLooper())
    private val watchdog = object : Runnable {
        override fun run() {
            val manager = getSystemService(NotificationManager::class.java)
            val enabled = manager.areNotificationsEnabled() && manager.getNotificationChannel(CHANNEL)?.importance != NotificationManager.IMPORTANCE_NONE
            if (!SessionGate.isActive() || !enabled) { SessionGate.revoke(); stopSelf(); return }
            handler.postDelayed(this, 1_000)
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == STOP || !SessionGate.isActive()) {
            SessionGate.revoke(); stopSelf(); return START_NOT_STICKY
        }
        val manager = getSystemService(NotificationManager::class.java)
        manager.createNotificationChannel(NotificationChannel(CHANNEL, "Active remote session", NotificationManager.IMPORTANCE_LOW))
        val stop = PendingIntent.getService(this, 0, Intent(this, javaClass).setAction(STOP), PendingIntent.FLAG_IMMUTABLE)
        val notification = Notification.Builder(this, CHANNEL)
            .setSmallIcon(android.R.drawable.stat_sys_warning)
            .setContentTitle("Remote Link session active")
            .setContentText("Another device can use the permissions you allowed. Tap Stop to revoke access.")
            .setOngoing(true).setCategory(Notification.CATEGORY_SERVICE)
            .addAction(Notification.Action.Builder(null, "Stop", stop).build()).build()
        if (Build.VERSION.SDK_INT >= 34) startForeground(4132, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        else startForeground(4132, notification)
        handler.removeCallbacks(watchdog); handler.post(watchdog)
        return START_NOT_STICKY
    }

    override fun onDestroy() {
        handler.removeCallbacksAndMessages(null)
        SessionGate.revoke()
        stopForeground(STOP_FOREGROUND_REMOVE)
        super.onDestroy()
    }
    override fun onBind(intent: Intent?): IBinder? = null

    companion object {
        const val STOP = "com.remotelink.platform.STOP"
        private const val CHANNEL = "remote_link_session"
    }
}
