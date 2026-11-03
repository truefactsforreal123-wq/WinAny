package com.remotelink.platform

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder

/** Foreground service required by Android 14+ while MediaProjection screen capture runs. */
class CaptureService : Service() {
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        getSystemService(NotificationManager::class.java)
            .createNotificationChannel(NotificationChannel(CHANNEL, "Screen sharing", NotificationManager.IMPORTANCE_LOW))
        val notification = Notification.Builder(this, CHANNEL)
            .setSmallIcon(android.R.drawable.stat_sys_warning)
            .setContentTitle("Remote Link is sharing your screen")
            .setOngoing(true).build()
        try {
            if (Build.VERSION.SDK_INT >= 29) startForeground(4134, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_MEDIA_PROJECTION)
            else startForeground(4134, notification)
            state = 1
        } catch (failure: Exception) {
            // Android 14+ throws SecurityException without projection consent; never crash the app.
            state = -1
            stopSelf()
        }
        return START_NOT_STICKY
    }

    override fun onDestroy() { stopForeground(STOP_FOREGROUND_REMOVE); super.onDestroy() }
    override fun onBind(intent: Intent?): IBinder? = null

    companion object {
        /** 0 = start pending, 1 = foreground started, -1 = startForeground failed. Polled by MainActivity. */
        @Volatile var state = 0
        private const val CHANNEL = "remote_link_capture"
    }
}
