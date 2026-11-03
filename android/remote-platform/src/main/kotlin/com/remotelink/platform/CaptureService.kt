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
        if (Build.VERSION.SDK_INT >= 29) startForeground(4134, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_MEDIA_PROJECTION)
        else startForeground(4134, notification)
        return START_NOT_STICKY
    }

    override fun onDestroy() { stopForeground(STOP_FOREGROUND_REMOVE); super.onDestroy() }
    override fun onBind(intent: Intent?): IBinder? = null

    private companion object { const val CHANNEL = "remote_link_capture" }
}
