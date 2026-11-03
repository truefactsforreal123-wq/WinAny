package com.remotelink.app

import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Intent
import android.provider.Settings
import android.os.Handler
import android.os.Looper
import android.os.Build
import android.Manifest
import android.app.NotificationManager
import android.app.NotificationChannel
import android.content.pm.PackageManager
import com.remotelink.platform.RemoteAccessibilityService
import com.remotelink.platform.CaptureService
import com.remotelink.platform.SessionGate
import com.remotelink.platform.SessionIndicatorService
import org.json.JSONObject

class MainActivity : FlutterActivity() {
    private var channel: MethodChannel? = null
    private var notificationRequest: MethodChannel.Result? = null

    private fun notificationsAvailable(): Boolean {
        val manager = getSystemService(NotificationManager::class.java)
        manager.createNotificationChannel(NotificationChannel("remote_link_session", "Active remote session", NotificationManager.IMPORTANCE_LOW))
        return manager.areNotificationsEnabled() &&
            manager.getNotificationChannel("remote_link_session").importance != NotificationManager.IMPORTANCE_NONE &&
            (Build.VERSION.SDK_INT < 33 || checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) == PackageManager.PERMISSION_GRANTED)
    }

    override fun onRequestPermissionsResult(requestCode: Int, permissions: Array<out String>, grantResults: IntArray) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        if (requestCode == 4133) {
            notificationRequest?.success(notificationsAvailable())
            notificationRequest = null
        }
    }

    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)
        channel = MethodChannel(flutterEngine.dartExecutor.binaryMessenger, "remote_link/android")
        SessionGate.onRevoked = {
            Handler(Looper.getMainLooper()).post { channel?.invokeMethod("sessionRevoked", null) }
        }
        channel?.setMethodCallHandler { call, result ->
            try {
                val args = call.arguments as? Map<*, *> ?: emptyMap<String, Any>()
                val session = args["sessionId"] as? String ?: ""
                when (call.method) {
                    "capabilities" -> result.success(mapOf(
                        "accessibilityEnabled" to (RemoteAccessibilityService.instance != null),
                        "input" to (RemoteAccessibilityService.instance != null),
                        "projectionRequiresConsent" to true,
                        "sessionActive" to SessionGate.isActive(),
                        "notificationsEnabled" to notificationsAvailable(),
                        "secureScreenCapture" to false,
                        "arbitraryKeys" to false
                    ))
                    "requestNotificationPermission" -> {
                        if (notificationsAvailable()) result.success(true)
                        else if (Build.VERSION.SDK_INT >= 33 && checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
                            require(notificationRequest == null) { "Notification permission request already pending" }
                            notificationRequest = result
                            requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), 4133)
                        } else {
                            startActivity(Intent(Settings.ACTION_APP_NOTIFICATION_SETTINGS).putExtra(Settings.EXTRA_APP_PACKAGE, packageName))
                            result.success(false)
                        }
                    }
                    "isAccessibilityEnabled" -> result.success(RemoteAccessibilityService.instance != null)
                    "openAccessibilitySettings" -> {
                        require(args["disclosureAccepted"] == true) { "Accessibility disclosure must be accepted" }
                        startActivity(Intent(Settings.ACTION_ACCESSIBILITY_SETTINGS))
                        result.success(true)
                    }
                    "acceptSession" -> {
                        // This call originates only in the local owner's accept dialog.
                        val input = args["input"] == true
                        require(notificationsAvailable()) { "Enable Remote Link session notifications before accepting access" }
                        require(!input || RemoteAccessibilityService.instance != null) { "Enable accessibility locally before allowing input" }
                        SessionGate.accept(session, input, args["clipboardText"] == true, args["confirmed"] == true)
                        try { startForegroundService(Intent(this, SessionIndicatorService::class.java)) }
                        catch (failure: Exception) { SessionGate.revoke(); throw failure }
                        result.success(true)
                    }
                    "startCaptureService" -> {
                        // startForeground runs async in onStartCommand: poll its outcome (max ~2 s).
                        CaptureService.state = 0
                        startForegroundService(Intent(this, CaptureService::class.java))
                        val handler = Handler(Looper.getMainLooper())
                        var tries = 0
                        fun poll() {
                            if (CaptureService.state == 1) result.success(true)
                            else if (CaptureService.state == -1 || ++tries > 40)
                                result.error("remote_platform", "Screen capture service failed to start", null)
                            else handler.postDelayed({ poll() }, 50)
                        }
                        poll()
                    }
                    "stopCaptureService" -> {
                        stopService(Intent(this, CaptureService::class.java))
                        result.success(true)
                    }
                    "revokeSession" -> {
                        try { SessionGate.revoke() }
                        finally { stopService(Intent(this, SessionIndicatorService::class.java)) }
                        result.success(true)
                    }
                    "injectInput" -> {
                        val event = args["event"] as? Map<*, *> ?: error("Missing input event")
                        val service = RemoteAccessibilityService.instance ?: error("Accessibility is not enabled")
                        result.success(service.input(session, JSONObject(event)))
                    }
                    "writeClipboard" -> {
                        require(SessionGate.allows(session, "clipboard_text")) { "Clipboard not authorized" }
                        val text = args["text"] as? String ?: error("Missing clipboard text")
                        require(text.length <= 1_048_576) { "Clipboard too large" }
                        getSystemService(ClipboardManager::class.java).setPrimaryClip(ClipData.newPlainText("Remote Link", text))
                        result.success(true)
                    }
                    else -> result.notImplemented()
                }
            } catch (failure: Exception) {
                result.error("remote_platform", failure.message ?: "Platform operation failed", null)
            }
        }
    }

    override fun cleanUpFlutterEngine(flutterEngine: FlutterEngine) {
        SessionGate.revoke()
        SessionGate.onRevoked = null
        channel?.setMethodCallHandler(null)
        channel = null
        notificationRequest?.error("closed", "Activity closed", null)
        notificationRequest = null
        stopService(Intent(this, SessionIndicatorService::class.java))
        stopService(Intent(this, CaptureService::class.java))
        super.cleanUpFlutterEngine(flutterEngine)
    }
}

