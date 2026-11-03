package com.remotelink.platform

import android.accessibilityservice.AccessibilityService
import android.accessibilityservice.GestureDescription
import android.graphics.Path
import android.os.Bundle
import android.view.accessibility.AccessibilityEvent
import android.view.accessibility.AccessibilityNodeInfo
import org.json.JSONObject

class RemoteAccessibilityService : AccessibilityService() {
    private data class Contact(val x: Float, val y: Float)
    private val contacts = mutableMapOf<Int, Contact>()
    private var pointer = Contact(0.5f, 0.5f)
    private var busy = false

    override fun onServiceConnected() { instance = this }
    override fun onAccessibilityEvent(event: AccessibilityEvent?) = Unit
    override fun onInterrupt() { cancelPendingGestures() }
    override fun onDestroy() { instance = null; SessionGate.revoke(); super.onDestroy() }

    fun cancelPendingGestures() { contacts.clear(); busy = false }

    private fun coordinate(event: JSONObject): Contact {
        val x = event.getDouble("x"); val y = event.getDouble("y")
        require(x.isFinite() && y.isFinite() && x in 0.0..1.0 && y in 0.0..1.0) { "Coordinates must be normalized" }
        return Contact(x.toFloat(), y.toFloat())
    }

    fun input(session: String, event: JSONObject): Boolean {
        require(SessionGate.allows(session, "input")) { "Input not authorized" }
        return when (event.getString("t")) {
            "mouse_move" -> { pointer = coordinate(event); true }
            "mouse_btn" -> {
                if (!event.getBoolean("down")) true
                else stroke(session, pointer, pointer, if (event.getString("b") == "right") 650 else 60)
            }
            "touch" -> {
                val id = event.getInt("id"); require(id in 0..15) { "Invalid touch ID" }
                val point = coordinate(event)
                when (event.getString("phase")) {
                    "start" -> { contacts[id] = point; true }
                    "move" -> { require(contacts.containsKey(id)) { "Touch not started" }; true }
                    "end" -> stroke(session, contacts.remove(id) ?: point, point, 180)
                    "cancel" -> { contacts.remove(id); true }
                    else -> error("Invalid touch phase")
                }
            }
            "wheel" -> {
                val dy = event.getDouble("dy"); require(dy.isFinite() && dy in -1200.0..1200.0)
                val end = Contact(pointer.x, (pointer.y - dy.toFloat() / 2400f).coerceIn(.05f, .95f))
                stroke(session, pointer, end, 100)
            }
            "key" -> if (!event.getBoolean("down")) true else when (event.getString("code")) {
                "Escape", "BrowserBack" -> performGlobalAction(GLOBAL_ACTION_BACK)
                "Home" -> performGlobalAction(GLOBAL_ACTION_HOME)
                "AppSwitch" -> performGlobalAction(GLOBAL_ACTION_RECENTS)
                else -> error("Use text entry for Android typing; this key is unsupported")
            }
            "text" -> setText(event.getString("text"))
            else -> error("Unsupported Android input type")
        }
    }

    private fun stroke(session: String, from: Contact, to: Contact, duration: Long): Boolean {
        if (busy || !SessionGate.allows(session, "input")) return false
        val metrics = resources.displayMetrics
        val path = Path().apply {
            moveTo(from.x * (metrics.widthPixels - 1), from.y * (metrics.heightPixels - 1))
            if (from != to) lineTo(to.x * (metrics.widthPixels - 1), to.y * (metrics.heightPixels - 1))
        }
        busy = true
        val result = dispatchGesture(GestureDescription.Builder().addStroke(GestureDescription.StrokeDescription(path, 0, duration)).build(),
            object : GestureResultCallback() {
                override fun onCompleted(gesture: GestureDescription?) { busy = false }
                override fun onCancelled(gesture: GestureDescription?) { busy = false }
            }, null)
        if (!result) busy = false
        return result
    }

    private fun setText(text: String): Boolean {
        require(text.length <= 16_384) { "Text too long" }
        val node = rootInActiveWindow?.findFocus(AccessibilityNodeInfo.FOCUS_INPUT) ?: return false
        return node.performAction(AccessibilityNodeInfo.ACTION_SET_TEXT, Bundle().apply {
            putCharSequence(AccessibilityNodeInfo.ACTION_ARGUMENT_SET_TEXT_CHARSEQUENCE, text)
        })
    }

    companion object { @Volatile var instance: RemoteAccessibilityService? = null; private set }
}
