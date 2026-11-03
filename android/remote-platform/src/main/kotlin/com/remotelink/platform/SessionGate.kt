package com.remotelink.platform

import android.os.SystemClock

/** Process-local, target-owned authority. No grant survives process death or expiry. */
object SessionGate {
    private data class Grant(val id: String, val input: Boolean, val clipboard: Boolean, val deadline: Long)
    @Volatile private var grant: Grant? = null
    @Volatile var onRevoked: (() -> Unit)? = null

    @Synchronized fun accept(id: String, input: Boolean, clipboard: Boolean, confirmed: Boolean) {
        require(confirmed && id.isNotBlank() && id.length <= 128) { "Local session consent required" }
        grant = Grant(id, input, clipboard, SystemClock.elapsedRealtime() + 3_600_000)
    }

    fun allows(id: String, capability: String): Boolean {
        val g = grant ?: return false
        if (SystemClock.elapsedRealtime() >= g.deadline) { revoke(); return false }
        return g.id == id && when (capability) {
            "input" -> g.input
            "clipboard_text" -> g.clipboard
            "view" -> true
            else -> false
        }
    }

    @Synchronized fun revoke() {
        val previous = grant
        grant = null
        RemoteAccessibilityService.instance?.cancelPendingGestures()
        if (previous != null) onRevoked?.invoke()
    }

    fun isActive(): Boolean = grant?.let { allows(it.id, "view") } ?: false
}
