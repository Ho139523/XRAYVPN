package com.familyfilter.parentpanel

import android.content.Context
import android.net.Uri

/** Settings, kept in private app storage. */
class Prefs(context: Context) {
    private val store = context.applicationContext.getSharedPreferences("family_filter", Context.MODE_PRIVATE)

    /** http://192.0.2.1:9099/v1/<user>/<token>, copied from the parent page (Phone setup). */
    var gateBase: String
        get() = store.getString("gate_base", "") ?: ""
        set(value) = store.edit().putString("gate_base", value).apply()

    /** The VPN client's local SOCKS5 port; the address 192.0.2.1 exists only inside the tunnel. */
    var socksPort: Int
        get() = store.getInt("socks_port", 10808)
        set(value) = store.edit().putInt("socks_port", value).apply()

    var reporting: Boolean
        get() = store.getBoolean("reporting", false)
        set(value) = store.edit().putBoolean("reporting", value).apply()

    var intervalMinutes: Int
        get() = store.getInt("interval_minutes", 5)
        set(value) = store.edit().putInt("interval_minutes", value).apply()

    var lastReport: String
        get() = store.getString("last_report", "") ?: ""
        set(value) = store.edit().putString("last_report", value).apply()

    /** The parent page lives on the same host and port as the gate. */
    val panelUrl: String?
        get() = Uri.parse(gateBase).takeIf { gateBase.isNotEmpty() && it.authority != null }
            ?.let { "${it.scheme}://${it.authority}/admin" }

    companion object {
        /**
         * Accepts any address copied from the "Phone setup" list and keeps
         * only http://host:port/v1/<user>/<token>. Null if it is not one.
         */
        fun normalizeBase(text: String): String? {
            val uri = Uri.parse(text.trim())
            val segments = uri.pathSegments
            if (uri.scheme != "http" && uri.scheme != "https") return null
            if (uri.authority.isNullOrEmpty() || segments.size < 3 || segments[0] != "v1") return null
            return "${uri.scheme}://${uri.authority}/v1/${Uri.encode(segments[1], "@")}/${Uri.encode(segments[2])}"
        }
    }
}
