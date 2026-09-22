package com.familyfilter.parentpanel

import java.net.HttpURLConnection
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.URL

/**
 * HTTP through the VPN client's local SOCKS5 inbound. That works whether or not
 * the VPN client excludes its own app from the tunnel, because talking to the
 * local proxy never leaves the phone; the core then carries it to the server.
 */
object CoreHttp {
    fun get(url: String, socksPort: Int, timeoutMs: Int = 10_000): Pair<Int, String> {
        val proxy = Proxy(Proxy.Type.SOCKS, InetSocketAddress("127.0.0.1", socksPort))
        val connection = URL(url).openConnection(proxy) as HttpURLConnection
        try {
            connection.connectTimeout = timeoutMs
            connection.readTimeout = timeoutMs
            connection.requestMethod = "GET"
            val code = connection.responseCode
            val stream = if (code in 200..299) connection.inputStream else connection.errorStream
            return code to (stream?.bufferedReader()?.use { it.readText() } ?: "")
        } finally {
            connection.disconnect()
        }
    }
}
