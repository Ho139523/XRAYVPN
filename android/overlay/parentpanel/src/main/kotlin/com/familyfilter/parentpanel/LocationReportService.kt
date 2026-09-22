package com.familyfilter.parentpanel

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.location.Location
import android.location.LocationListener
import android.location.LocationManager
import android.os.Build
import android.os.IBinder
import android.os.Looper
import java.text.DateFormat
import java.util.Date
import java.util.Locale
import java.util.concurrent.Executors

/**
 * Sends the phone's position to the family filter's gate, which decides which
 * of the parents' places the child is in. The gate is reachable only through
 * the VPN, so nothing is sent while the VPN is off; the next update retries.
 */
class LocationReportService : Service(), LocationListener {
    private lateinit var prefs: Prefs
    private lateinit var manager: LocationManager
    private val executor = Executors.newSingleThreadExecutor()

    override fun onCreate() {
        super.onCreate()
        prefs = Prefs(this)
        manager = getSystemService(Context.LOCATION_SERVICE) as LocationManager
        goForeground()
        if (!register()) stopSelf()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int = START_STICKY

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onDestroy() {
        try {
            manager.removeUpdates(this)
        } catch (error: SecurityException) {
            // permission already revoked
        }
        executor.shutdown()
        super.onDestroy()
    }

    private fun goForeground() {
        val channelId = "family_filter_location"
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                channelId, getString(R.string.fp_notification_title), NotificationManager.IMPORTANCE_LOW
            )
            (getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager).createNotificationChannel(channel)
        }
        val builder = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            Notification.Builder(this, channelId)
        } else {
            @Suppress("DEPRECATION") Notification.Builder(this)
        }
        val notification = builder
            .setContentTitle(getString(R.string.fp_notification_title))
            .setContentText(getString(R.string.fp_notification_text))
            .setSmallIcon(android.R.drawable.ic_menu_mylocation)
            .setOngoing(true)
            .build()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            startForeground(NOTIFICATION_ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_LOCATION)
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }
    }

    /** Returns false when no location updates could be requested. */
    private fun register(): Boolean {
        val minTimeMs = prefs.intervalMinutes.coerceAtLeast(1) * 60_000L
        var registered = false
        try {
            for (provider in listOf(LocationManager.GPS_PROVIDER, LocationManager.NETWORK_PROVIDER)) {
                if (!manager.isProviderEnabled(provider)) continue
                manager.requestLocationUpdates(provider, minTimeMs, MIN_DISTANCE_M, this, Looper.getMainLooper())
                registered = true
                manager.getLastKnownLocation(provider)?.let { report(it) }
            }
        } catch (error: SecurityException) {
            return false
        }
        return registered
    }

    override fun onLocationChanged(location: Location) = report(location)

    // Required on API < 30, where the interface's methods are not default.
    @Deprecated("Deprecated in Java")
    override fun onStatusChanged(provider: String?, status: Int, extras: android.os.Bundle?) {}

    override fun onProviderEnabled(provider: String) {}

    override fun onProviderDisabled(provider: String) {}

    private fun report(location: Location) {
        if (location.hasAccuracy() && location.accuracy > MAX_ACCURACY_M) return
        val base = prefs.gateBase
        if (base.isEmpty()) return
        val url = String.format(Locale.US, "%s/locate?lat=%.6f&lon=%.6f", base, location.latitude, location.longitude)
        val port = prefs.socksPort
        executor.execute {
            val outcome = try {
                val (code, _) = CoreHttp.get(url, port)
                if (code == 200) "OK" else "HTTP $code"
            } catch (error: Exception) {
                error.javaClass.simpleName
            }
            prefs.lastReport = "${DateFormat.getTimeInstance(DateFormat.SHORT).format(Date())} $outcome"
        }
    }

    companion object {
        private const val NOTIFICATION_ID = 4711
        private const val MIN_DISTANCE_M = 30f
        private const val MAX_ACCURACY_M = 500f

        fun start(context: Context) {
            val intent = Intent(context, LocationReportService::class.java)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService(intent)
            } else {
                context.startService(intent)
            }
        }

        fun stop(context: Context) {
            context.stopService(Intent(context, LocationReportService::class.java))
        }
    }
}
