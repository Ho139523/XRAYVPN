package com.familyfilter.parentpanel

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent

/** Resumes location reporting after a reboot, if the person turned it on. */
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Intent.ACTION_BOOT_COMPLETED) return
        val prefs = Prefs(context)
        if (!prefs.reporting || prefs.gateBase.isEmpty()) return
        try {
            LocationReportService.start(context)
        } catch (error: Exception) {
            // Android may refuse to start a location service from the background;
            // reporting resumes the next time the app is opened.
        }
    }
}
