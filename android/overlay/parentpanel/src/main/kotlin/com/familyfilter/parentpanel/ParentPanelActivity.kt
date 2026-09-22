package com.familyfilter.parentpanel

import android.Manifest
import android.annotation.SuppressLint
import android.app.Activity
import android.app.AlertDialog
import android.content.pm.PackageManager
import android.graphics.Color
import android.os.Build
import android.os.Bundle
import android.text.InputType
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.webkit.CookieManager
import android.webkit.WebResourceError
import android.webkit.WebResourceRequest
import android.webkit.WebView
import android.webkit.WebViewClient
import android.widget.Button
import android.widget.CheckBox
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ProgressBar
import android.widget.TextView
import android.widget.Toast
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import androidx.webkit.ProxyConfig
import androidx.webkit.ProxyController
import androidx.webkit.WebViewFeature
import java.util.concurrent.Executor

/**
 * Shows the family filter's parent page. The page lives at an address that
 * exists only inside the VPN tunnel, so the WebView is pointed at the VPN
 * client's local SOCKS5 proxy. Also owns the settings and the location switch.
 */
class ParentPanelActivity : Activity() {
    private lateinit var prefs: Prefs
    private lateinit var web: WebView
    private lateinit var progress: ProgressBar
    private lateinit var status: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        prefs = Prefs(this)
        setContentView(buildUi())
        if (prefs.panelUrl == null) {
            Toast.makeText(this, R.string.fp_no_link, Toast.LENGTH_LONG).show()
            showSettings()
        } else {
            openPanel()
        }
    }

    override fun onResume() {
        super.onResume()
        refreshStatus()
    }

    @Deprecated("Deprecated in Java")
    override fun onBackPressed() {
        if (web.canGoBack()) web.goBack() else @Suppress("DEPRECATION") super.onBackPressed()
    }

    // ---- UI -----------------------------------------------------------------

    @SuppressLint("SetJavaScriptEnabled")
    private fun buildUi(): View {
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setBackgroundColor(Color.WHITE)
        }
        ViewCompat.setOnApplyWindowInsetsListener(root) { view, insets ->
            val bars = insets.getInsets(WindowInsetsCompat.Type.systemBars())
            view.setPadding(bars.left, bars.top, bars.right, bars.bottom)
            insets
        }

        val bar = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setBackgroundColor(Color.parseColor("#1D4ED8"))
            setPadding(dp(12), dp(6), dp(6), dp(6))
        }
        val titles = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        titles.addView(TextView(this).apply {
            setText(R.string.fp_app_label)
            setTextColor(Color.WHITE)
            textSize = 18f
        })
        status = TextView(this).apply {
            setTextColor(Color.parseColor("#DBEAFE"))
            textSize = 12f
        }
        titles.addView(status)
        bar.addView(titles, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
        bar.addView(barButton(R.string.fp_reload) { openPanel() })
        bar.addView(barButton(R.string.fp_settings) { showSettings() })
        root.addView(bar, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT))

        progress = ProgressBar(this, null, android.R.attr.progressBarStyleHorizontal).apply {
            max = 100
            visibility = View.GONE
        }
        root.addView(progress, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, dp(3)))

        web = WebView(this).apply {
            settings.javaScriptEnabled = true
            settings.domStorageEnabled = true
            CookieManager.getInstance().setAcceptCookie(true)
            webViewClient = object : WebViewClient() {
                override fun shouldOverrideUrlLoading(view: WebView, request: WebResourceRequest): Boolean {
                    // Stay on the parent page's own host; never wander off to other sites.
                    val panel = prefs.panelUrl ?: return true
                    return android.net.Uri.parse(panel).authority != request.url.authority
                }

                override fun onReceivedError(view: WebView, request: WebResourceRequest, error: WebResourceError) {
                    if (request.isForMainFrame) view.loadDataWithBaseURL(null, errorPage(), "text/html", "utf-8", null)
                }

                override fun onPageFinished(view: WebView, url: String) {
                    progress.visibility = View.GONE
                }
            }
            webChromeClient = object : android.webkit.WebChromeClient() {
                override fun onProgressChanged(view: WebView, newProgress: Int) {
                    progress.visibility = if (newProgress in 1..99) View.VISIBLE else View.GONE
                    progress.progress = newProgress
                }
            }
        }
        root.addView(web, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f))
        return root
    }

    private fun barButton(label: Int, action: () -> Unit) = Button(this).apply {
        setText(label)
        isAllCaps = false
        setTextColor(Color.WHITE)
        setBackgroundColor(Color.TRANSPARENT)
        setOnClickListener { action() }
    }

    private fun dp(value: Int) = (value * resources.displayMetrics.density).toInt()

    private fun refreshStatus() {
        val last = prefs.lastReport.ifEmpty { getString(R.string.fp_never) }
        status.text = if (prefs.reporting) getString(R.string.fp_last_report, last) else ""
    }

    private fun errorPage() =
        "<html><body style='font-family:sans-serif;padding:24px;text-align:center'>" +
            "<h3>${getString(R.string.fp_error_title)}</h3><p>${getString(R.string.fp_error_body)}</p></body></html>"

    // ---- the page -------------------------------------------------------------

    private fun openPanel() {
        val url = prefs.panelUrl ?: return
        val load = { web.loadUrl(url) }
        if (!WebViewFeature.isFeatureSupported(WebViewFeature.PROXY_OVERRIDE)) {
            load()
            return
        }
        try {
            val config = ProxyConfig.Builder().addProxyRule("socks5://127.0.0.1:${prefs.socksPort}").build()
            ProxyController.getInstance().setProxyOverride(config, Executor { it.run() }, { load() })
        } catch (error: Exception) {
            load() // this WebView cannot use a SOCKS proxy; works only if the VPN covers this app
        }
    }

    // ---- settings -------------------------------------------------------------

    private fun showSettings() {
        val form = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(20), dp(8), dp(20), 0)
        }
        fun field(label: Int, value: String, numeric: Boolean = false): EditText {
            form.addView(TextView(this).apply { setText(label); textSize = 13f })
            return EditText(this).apply {
                setText(value)
                inputType = if (numeric) InputType.TYPE_CLASS_NUMBER else InputType.TYPE_TEXT_VARIATION_URI
                isSingleLine = true
                form.addView(this)
            }
        }
        val link = field(R.string.fp_link_label, prefs.gateBase)
        val port = field(R.string.fp_port_label, prefs.socksPort.toString(), numeric = true)
        val report = CheckBox(this).apply { setText(R.string.fp_report); isChecked = prefs.reporting }
        form.addView(report)
        val interval = field(R.string.fp_interval_label, prefs.intervalMinutes.toString(), numeric = true)

        AlertDialog.Builder(this)
            .setTitle(R.string.fp_settings)
            .setView(form)
            .setPositiveButton(R.string.fp_save, null)
            .setNegativeButton(R.string.fp_cancel, null)
            .create()
            .also { dialog ->
                dialog.setOnShowListener {
                    dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener {
                        if (save(link.text.toString(), port.text.toString(), report.isChecked, interval.text.toString())) {
                            dialog.dismiss()
                        }
                    }
                }
            }
            .show()
    }

    private fun save(linkText: String, portText: String, report: Boolean, intervalText: String): Boolean {
        val base = if (linkText.isBlank()) "" else Prefs.normalizeBase(linkText)
        if (base == null) {
            Toast.makeText(this, R.string.fp_bad_link, Toast.LENGTH_LONG).show()
            return false
        }
        val socks = portText.trim().toIntOrNull()
        if (socks == null || socks !in 1..65535) {
            Toast.makeText(this, R.string.fp_bad_port, Toast.LENGTH_LONG).show()
            return false
        }
        prefs.gateBase = base
        prefs.socksPort = socks
        prefs.intervalMinutes = (intervalText.trim().toIntOrNull() ?: 5).coerceIn(1, 120)
        prefs.reporting = report && base.isNotEmpty()
        LocationReportService.stop(this)
        if (prefs.reporting) ensureLocationPermissions() else refreshStatus()
        openPanel()
        return true
    }

    // ---- location permissions ---------------------------------------------------

    private fun granted(permission: String) = checkSelfPermission(permission) == PackageManager.PERMISSION_GRANTED

    private fun ensureLocationPermissions() {
        val missing = mutableListOf<String>()
        if (!granted(Manifest.permission.ACCESS_FINE_LOCATION)) missing += Manifest.permission.ACCESS_FINE_LOCATION
        if (!granted(Manifest.permission.ACCESS_COARSE_LOCATION)) missing += Manifest.permission.ACCESS_COARSE_LOCATION
        if (Build.VERSION.SDK_INT >= 33 && !granted(Manifest.permission.POST_NOTIFICATIONS)) {
            missing += Manifest.permission.POST_NOTIFICATIONS
        }
        if (missing.isNotEmpty()) {
            requestPermissions(missing.toTypedArray(), REQUEST_LOCATION)
            return
        }
        if (Build.VERSION.SDK_INT >= 29 && !granted(Manifest.permission.ACCESS_BACKGROUND_LOCATION)) {
            // "Allow all the time": needed so reporting keeps working when the app is closed.
            requestPermissions(arrayOf(Manifest.permission.ACCESS_BACKGROUND_LOCATION), REQUEST_BACKGROUND)
            return
        }
        startReporting()
    }

    override fun onRequestPermissionsResult(requestCode: Int, permissions: Array<out String>, grantResults: IntArray) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        when (requestCode) {
            REQUEST_LOCATION ->
                if (granted(Manifest.permission.ACCESS_FINE_LOCATION)) ensureLocationPermissions() else denied()
            // Background access is optional: without it reporting works while the app is in use.
            REQUEST_BACKGROUND -> startReporting()
        }
    }

    private fun denied() {
        prefs.reporting = false
        Toast.makeText(this, R.string.fp_permission_denied, Toast.LENGTH_LONG).show()
        refreshStatus()
    }

    private fun startReporting() {
        LocationReportService.start(this)
        refreshStatus()
    }

    companion object {
        private const val REQUEST_LOCATION = 1
        private const val REQUEST_BACKGROUND = 2
    }
}
