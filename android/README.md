# Family VPN for Android

One app for both people:

* **the child** connects to the VPN with it: it *is* the [v2rayNG](https://github.com/2dust/v2rayNG)
  client (VLESS + Reality, import the link the installer prints), unchanged;
* **the parent** opens the second icon, **Parent panel**, which shows the family
  filter's page (sites, places on a map, parents) through the VPN;
* **optional location reporting**: the app sends the phone's position to the
  server, which decides which of the parents' places the child is in. No
  Shortcuts or Tasker automation is needed.

## How it is put together

`android/overlay/parentpanel/` is a small Android library module (Kotlin, no
dependency on Google Play Services). `android/apply-overlay.py` copies it into a
checkout of v2rayNG, includes it in the Gradle build, makes the app depend on it
and allows plain HTTP in the manifest (the parent page is `http://192.0.2.1:9099`,
an address that exists only inside the tunnel). `.github/workflows/android-apk.yml`
does that on GitHub and builds the APK. Nothing of v2rayNG is copied into this
repository.

The panel and the location reports go through the VPN client's **local SOCKS5
proxy** (default port 10808, changeable in Settings). That works whether or not
the VPN client excludes its own app from the tunnel, because the traffic to the
local proxy never leaves the phone.

## Build the APK

1. Push this repository to GitHub.
2. Actions → **Android APK** → *Run workflow*. Inputs: the v2rayNG tag or branch,
   the JDK and NDK versions (defaults are a starting point).
3. Download the `family-vpn-apk` artifact and install it (allow "unknown sources").

The APK is debug-signed, so it will not update over the official v2rayNG
(different signature; uninstall that first) and is meant for sideloading.

**This pipeline has not been run.** It was written without inspecting v2rayNG's
own build, which changes between releases (JDK, NDK, the native tun2socks build,
where `libv2ray.aar` comes from). If a step fails, its log says what upstream
wants; fix the matching step or input in the workflow and run again. Locally the
same thing is
`python3 android/apply-overlay.py <v2rayNG checkout>` and then `./gradlew assembleDebug`.
Also unverified on a device: WebView's SOCKS5 proxy override (Android System
WebView must be recent) and the background-location behaviour of each vendor.

## Using it

**Child:** import the VPN link in the VPN client part as usual and connect.

**Parent, first time:**

1. Connect the VPN.
2. Open **Parent panel**. Settings opens by itself.
3. On the parent page (web, or a browser through the VPN) → *Phone setup* → copy
   **App setup link**. Paste it in the app's Settings and save.
4. Sign in with the parent login.

**Location reporting** (on the child's phone): Settings → tick *Report my
location*, allow location "all the time" and notifications when asked. A
foreground notification shows while it runs. Reports are sent when the phone
moves (30 m) and at most as often as the interval; while the VPN is off they
simply fail and the next one retries. The server keeps the last known place.

## Limits worth knowing

* It reports only while the VPN client is connected: the gate is reachable
  only through the tunnel.
* A child who owns the phone can turn reporting off, uninstall the app or
  disconnect the VPN. Places with a **Wi-Fi network** are checked by the server
  itself and do not depend on the app.
* Battery savers on some phones kill background services; exempt the app.
* v2rayNG is GPLv3, so an APK built from it must be distributed under GPLv3 with
  its source.
