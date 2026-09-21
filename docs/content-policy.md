# Content policy

* **Porn** is blocked for every VPN user, always.
* **Every VPN user (3X-UI "client") has their own policy and their own parent
  account(s).** Parents use a web page to choose, per site, whether it is

  | Mode | Meaning |
  | --- | --- |
  | **always** | blocked everywhere |
  | **in** places | blocked only while the user is in the chosen places |
  | **except** places | blocked everywhere, open only in the chosen places |

* **Places** are drawn on a map (centre + radius) and/or defined by a Wi-Fi
  network. The phone reports its position; the server works out which places
  the user is in.

Everything is enforced on the server in the Xray routing table, so the client
app (v2rayNG, Shadowrocket, V2Box, Streisand...) needs no configuration for the
filter itself. The only phone-side setup is the position report.

## What you must know first

* **Only traffic that goes through this VPN is controlled.** Turning the VPN
  off, or routing a site "direct" in the app, bypasses everything here. For a
  hard guarantee on a device, combine this with Screen Time (iOS), Family Link /
  a work profile (Android), or a filtering DNS on the home router.
* **The server cannot read a phone's GPS.** The phone's OS does the geofencing
  and *tells* the server (see "Phone setup"). That is fine for self-control; a
  phone's owner can also switch the automation off. To enforce against someone
  else, give the place a **Wi-Fi network** (public IP / DDNS name), which the
  server checks itself.
* Blocklists are never complete. Porn filtering combines `geosite:category-porn`,
  keywords, the family DNS answer for every hostname and a null-IP block. Add
  stragglers to `POLICY_EXTRA_BLOCK_DOMAINS`.
* Encrypted Client Hello and a second VPN/proxy *inside* the tunnel hide the
  destination name. HTTPS/SVCB DNS records (which carry ECH keys) are not
  answered, and DoH/DoT to public resolvers is blocked.

## Parent accounts

When you create a user in 3X-UI, the location gate notices within
`POLICY_SYNC_SECONDS` (default 60 s) and creates, for that user:

* a starting policy (`youtube` and `instagram` blocked while in any place), and
* a **parent account** named `<user>-parent` with a random password.

The initial passwords are listed in `state/parent-credentials.txt` (mode 600)
and by `python3 policy/vpn_policy.py parents list`. A line disappears once that
parent changes their password, so the file only ever lists accounts still on
their generated password. `parents reset <username>` makes a new one.

Parents sign in at **`http://192.0.2.1:9099/admin`** (reachable only through the
VPN tunnel). Each parent sees and edits **only their own user**:

* sites and modes, places on the map, the phone URLs, and
* **the parents**: add another parent, change any parent's username or
  password (your own password needs the current one), remove a parent (not
  yourself, never the last one).

The page is Persian by default with an English toggle. Five wrong passwords lock
that username for five minutes (so a child guessing can lock a parent out
briefly; the phone URLs keep working, and restarting `vpn-policy-gate` clears
it). Anyone who can reach the 3X-UI panel (port 2053) can also remove the whole
policy, so give that a strong password too.

## Sites

On the page, type or paste a site (`https://www.tiktok.com/@x` becomes
`tiktok.com`; subdomains are included), an app name (`youtube`, `instagram`
cover all their domains) or `keyword:casino`, pick a mode, and for the two
place-based modes tick the places (or **any place**).

Precedence, first match wins: porn, then *always*, then *in*, then the *open
here* exceptions, then the *everywhere else* block. `POLICY_ALLOW_DOMAINS` is
an admin-level override that beats only the porn list.

From SSH:

```
python3 policy/vpn_policy.py sites list [user]
python3 policy/vpn_policy.py sites add    <user> tiktok.com
python3 policy/vpn_policy.py sites add    <user> youtube   --mode in     --zones home,library
python3 policy/vpn_policy.py sites add    <user> instagram --mode except --zones home
python3 policy/vpn_policy.py sites remove <user> tiktok.com
```

## Places

On the map, tap to set the centre, set the radius, name it, save. A search box
finds addresses (OpenStreetMap Nominatim). A place may also have **Wi-Fi
networks**: connections from those addresses count as being in that place,
enforced by the server with no phone involved (it does not follow the person
onto mobile data).

The map itself is Leaflet (BSD-2, `policy/static/leaflet/`, served from this
server); only the map tiles are fetched from `tile.openstreetmap.org`, through
the tunnel. Place names, coordinates and blocklists never leave the server.

## Phone setup

The parent page, section *Phone setup*, lists this user's personal URLs with a
copy button. The address `192.0.2.1` is not a real host: Xray recognises it
*inside the tunnel* and hands the request to the local gate, which listens on
`127.0.0.1` only. The token in each URL belongs to one user. With the VPN off
the request goes nowhere (`192.0.2.0/24` is reserved) but, being plain HTTP, it
could be seen on the local network. To rotate every token delete
`state/gate.secret`.

**Report position (recommended):** `.../locate?lat=LAT&lon=LON`. The server
compares it with the user's places and enters/leaves them, so the phone needs
no knowledge of the places:

* **iPhone**: Shortcuts, *Get Current Location* → *Get Details of Locations*
  (Latitude, Longitude) → *Get Contents of URL* with those values in the URL.
  Run it from an Automation, e.g. when the VPN app or a chosen app opens, at
  chosen times, or on *Arrive* / *Leave*.
* **Android**: Tasker or MacroDroid, a location trigger or periodic task, action
  *HTTP Request (GET)* with the location variables. Exempt the app from battery
  optimisation.

**Enter / exit by name:** `.../<place>/enter` and `.../<place>/exit`, for phones
that already have their own geofence automation (iOS *Arrive*/*Leave*).

Notes:

* The VPN must be connected when the phone reports. Use iOS *Connect On Demand*
  or Android *Always-on VPN*.
* When a place changes, the server re-applies its routing, which can interrupt
  connections for a moment. Only the user who moved is affected.
* If a report is missed (VPN off when leaving) the user stays "in" that place
  until the next report. Reset with
  `python3 policy/vpn_policy.py set <user> <place> exit`.

## Commands

```
python3 policy/vpn_policy.py apply     # sync users, parents and Xray rules (idempotent)
python3 policy/vpn_policy.py verify    # rules, sniffing, Xray, DNS filter, parents, gate
python3 policy/vpn_policy.py status    # every user, their places and where they are
python3 policy/vpn_policy.py urls [user]
python3 policy/vpn_policy.py set <user> <place> enter|exit
python3 policy/vpn_policy.py sites list|add|remove ...
python3 policy/vpn_policy.py parents list | reset <username>
python3 policy/vpn_policy.py remove    # strip the policy, leave the panel's own config
```

`apply` layers the policy on the Xray template the panel already has, touching
only rules and outbounds tagged `vpnapp-*`, and turns on sniffing for every
inbound. If Xray will not stay up with the new template the previous one is
restored automatically and the command fails with Xray's error. The pre-policy
template is kept in `state/xray-template.pre-policy.json`.

## Files (all in `state/`, mode 600, git-ignored)

| File | Content |
| --- | --- |
| `policy.json` | per user: places and sites |
| `parents.json` | parent accounts (salted PBKDF2 hashes, never passwords) |
| `parent-credentials.txt` | accounts still on their generated password |
| `zone-state.json` | which places each user is in now |
| `gate.secret` | key for the per-user phone tokens |

Upgrading from the earlier version migrates automatically: the old global
`always`/`geo` lists become each existing user's policy, the single parent
password becomes a parent named `parent` (when there is exactly one user), and
"at home" state is kept. The old files are renamed `*.migrated`.

## Adding the policy to an existing appliance

```
cd /path/to/XRAYVPN
cp config/appliance.env.example config/.env       # edit the POLICY_* lines
printf 'PANEL_USERNAME=...\nPANEL_PASSWORD=...\n' > state/secrets.env && chmod 600 state/secrets.env
python3 policy/vpn_policy.py apply
ROOT_DIR=$PWD bash scripts/09-content-policy.sh   # installs and starts the gate service
```

The gate reaches Xray at `127.0.0.1`, which is correct with the appliance's
`network_mode: host`. With a bridged 3X-UI container it would not be.
