"""Parent web page: sign-in, blocked sites, places on a map, phone setup, parents.

Served by the location gate under /admin, reachable only through the VPN tunnel.
Server-rendered HTML plus one static script (map and small conveniences), so the
Content-Security-Policy can forbid inline script.
"""
from __future__ import annotations

import hmac
import html
import http.cookies
import json
import secrets
import threading
import time
import urllib.parse
from pathlib import Path

from i18n import UserError, t

STATIC = Path(__file__).resolve().parent / "static"
SESSION_SECONDS = 12 * 3600
LOCKOUT_FAILURES, LOCKOUT_SECONDS, GLOBAL_FAILURES = 5, 300, 40
DEFAULT_CENTER = (35.6892, 51.3890)  # Tehran; only used before any place exists
LANGS = ("fa", "en")

CSP = ("default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
       "img-src 'self' data: https://tile.openstreetmap.org https://*.tile.openstreetmap.org; "
       "connect-src https://nominatim.openstreetmap.org; form-action 'self'; base-uri 'none'; "
       "frame-ancestors 'none'")
TYPES = {".js": "application/javascript; charset=utf-8", ".css": "text/css; charset=utf-8",
         ".png": "image/png", ".svg": "image/svg+xml"}
JS_STRINGS = ("map_pick_first", "search_none", "copied", "copy", "coords", "no_coords", "new_place")

e = html.escape


class Form:
    """Parsed application/x-www-form-urlencoded body."""

    def __init__(self, raw):
        self.data = urllib.parse.parse_qs(raw, keep_blank_values=True)

    def __call__(self, name):
        return (self.data.get(name) or [""])[0]

    def getlist(self, name):
        return self.data.get(name, [])


class AdminUI:
    def __init__(self, cfg, policy, parents, state, syncer, gate_base, login_token, apps=()):
        self.cfg, self.policy, self.parents = cfg, policy, parents
        self.apps = tuple(apps)
        self.state, self.syncer = state, syncer
        self.gate_base, self.login_token = gate_base, login_token
        self.lock = threading.Lock()
        self.sessions = {}
        self.failures = {}

    # -- plumbing ----------------------------------------------------------

    def _send(self, h, code, body, ctype="text/html; charset=utf-8", headers=(), cache="no-store"):
        data = body.encode() if isinstance(body, str) else body
        h.send_response(code)
        h.send_header("Content-Type", ctype)
        h.send_header("Content-Length", str(len(data)))
        h.send_header("Cache-Control", cache)
        h.send_header("X-Content-Type-Options", "nosniff")
        h.send_header("X-Frame-Options", "DENY")
        h.send_header("Referrer-Policy", "no-referrer")
        h.send_header("Content-Security-Policy", CSP)
        for name, value in headers:
            h.send_header(name, value)
        h.end_headers()
        h.wfile.write(data)

    def _redirect(self, h, location, headers=()):
        self._send(h, 303, "", headers=[("Location", location), *headers])

    def _cookies(self, h):
        try:
            return http.cookies.SimpleCookie(h.headers.get("Cookie", ""))
        except http.cookies.CookieError:
            return {}

    def _lang(self, h):
        cookie = self._cookies(h).get("lang")
        return cookie.value if cookie and cookie.value in LANGS else "fa"

    def _session(self, h):
        cookie = self._cookies(h).get("fvsess")
        with self.lock:
            now = time.time()
            for key in [k for k, s in self.sessions.items() if s["expires"] < now]:
                del self.sessions[key]
            return self.sessions.get(cookie.value) if cookie else None

    def _form(self, h):
        try:
            length = max(0, min(int(h.headers.get("Content-Length") or 0), 16384))
        except ValueError:
            length = 0
        return Form(h.rfile.read(length).decode("utf-8", errors="replace"))

    def _flash(self, session, kind, text):
        session.setdefault("flash", []).append((kind, text))

    # -- routing -----------------------------------------------------------

    def handle(self, h):
        parts = urllib.parse.urlsplit(h.path).path.strip("/").split("/")[1:]
        route = "/".join(parts)
        lang = self._lang(h)
        if parts[:1] == ["static"]:
            return self._static(h, parts[1:])
        if parts[:1] == ["lang"] and len(parts) == 2 and parts[1] in LANGS:
            return self._redirect(h, "/admin", [("Set-Cookie", "lang=%s; Path=/admin; Max-Age=31536000; "
                                                                "SameSite=Strict" % parts[1])])
        if route == "login":
            return self._login(h, lang)
        session = self._session(h)
        if session is None:
            return self._redirect(h, "/admin/login")
        if h.command == "GET" and route == "":
            return self._panel(h, session, lang)
        if h.command == "POST":
            return self._action(h, session, lang, route)
        return self._send(h, 404, "Not found")

    def _static(self, h, parts):
        path = STATIC.joinpath(*parts).resolve()
        try:
            path.relative_to(STATIC.resolve())
        except ValueError:
            return self._send(h, 404, "Not found")
        if not path.is_file() or path.suffix not in TYPES:
            return self._send(h, 404, "Not found")
        self._send(h, 200, path.read_bytes(), TYPES[path.suffix], cache="public, max-age=3600")

    # -- sign-in -----------------------------------------------------------

    def _locked(self, key):
        now = time.monotonic()
        for k in (key, "*"):
            self.failures[k] = [x for x in self.failures.get(k, []) if now - x < LOCKOUT_SECONDS]
        return len(self.failures[key]) >= LOCKOUT_FAILURES or len(self.failures["*"]) >= GLOBAL_FAILURES

    def _login(self, h, lang):
        if h.command != "POST":
            return self._send(h, 200, render_login(lang, self.login_token()))
        form = self._form(h)
        username = form("username").strip()
        key = username.lower()[:40] or "?"
        with self.lock:
            if self._locked(key):
                return self._send(h, 429, render_login(lang, self.login_token(), t(lang, "err_locked")))
        record = None
        if hmac.compare_digest(form("csrf"), self.login_token()):
            record = self.parents.authenticate(username, form("password"))
        with self.lock:
            if record is None:
                self.failures[key].append(time.monotonic())
                self.failures["*"].append(time.monotonic())
                return self._send(h, 401, render_login(lang, self.login_token(), t(lang, "err_login")))
            token = secrets.token_urlsafe(32)
            self.sessions[token] = {"user": record["username"], "child": record["child"],
                                    "csrf": secrets.token_urlsafe(24),
                                    "expires": time.time() + SESSION_SECONDS}
        self._redirect(h, "/admin", [("Set-Cookie", "fvsess=%s; Path=/admin; HttpOnly; SameSite=Strict; "
                                                    "Max-Age=%d" % (token, SESSION_SECONDS))])

    # -- actions -----------------------------------------------------------

    def _mine(self, session, username):
        record = self.parents.get(username)
        if not record or record["child"] != session["child"]:
            raise UserError("err_no_such")
        return record["username"]

    def _action(self, h, session, lang, route):
        form = self._form(h)
        if not hmac.compare_digest(form("csrf"), session["csrf"]):
            self._flash(session, "err", t(lang, "err_csrf"))
            return self._redirect(h, "/admin")
        child, anchor, changed = session["child"], "", False
        if route == "logout":
            with self.lock:
                self.sessions = {k: v for k, v in self.sessions.items() if v is not session}
            return self._redirect(h, "/admin/login", [("Set-Cookie", "fvsess=; Path=/admin; Max-Age=0")])
        try:
            if route == "site/add":
                entry = self.policy.set_site(child, form("site"), form("mode"), form.getlist("zones"))
                self._flash(session, "ok", t(lang, "site_saved", site=entry))
                anchor, changed = "#sites", True
            elif route == "site/remove":
                entry = self.policy.remove_site(child, form("site"))
                self._flash(session, "ok", t(lang, "site_removed", site=entry))
                anchor, changed = "#sites", True
            elif route == "zone/save":
                zone = self.policy.save_zone(child, form("id"), form("name"), form("lat"), form("lon"),
                                             form("radius"), form("networks"))
                self._flash(session, "ok", t(lang, "zone_saved", name=zone["name"]))
                anchor, changed = "#places", True
            elif route == "zone/remove":
                self.policy.remove_zone(child, form("id"))
                self._flash(session, "ok", t(lang, "zone_removed"))
                anchor, changed = "#places", True
            elif route == "parent/add":
                self.parents.add(child, form("username").strip(), form("password"))
                self._flash(session, "ok", t(lang, "parent_added", username=form("username").strip()))
                anchor = "#parents"
            elif route == "parent/update":
                target = self._mine(session, form("username"))
                is_me = target.lower() == session["user"].lower()
                if form("new_password") and is_me and not self.parents.authenticate(target, form("current")):
                    raise UserError("err_password_wrong")
                renamed = self.parents.update(target, form("new_username").strip(), form("new_password"))
                if is_me:
                    session["user"] = renamed
                self._flash(session, "ok", t(lang, "parent_saved"))
                anchor = "#parents"
            elif route == "parent/remove":
                target = self._mine(session, form("username"))
                if target.lower() == session["user"].lower():
                    raise UserError("err_self_remove")
                self.parents.remove(target)
                self._flash(session, "ok", t(lang, "parent_removed", username=target))
                anchor = "#parents"
            else:
                return self._send(h, 404, "Not found")
        except UserError as error:
            self._flash(session, "err", error.message(lang))
            anchor = {"site": "#sites", "zone": "#places", "parent": "#parents"}.get(route.split("/")[0], "")
        if changed:
            self.syncer.wake.set()
        self._redirect(h, "/admin" + anchor)

    def _panel(self, h, session, lang):
        child = session["child"]
        policy = self.policy.get(child) or {"zones": [], "sites": []}
        ctx = {
            "lang": lang, "child": child, "user": session["user"], "csrf": session["csrf"],
            "zones": policy["zones"], "sites": policy["sites"],
            "inside": self.state.zones_of(child),
            "parents": self.parents.of_child(child),
            "base": self.gate_base(self.cfg, child),
            "flash": session.pop("flash", []), "apps": self.apps,
        }
        self._send(h, 200, render_panel(ctx))


# --------------------------------------------------------------------------
# rendering
# --------------------------------------------------------------------------

def page(lang, title, body, scripts=""):
    rtl = lang == "fa"
    return ('<!doctype html><html lang="%s" dir="%s"><head><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width,initial-scale=1">'
            '<meta name="color-scheme" content="light dark"><title>%s</title>'
            '<link rel="stylesheet" href="/admin/static/leaflet/leaflet.css">'
            '<link rel="stylesheet" href="/admin/static/admin.css"></head><body>%s%s</body></html>'
            % (lang, "rtl" if rtl else "ltr", e(title), body, scripts))


def render_login(lang, token, error=""):
    tr = lambda key, **kw: t(lang, key, **kw)
    other = "en" if lang == "fa" else "fa"
    body = (
        '<main class="login"><div class="card login-card"><div class="logo">🛡️</div>'
        '<h1>%(title)s</h1><p class="note">%(hint)s</p>%(error)s'
        '<form method="post" action="/admin/login" class="stack">'
        '<input type="hidden" name="csrf" value="%(token)s">'
        '<label>%(user)s<input name="username" dir="ltr" autocomplete="username" autocapitalize="none" '
        'autocorrect="off" required autofocus></label>'
        '<label>%(pass)s<input name="password" type="password" dir="ltr" autocomplete="current-password" '
        'required></label><button class="btn primary wide">%(sign_in)s</button></form>'
        '<p class="center"><a class="pill" href="/admin/lang/%(other)s">%(lang)s</a></p></div></main>'
    ) % {"title": e(tr("title")), "hint": e(tr("login_hint")), "token": token,
         "error": '<p class="flash err">%s</p>' % e(error) if error else "",
         "user": e(tr("username")), "pass": e(tr("password")), "sign_in": e(tr("sign_in")),
         "other": other, "lang": e(tr("language"))}
    return page(lang, tr("title"), body)


def zone_label(lang, zones, zone_id):
    if zone_id == "*":
        return t(lang, "all_places")
    return next((z["name"] for z in zones if z["id"] == zone_id), zone_id)


def render_panel(ctx):
    lang, zones, csrf = ctx["lang"], ctx["zones"], ctx["csrf"]
    tr = lambda key, **kw: t(lang, key, **kw)
    hidden = '<input type="hidden" name="csrf" value="%s">' % e(csrf)
    names = {z["id"]: z["name"] for z in zones}

    # ---- status + flash
    inside = ctx["inside"]
    status = ('<div class="status on">📍 %s</div>' % e(tr("status_in", zones="، ".join(
        names.get(z, z) for z in inside))) if inside else
        '<div class="status">✅ %s</div>' % e(tr("status_none")))
    flash = "".join('<p class="flash %s">%s</p>' % (k, e(m)) for k, m in ctx["flash"])

    # ---- sites
    pickers = ['<label class="chip"><input type="checkbox" name="zones" value="*"><span>%s</span></label>'
               % e(tr("all_places"))]
    pickers += ['<label class="chip"><input type="checkbox" name="zones" value="%s"><span>%s</span></label>'
                % (e(z["id"], quote=True), e(z["name"])) for z in zones]
    rows = []
    for site in ctx["sites"]:
        label = site["site"]
        tag = '<span class="tag">%s</span>' % e(tr("app_suffix")) if label in ctx["apps"] else ""
        where = "، ".join(zone_label(lang, zones, z) for z in site["zones"]) or tr("no_zones_chosen")
        chip = {"always": tr("chip_always"), "in": tr("chip_in", zones=where),
                "except": tr("chip_except", zones=where)}[site["mode"]]
        rows.append(
            '<li class="row"><div class="grow"><b dir="ltr">%s</b> %s<div><span class="badge %s">%s</span></div></div>'
            '<div class="acts"><button type="button" class="btn small" data-edit="%s">%s</button>'
            '<form method="post" action="/admin/site/remove">%s<input type="hidden" name="site" value="%s">'
            '<button class="btn small danger">%s</button></form></div></li>'
            % (e(label), tag, site["mode"], e(chip), e(json.dumps(site), quote=True), e(tr("edit")),
               hidden, e(label, quote=True), e(tr("remove"))))
    sites = (
        '<section class="card" id="sites"><h2>🚫 %(title)s</h2><p class="note">%(porn)s</p>'
        '<form method="post" action="/admin/site/add" id="site-form" class="stack">%(hidden)s'
        '<label>%(site_label)s<input name="site" id="site-input" dir="ltr" placeholder="%(ph)s" required '
        'autocapitalize="none" autocorrect="off"></label><p class="hint">%(hint)s</p>'
        '<fieldset class="modes"><legend>%(mode_label)s</legend>'
        '<label class="mode"><input type="radio" name="mode" value="always" checked><span>%(m1)s</span></label>'
        '<label class="mode"><input type="radio" name="mode" value="in"><span>%(m2)s</span></label>'
        '<label class="mode"><input type="radio" name="mode" value="except"><span>%(m3)s</span></label></fieldset>'
        '<div id="zonepick" class="zonepick"><p class="label">%(pick)s</p><div class="chips">%(pickers)s</div>%(nozones)s</div>'
        '<button class="btn primary">%(add)s</button></form>'
        '<ul class="rows">%(rows)s</ul></section>'
    ) % {"title": e(tr("sec_sites")), "porn": e(tr("porn_note")), "hidden": hidden,
         "site_label": e(tr("site_label")), "ph": e(tr("site_ph"), quote=True), "hint": e(tr("sites_hint")),
         "mode_label": e(tr("mode_label")), "m1": e(tr("mode_always")), "m2": e(tr("mode_in")),
         "m3": e(tr("mode_except")), "pick": e(tr("pick_places")), "pickers": "".join(pickers),
         "nozones": '' if zones else '<p class="hint">%s</p>' % e(tr("no_places_hint")),
         "add": e(tr("add_site")),
         "rows": "".join(rows) or '<li class="empty">%s</li>' % e(tr("empty_sites"))}

    # ---- places
    prow = []
    for z in zones:
        where = ("%.5f, %.5f · %s m" % (z["lat"], z["lon"], z["radius"]) if z["lat"] is not None
                 else tr("no_coords"))
        if z["networks"]:
            where += " · Wi-Fi: " + ", ".join(z["networks"])
        prow.append(
            '<li class="row"><div class="grow"><b>%s</b><div class="hint" dir="ltr">%s</div></div>'
            '<div class="acts"><button type="button" class="btn small" data-zone="%s">%s</button>'
            '<form method="post" action="/admin/zone/remove">%s<input type="hidden" name="id" value="%s">'
            '<button class="btn small danger">%s</button></form></div></li>'
            % (e(z["name"]), e(where), e(json.dumps(z), quote=True), e(tr("edit")), hidden,
               e(z["id"], quote=True), e(tr("remove"))))
    places = (
        '<section class="card" id="places"><h2>📍 %(title)s</h2><p class="note">%(hint)s</p>'
        '<div class="searchbar"><input id="q" type="search" placeholder="%(sph)s"><button type="button" '
        'id="search" class="btn">%(search)s</button></div><p id="search-msg" class="hint"></p>'
        '<div id="map" class="map" dir="ltr"></div>'
        '<form method="post" action="/admin/zone/save" id="zone-form" class="stack">%(hidden)s'
        '<input type="hidden" name="id" id="zone-id"><input type="hidden" name="lat" id="zone-lat">'
        '<input type="hidden" name="lon" id="zone-lon">'
        '<label>%(name)s<input name="name" id="zone-name" maxlength="60" placeholder="%(nph)s" required></label>'
        '<label>%(radius)s<span class="range"><input type="range" id="zone-range" min="50" max="2000" step="10" value="150">'
        '<input type="number" name="radius" id="zone-radius" min="20" max="20000" value="150" dir="ltr"></span></label>'
        '<p class="hint" id="zone-coords" dir="ltr"></p>'
        '<details><summary>%(networks)s</summary><textarea name="networks" id="zone-networks" rows="3" dir="ltr" '
        'placeholder="%(netph)s"></textarea><p class="hint">%(nethint)s</p></details>'
        '<div class="btnrow"><button class="btn primary">%(save)s</button>'
        '<button type="button" class="btn" id="zone-new">%(new)s</button></div></form>'
        '<ul class="rows">%(rows)s</ul></section>'
    ) % {"title": e(tr("sec_places")), "hint": e(tr("places_hint")), "sph": e(tr("search_ph"), quote=True),
         "search": e(tr("search")), "hidden": hidden, "name": e(tr("zone_name")),
         "nph": e(tr("zone_name_ph"), quote=True), "radius": e(tr("radius")), "networks": e(tr("networks")),
         "netph": e(tr("networks_ph"), quote=True), "nethint": e(tr("networks_hint")),
         "save": e(tr("save_place")), "new": e(tr("new_place")),
         "rows": "".join(prow) or '<li class="empty">%s</li>' % e(tr("empty_places"))}

    # ---- phone
    urls = [(tr("phone_app"), ctx["base"]), (tr("phone_locate"), ctx["base"] + "/locate?lat=LAT&lon=LON")]
    for z in zones:
        urls.append((tr("phone_enter", zone=z["name"]), "%s/%s/enter" % (ctx["base"], z["id"])))
        urls.append((tr("phone_exit", zone=z["name"]), "%s/%s/exit" % (ctx["base"], z["id"])))
    phone = (
        '<section class="card" id="phone"><h2>📱 %s</h2><p class="note">%s</p><ul class="rows">%s</ul>'
        '<p class="hint">%s<br>%s</p></section>'
    ) % (e(tr("sec_phone")), e(tr("phone_hint")),
         "".join('<li class="row url"><div class="grow"><span class="label">%s</span><code dir="ltr">%s</code></div>'
                 '<button type="button" class="btn small" data-copy="%s">%s</button></li>'
                 % (e(label), e(url), e(url, quote=True), e(tr("copy"))) for label, url in urls),
         e(tr("phone_ios")), e(tr("phone_android")))

    # ---- parents
    many = len(ctx["parents"]) > 1
    prows = []
    for p in ctx["parents"]:
        me = p["username"].lower() == ctx["user"].lower()
        prows.append(
            '<li class="parent"><div class="row"><div class="grow"><b dir="ltr">%(u)s</b>%(you)s</div>%(rm)s</div>'
            '<details><summary class="btn small">%(change)s</summary>'
            '<form method="post" action="/admin/parent/update" class="stack">%(hidden)s'
            '<input type="hidden" name="username" value="%(uq)s">'
            '<label>%(nu)s<input name="new_username" dir="ltr" placeholder="%(uq)s" autocapitalize="none"></label>'
            '<label>%(np)s<input name="new_password" type="password" dir="ltr" autocomplete="new-password"></label>'
            '%(cur)s<button class="btn primary">%(save)s</button></form></details></li>'
            % {"u": e(p["username"]), "uq": e(p["username"], quote=True), "hidden": hidden,
               "you": ' <span class="tag">%s</span>' % e(tr("you")) if me else "",
               "rm": ('<form method="post" action="/admin/parent/remove">%s<input type="hidden" name="username" '
                      'value="%s"><button class="btn small danger">%s</button></form>'
                      % (hidden, e(p["username"], quote=True), e(tr("remove")))) if many and not me else "",
               "change": e(tr("change")), "nu": e(tr("new_username")), "np": e(tr("new_password")),
               "cur": ('<label>%s<input name="current" type="password" dir="ltr" autocomplete="current-password">'
                       '</label>' % e(tr("current_password"))) if me else "",
               "save": e(tr("save"))})
    parents = (
        '<section class="card" id="parents"><h2>👪 %s</h2><p class="note">%s</p><ul class="rows">%s</ul>'
        '<form method="post" action="/admin/parent/add" class="stack addparent">%s'
        '<label>%s<input name="username" dir="ltr" autocapitalize="none" required></label>'
        '<label>%s<input name="password" type="password" dir="ltr" autocomplete="new-password" required></label>'
        '<button class="btn primary">%s</button></form></section>'
    ) % (e(tr("sec_parents")), e(tr("parents_note")), "".join(prows), hidden, e(tr("username")),
         e(tr("password")), e(tr("add_parent")))

    # ---- page
    other = "en" if lang == "fa" else "fa"
    data = {"zones": zones, "center": DEFAULT_CENTER, "lang": lang,
            "i18n": {k: t(lang, k) for k in JS_STRINGS}}
    data_json = json.dumps(data, ensure_ascii=False).replace("<", "\\u003c")
    body = (
        '<header class="top"><div class="brand"><span class="logo">🛡️</span><div><b>%(title)s</b>'
        '<small>%(managing)s</small></div></div><div class="tools"><a class="pill" href="/admin/lang/%(other)s">%(lang)s</a>'
        '<form method="post" action="/admin/logout">%(hidden)s<button class="pill">%(out)s</button></form></div></header>'
        '<nav class="tabs"><a href="#sites">%(t1)s</a><a href="#places">%(t2)s</a><a href="#phone">%(t3)s</a>'
        '<a href="#parents">%(t4)s</a></nav><main>%(flash)s%(status)s%(sites)s%(places)s%(phone)s%(parents)s</main>'
    ) % {"title": e(tr("title")), "managing": e(tr("managing", child=ctx["child"])), "other": other,
         "lang": e(tr("language")), "hidden": hidden, "out": e(tr("sign_out")), "t1": e(tr("sec_sites")),
         "t2": e(tr("sec_places")), "t3": e(tr("sec_phone")), "t4": e(tr("sec_parents")),
         "flash": flash, "status": status, "sites": sites, "places": places, "phone": phone, "parents": parents}
    scripts = ('<script type="application/json" id="data">%s</script>'
               '<script src="/admin/static/leaflet/leaflet.js"></script>'
               '<script src="/admin/static/admin.js"></script>' % data_json)
    return page(lang, tr("title"), body, scripts)

