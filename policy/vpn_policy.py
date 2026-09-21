#!/usr/bin/env python3
"""Content policy for the VPN appliance (3X-UI / Xray).

Everything is enforced on the server, inside the Xray routing table, so it
applies to any VLESS/VMess client (v2rayNG, Shadowrocket, V2Box, Streisand...)
without touching the phone:

* Porn is blocked for every user: all DNS that goes through the tunnel is
  answered by a family-safe resolver whatever resolver the client configured,
  DoH/DoT to public resolvers is blocked, and destinations are matched by the
  sniffed TLS/HTTP/QUIC hostname, not by the client's own DNS answer.
* Every 3X-UI client gets its own policy and a parent account. Parents (web
  page reachable through the tunnel) choose, per site, whether it is blocked
  always, only in some places, or everywhere except some places.
* Places are drawn on a map (centre + radius). The phone reports its position
  to a gate reachable only through the tunnel and the server decides which
  places it is in; a place can also be a Wi-Fi network (source IP).

The server cannot read a phone's GPS: the phone's OS reports it (iOS
Shortcuts / Android Tasker or MacroDroid). See docs/content-policy.md.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import hmac
import http.cookiejar
import http.server
import ipaddress
import json
import math
import os
import re
import secrets
import shlex
import socket
import struct
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

import webui
from i18n import UserError

sys.path.insert(0, str(Path(__file__).resolve().parent))
ROOT = Path(os.environ.get("ROOT_DIR") or Path(__file__).resolve().parent.parent)
STATE = ROOT / "state"
TAG = "vpnapp-"

DEFAULTS = {
    "XUI_PANEL_PORT": "2053",
    "POLICY_BLOCK_PORN": "true",
    "POLICY_BLOCK_DOH": "true",
    "POLICY_FAMILY_DNS": "1.1.1.3 1.0.0.3",
    "POLICY_EXTRA_BLOCK_DOMAINS": "",
    "POLICY_ALLOW_DOMAINS": "",
    "POLICY_ZONE_APPS": "youtube instagram",
    "POLICY_ZONE_SOURCE_IPS": "",
    "POLICY_SYNC_SECONDS": "60",
    "POLICY_GATE_ENABLED": "true",
    "POLICY_GATE_PORT": "9099",
    "POLICY_GATE_VIRTUAL_IP": "192.0.2.1",
}

SITE_RE = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}$")
KEYWORD_RE = re.compile(r"^[a-z0-9-]{3,40}$")

PORN_DOMAINS = [
    "geosite:category-porn",
    "domain:xxx", "domain:porn", "domain:sex", "domain:adult",
    "keyword:porn", "keyword:xvideos", "keyword:xnxx", "keyword:xhamster",
    "keyword:redtube", "keyword:youporn", "keyword:hentai", "keyword:onlyfans",
]

APP_DOMAINS = {
    "youtube": [
        "geosite:youtube", "domain:youtube.com", "domain:youtu.be",
        "domain:youtube-nocookie.com", "domain:youtubekids.com",
        "domain:googlevideo.com", "domain:ytimg.com",
        "domain:youtubei.googleapis.com", "domain:youtube.googleapis.com",
    ],
    "instagram": [
        "geosite:instagram", "domain:instagram.com", "domain:cdninstagram.com",
        "domain:instagr.am", "domain:ig.me", "domain:igsonar.com",
    ],
}

DOH_DOMAINS = [
    "domain:dns.google", "domain:dns64.dns.google", "domain:cloudflare-dns.com",
    "domain:one.one.one.one", "domain:dns.quad9.net", "domain:doh.opendns.com",
    "domain:dns.adguard-dns.com", "domain:dns.nextdns.io",
    "domain:doh.cleanbrowsing.org", "domain:doh.dns.sb", "domain:dns.sb",
]
DOH_IPS = [
    "1.1.1.1", "1.0.0.1", "1.1.1.2", "1.0.0.2", "1.1.1.3", "1.0.0.3",
    "8.8.8.8", "8.8.4.4", "9.9.9.9", "149.112.112.112",
    "208.67.222.222", "208.67.220.220", "94.140.14.14", "94.140.15.15",
    "2606:4700:4700::1111", "2606:4700:4700::1001",
    "2001:4860:4860::8888", "2001:4860:4860::8844", "2620:fe::fe",
]

EMAIL_RE = re.compile(r"^[A-Za-z0-9._@+-]{1,64}$")
ZONE_RE = re.compile(r"^[A-Za-z0-9_-]{1,32}$")


def log(message):
    print(message, flush=True)


# --------------------------------------------------------------------------
# configuration
# --------------------------------------------------------------------------

def read_env_file(path):
    values = {}
    if not path.is_file():
        return values
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, raw = line.partition("=")
        try:
            values[key.strip()] = " ".join(shlex.split(raw, comments=True))
        except ValueError:
            values[key.strip()] = raw.strip()
    return values


def load_config():
    cfg = dict(DEFAULTS)
    for name in ("xui.env", "server.env", "secrets.env", "inbound.env", "client.env"):
        cfg.update(read_env_file(STATE / name))
    cfg.update(read_env_file(ROOT / "config" / ".env"))
    cfg.update({k: v for k, v in os.environ.items()
                if k in DEFAULTS or k.startswith(("XUI_", "POLICY_", "PANEL_", "CLIENT_"))})
    return cfg


def flag(cfg, key):
    return cfg.get(key, "").strip().lower() in ("1", "true", "yes", "on")


def words(cfg, key):
    return cfg.get(key, "").replace(",", " ").split()


# --------------------------------------------------------------------------
# 3X-UI panel API
# --------------------------------------------------------------------------

class PanelError(RuntimeError):
    pass


class Panel:
    """Minimal 3X-UI client: cookie session + CSRF token, stdlib only."""

    XRAY_PREFIXES = ("/panel/api/xray", "/panel/xray")  # newer, older

    def __init__(self, cfg, timeout=20):
        self.base = "http://127.0.0.1:%s" % cfg["XUI_PANEL_PORT"]
        self.username = cfg.get("PANEL_USERNAME", "")
        self.password = cfg.get("PANEL_PASSWORD", "")
        self.timeout = timeout
        self.csrf = ""
        self.xray_prefix = self.XRAY_PREFIXES[0]
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))

    def _open(self, method, path, body=None, content_type=None):
        request = urllib.request.Request(self.base + path, data=body, method=method)
        if content_type:
            request.add_header("Content-Type", content_type)
        if self.csrf:
            request.add_header("X-CSRF-Token", self.csrf)
        try:
            with self.opener.open(request, timeout=self.timeout) as response:
                return response.status, response.read()
        except urllib.error.HTTPError as error:
            return error.code, error.read()
        except (urllib.error.URLError, OSError) as error:
            raise PanelError("panel unreachable at %s: %s" % (self.base, error))

    def call(self, method, path, payload=None, form=None, check=True):
        body, content_type = None, None
        if payload is not None:
            body, content_type = json.dumps(payload).encode(), "application/json"
        elif form is not None:
            body = urllib.parse.urlencode(form).encode()
            content_type = "application/x-www-form-urlencoded"
        status, raw = self._open(method, path, body, content_type)
        try:
            document = json.loads(raw)
        except ValueError:
            document = {}
        if check and not document.get("success"):
            raise PanelError("%s %s failed: HTTP %s %s" % (method, path, status, raw[:200]))
        return status, document

    def login(self):
        if not self.username or not self.password:
            raise PanelError("PANEL_USERNAME/PANEL_PASSWORD not found in state/secrets.env")
        _, page = self._open("GET", "/")
        match = re.search(rb'name="csrf-token" content="([^"]+)"', page)
        self.csrf = match.group(1).decode() if match else ""  # older panels have none
        self.call("POST", "/login",
                  payload={"username": self.username, "password": self.password})

    def xray_setting(self):
        for prefix in self.XRAY_PREFIXES:
            status, document = self.call("POST", prefix + "/", check=False)
            if status != 404:
                break
        if not document.get("success"):
            raise PanelError("could not read the Xray template from the panel (HTTP %s)" % status)
        self.xray_prefix = prefix
        obj = document["obj"]
        if isinstance(obj, str):
            obj = json.loads(obj)
        setting = obj["xraySetting"]
        if isinstance(setting, str):
            setting = json.loads(setting)
        return setting, obj.get("outboundTestUrl", "")

    def save_xray_setting(self, setting, outbound_test_url=""):
        form = {"xraySetting": json.dumps(setting)}
        if outbound_test_url:
            form["outboundTestUrl"] = outbound_test_url
        self.call("POST", self.xray_prefix + "/update", form=form)

    def xray_state(self):
        _, document = self.call("GET", "/panel/api/server/status")
        return document["obj"]["xray"]

    def restart_xray(self, wait=30, settle=5):
        """Restart Xray and require it to stay up for `settle` seconds.

        A config Xray rejects makes the panel crash-loop it, so a single
        "running" reading right after the restart proves nothing.
        """
        self.call("POST", "/panel/api/server/restartXrayService")
        started = time.time()
        deadline = started + wait
        stable_since = None
        state = {}
        while time.time() < deadline:
            state = self.xray_state()
            if state.get("state") == "running":
                stable_since = stable_since or time.time()
                if time.time() - stable_since >= settle:
                    return
            else:
                stable_since = None
                # a stale error from before the restart clears within a second or two
                if state.get("state") == "error" and time.time() - started > 3:
                    break
            time.sleep(0.5)
        raise PanelError("Xray is not staying up after restart: %s"
                         % (state.get("errorMsg") or state.get("state")))

    def inbounds(self):
        _, document = self.call("GET", "/panel/api/inbounds/list")
        return document.get("obj") or []

    def client_emails(self):
        """Emails of every VPN user (3X-UI "client")."""
        status, document = self.call("GET", "/panel/api/clients/list", check=False)
        if status != 404 and document.get("success"):
            return sorted({c["email"] for c in document.get("obj") or [] if c.get("email")})
        emails = set()  # older panels: read them out of the inbounds
        for inbound in self.inbounds():
            settings = inbound.get("settings") or {}
            settings = json.loads(settings) if isinstance(settings, str) else settings
            emails |= {c["email"] for c in settings.get("clients", []) if c.get("email")}
        return sorted(emails)

    def update_inbound(self, inbound):
        self.call("POST", "/panel/api/inbounds/update/%s" % inbound["id"], payload=inbound)


# --------------------------------------------------------------------------
# helpers kept from before
# --------------------------------------------------------------------------

def rule(name, outbound, **match):
    return dict(type="field", ruleTag=TAG + name, outboundTag=outbound, **match)


def is_ours(item):
    tag = item.get("ruleTag") or item.get("tag") or ""
    return tag.startswith(TAG)


def strip_managed(template):
    """Remove everything this module added, leaving the panel's own config."""
    template = copy.deepcopy(template)
    routing = template.setdefault("routing", {})
    routing["rules"] = [r for r in routing.get("rules", []) if not is_ours(r)]
    template["outbounds"] = [o for o in template.get("outbounds", []) if not is_ours(o)]
    if (template.get("dns") or {}).get("tag") == TAG + "dns":
        del template["dns"]
        if routing.get("domainStrategy") == "IPIfNonMatch":
            routing["domainStrategy"] = "AsIs"
    return template


# --------------------------------------------------------------------------
# DNS check
# --------------------------------------------------------------------------

def _skip_name(packet, pos):
    while True:
        length = packet[pos]
        if length & 0xC0 == 0xC0:
            return pos + 2
        if length == 0:
            return pos + 1
        pos += 1 + length


def dns_lookup(server, name, timeout=4, port=53):
    """Plain UDP A lookup -> (rcode, [ipv4, ...])."""
    qname = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\0"
    tid = secrets.token_bytes(2)
    packet = tid + struct.pack(">HHHHH", 0x0100, 1, 0, 0, 0) + qname + struct.pack(">HH", 1, 1)
    family = socket.AF_INET6 if ":" in server else socket.AF_INET
    with socket.socket(family, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        sock.sendto(packet, (server, port))
        reply, _ = sock.recvfrom(4096)
    if reply[:2] != tid:
        raise OSError("mismatched DNS reply")
    rcode = reply[3] & 0x0F
    questions, answers = struct.unpack(">HH", reply[4:8])
    pos = 12
    for _ in range(questions):
        pos = _skip_name(reply, pos) + 4
    addresses = []
    for _ in range(answers):
        pos = _skip_name(reply, pos)
        rtype, _, _, length = struct.unpack(">HHIH", reply[pos:pos + 10])
        pos += 10
        if rtype == 1 and length == 4:
            addresses.append(socket.inet_ntoa(reply[pos:pos + 4]))
        pos += length
    return rcode, addresses


def check_family_dns(cfg):
    """Return (ok, message). Requires a reachable resolver that filters porn."""
    for server in words(cfg, "POLICY_FAMILY_DNS"):
        try:
            _, clean = dns_lookup(server, "example.com")
            rcode, adult = dns_lookup(server, "pornhub.com")
        except OSError as error:
            log("family DNS %s unreachable: %s" % (server, error))
            continue
        filtered = rcode == 3 or not adult or adult == ["0.0.0.0"]
        if clean and clean != ["0.0.0.0"] and filtered:
            return True, "family DNS %s resolves example.com and blocks pornhub.com" % server
        return False, "DNS server %s does not filter adult domains" % server
    return False, "no POLICY_FAMILY_DNS server is reachable from this host"


SNIFFING = {"enabled": True, "destOverride": ["http", "tls", "quic"],
            "metadataOnly": False, "routeOnly": True}


def ensure_sniffing(panel):
    """Domain rules need the destination hostname, so sniffing must be on."""
    changed = []
    for inbound in panel.inbounds():
        raw = inbound.get("sniffing") or {}
        current = json.loads(raw) if isinstance(raw, str) else dict(raw)
        wanted = set(SNIFFING["destOverride"])
        if (current.get("enabled") and not current.get("metadataOnly")
                and {"http", "tls"} <= set(current.get("destOverride") or [])):
            continue
        merged = dict(current, **SNIFFING)
        merged["destOverride"] = sorted(wanted | set(current.get("destOverride") or []))
        inbound["sniffing"] = json.dumps(merged) if isinstance(raw, str) else merged
        panel.update_inbound(inbound)
        changed.append(inbound.get("remark") or str(inbound["id"]))
    return changed


def remove_policy(cfg):
    panel = Panel(cfg)
    panel.login()
    base, test_url = panel.xray_setting()
    panel.save_xray_setting(strip_managed(base), test_url)
    panel.restart_xray()


def gate_secret():
    path = STATE / "gate.secret"
    if not path.exists():
        STATE.mkdir(parents=True, exist_ok=True)
        path.write_text(secrets.token_hex(32))
        path.chmod(0o600)
    return path.read_text().strip().encode()


def gate_token(email):
    return hmac.new(gate_secret(), email.encode(), hashlib.sha256).hexdigest()[:32]



# --------------------------------------------------------------------------
# sites, places and parents (kept per child = per 3X-UI client)
# --------------------------------------------------------------------------

MODES = ("always", "in", "except")
ANY_ZONE = "*"
MAX_SITES, MAX_ZONES, MAX_NETWORKS = 300, 30, 10
RADIUS_RANGE = (20, 20000)
USER_RE = re.compile(r"^[A-Za-z0-9._@+-]{3,40}$")
HOST_RE = re.compile(r"^(?:[a-z0-9-]+\.)+[a-z]{2,}$")


def normalize_entry(text):
    """Turn what a parent typed into the stored form, or raise UserError.

    Accepts a site as copied from a browser (https://www.tiktok.com/x -> tiktok.com),
    an app name known to this module (youtube), or keyword:word.
    """
    text = text.strip().lower()
    if text in APP_DOMAINS:
        return text
    if text.startswith("keyword:"):
        word = text[len("keyword:"):]
        if KEYWORD_RE.match(word):
            return "keyword:" + word
        raise UserError("err_keyword")
    try:
        host = urllib.parse.urlsplit(text if "://" in text else "//" + text).hostname or ""
        host = host[4:] if host.startswith("www.") else host
        host = host.encode("idna").decode("ascii")
    except (ValueError, UnicodeError):
        host = ""
    if not SITE_RE.match(host):
        raise UserError("err_site", text=text[:60])
    return host


def expand_entries(entries):
    """Stored entries -> Xray domain rules."""
    rules = []
    for entry in entries:
        if entry in APP_DOMAINS:
            rules += APP_DOMAINS[entry]
        elif entry.startswith("keyword:"):
            rules.append(entry)
        else:
            rules.append("domain:" + entry)
    return list(dict.fromkeys(rules))


def parse_networks(text):
    """IPs, CIDRs or DDNS host names, separated by whitespace or commas."""
    tokens = list(dict.fromkeys(re.split(r"[\s,;]+", text.strip().lower()))) if text.strip() else []
    if len(tokens) > MAX_NETWORKS:
        raise UserError("err_networks", text="...")
    for token in tokens:
        try:
            ipaddress.ip_network(token, strict=False)
        except ValueError:
            if not HOST_RE.match(token):
                raise UserError("err_networks", text=token[:60])
    return tokens


def resolve_networks(tokens):
    """Networks as IPs/CIDRs; host names (DDNS) are resolved now."""
    found = []
    for token in tokens:
        try:
            found.append(str(ipaddress.ip_network(token, strict=False)))
            continue
        except ValueError:
            pass
        try:
            for info in socket.getaddrinfo(token, None, type=socket.SOCK_STREAM):
                found.append(str(ipaddress.ip_network(info[4][0])))
        except (OSError, ValueError):
            log("WARNING: could not resolve %r; skipping it" % token)
    return sorted(set(found))


def distance_m(lat1, lon1, lat2, lon2):
    """Great-circle distance in metres."""
    p1, p2 = math.radians(lat1), math.radians(lat2)
    a = (math.sin((p2 - p1) / 2) ** 2
         + math.cos(p1) * math.cos(p2) * math.sin(math.radians(lon2 - lon1) / 2) ** 2)
    return 2 * 6371000 * math.asin(math.sqrt(a))


def default_child(cfg, legacy=None):
    """Policy for a child that has none yet.

    `legacy` is the old global {always, geo} pair; without it POLICY_ZONE_APPS
    seeds "blocked in any place I'm restricted".
    """
    if legacy is not None:
        sites = [{"site": s, "mode": "always", "zones": []} for s in legacy.get("always", [])]
        sites += [{"site": s, "mode": "in", "zones": [ANY_ZONE]} for s in legacy.get("geo", [])]
    else:
        apps = words(cfg, "POLICY_ZONE_APPS")
        for app in apps:
            if app not in APP_DOMAINS:
                raise PanelError("unknown POLICY_ZONE_APPS entry %r (known: %s)"
                                 % (app, ", ".join(sorted(APP_DOMAINS))))
        sites = [{"site": a, "mode": "in", "zones": [ANY_ZONE]} for a in apps]
    zones = []
    networks = words(cfg, "POLICY_ZONE_SOURCE_IPS")
    if networks:
        zones.append({"id": "network", "name": "Network", "lat": None, "lon": None,
                      "radius": 150, "networks": networks})
    return {"zones": zones, "sites": sites}


def _write_json(path, data):
    STATE.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False))
    tmp.chmod(0o600)
    os.replace(tmp, path)


class PolicyStore:
    """Per-child sites and places: {"children": {email: {"zones": [...], "sites": [...]}}}.

    A site has a mode: `always` (blocked everywhere), `in` (blocked only in the
    listed places) or `except` (blocked everywhere but the listed places).
    The zone list may contain "*" meaning any place the child is in.
    """

    def __init__(self, cfg):
        self.cfg = cfg
        self.lock = threading.Lock()

    @property
    def path(self):
        return STATE / "policy.json"

    def _read(self):
        try:
            data = json.loads(self.path.read_text())
        except FileNotFoundError:
            data = {}
        except ValueError:
            raise PanelError("%s is not valid JSON; fix or delete it" % self.path)
        data.setdefault("children", {})
        return data

    def _child(self, data, email):
        if email not in data["children"]:
            raise UserError("err_child", child=email)
        return data["children"][email]

    def children(self):
        with self.lock:
            return copy.deepcopy(self._read()["children"])

    def get(self, email):
        return self.children().get(email)

    def ensure(self, emails):
        """Create default policy for children that have none; returns their emails."""
        with self.lock:
            data = self._read()
            legacy_path = STATE / "blocklists.json"
            legacy = None
            if not self.path.exists() and legacy_path.exists() and emails:
                try:
                    legacy = json.loads(legacy_path.read_text())
                except ValueError:
                    legacy = None
            created = [e for e in emails if e not in data["children"]]
            for email in created:
                data["children"][email] = default_child(self.cfg, legacy)
            if created:
                _write_json(self.path, data)
                if legacy is not None:
                    legacy_path.rename(legacy_path.with_name("blocklists.json.migrated"))
            return created

    def set_site(self, email, text, mode, zones=()):
        if mode not in MODES:
            raise UserError("err_mode")
        entry = normalize_entry(text)
        with self.lock:
            data = self._read()
            child = self._child(data, email)
            known = {z["id"] for z in child["zones"]}
            chosen = [] if mode == "always" else [z for z in dict.fromkeys(zones)
                                                   if z == ANY_ZONE or z in known]
            sites = [s for s in child["sites"] if s["site"] != entry]
            if len(sites) >= MAX_SITES:
                raise UserError("err_list_full", limit=MAX_SITES)
            child["sites"] = sites + [{"site": entry, "mode": mode, "zones": chosen}]
            _write_json(self.path, data)
        return entry

    def remove_site(self, email, text):
        entry = normalize_entry(text)
        with self.lock:
            data = self._read()
            child = self._child(data, email)
            child["sites"] = [s for s in child["sites"] if s["site"] != entry]
            _write_json(self.path, data)
        return entry

    def save_zone(self, email, zone_id, name, lat, lon, radius, networks_text=""):
        """Create (zone_id empty) or update a place; returns the zone dict."""
        name = " ".join(str(name).split())[:60]
        if not name:
            raise UserError("err_zone_name")
        networks = parse_networks(networks_text)
        blank = str(lat).strip() == "" and str(lon).strip() == ""
        try:
            lat, lon = (None, None) if blank else (float(lat), float(lon))
            if lat is not None and not (-90 <= lat <= 90 and -180 <= lon <= 180):
                raise ValueError
            radius = int(float(radius or 150))
        except (TypeError, ValueError):
            raise UserError("err_zone_coords")
        if lat is None and not networks:
            raise UserError("err_zone_position")
        if lat is not None and not RADIUS_RANGE[0] <= radius <= RADIUS_RANGE[1]:
            raise UserError("err_zone_radius", low=RADIUS_RANGE[0], high=RADIUS_RANGE[1])
        with self.lock:
            data = self._read()
            child = self._child(data, email)
            zones = child["zones"]
            if zone_id:
                if not any(z["id"] == zone_id for z in zones):
                    raise UserError("err_no_such")
            else:
                if len(zones) >= MAX_ZONES:
                    raise UserError("err_zone_limit", limit=MAX_ZONES)
                base = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")[:24] or "zone"
                taken = {z["id"] for z in zones}
                zone_id = base
                for n in range(2, 1000):
                    if zone_id not in taken:
                        break
                    zone_id = "%s-%d" % (base, n)
            zone = {"id": zone_id, "name": name, "lat": lat, "lon": lon,
                    "radius": radius, "networks": networks}
            child["zones"] = [zone if z["id"] == zone_id else z for z in zones]
            if not any(z["id"] == zone_id for z in zones):
                child["zones"].append(zone)
            _write_json(self.path, data)
        return zone

    def remove_zone(self, email, zone_id):
        with self.lock:
            data = self._read()
            child = self._child(data, email)
            child["zones"] = [z for z in child["zones"] if z["id"] != zone_id]
            for site in child["sites"]:
                site["zones"] = [z for z in site["zones"] if z != zone_id]
            _write_json(self.path, data)


class ParentStore:
    """Parent accounts. Each belongs to one child; a child can have several."""

    def __init__(self):
        self.lock = threading.Lock()

    @property
    def path(self):
        return STATE / "parents.json"

    @property
    def credentials_path(self):
        return STATE / "parent-credentials.txt"

    def _read(self):
        try:
            data = json.loads(self.path.read_text())
        except FileNotFoundError:
            data = {}
        except ValueError:
            raise PanelError("%s is not valid JSON; fix or delete it" % self.path)
        data.setdefault("parents", {})
        return data

    @staticmethod
    def _digest(password, salt):
        return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200_000)

    def _record(self, child, username, password):
        salt = os.urandom(16)
        return {"username": username, "child": child, "salt": salt.hex(),
                "hash": self._digest(password, salt).hex()}

    @staticmethod
    def _check_username(username):
        if not USER_RE.match(username):
            raise UserError("err_username")

    @staticmethod
    def _check_password(password):
        if len(password) < 8 or len(password) > 128:
            raise UserError("err_password_short")

    # -- the credentials file lists accounts still on their generated password
    def _remember(self, child, username, password):
        with open(self.credentials_path, "a") as f:
            f.write("%s\t%s\t%s\n" % (child, username, password))
        self.credentials_path.chmod(0o600)

    def _forget(self, username):
        try:
            lines = self.credentials_path.read_text().splitlines()
        except FileNotFoundError:
            return
        keep = [l for l in lines if l.split("\t")[1:2] != [username]
                and (len(l.split("\t")) < 2 or l.split("\t")[1].lower() != username.lower())]
        self.credentials_path.write_text("".join(l + "\n" for l in keep))
        self.credentials_path.chmod(0o600)

    @staticmethod
    def _public(record):
        return {"username": record["username"], "child": record["child"]}

    def authenticate(self, username, password):
        with self.lock:
            record = self._read()["parents"].get(username.strip().lower())
        salt = bytes.fromhex(record["salt"]) if record else b"\0" * 16
        digest = self._digest(password, salt)  # same work whether or not the user exists
        if record and hmac.compare_digest(digest, bytes.fromhex(record["hash"])):
            return self._public(record)
        return None

    def get(self, username):
        with self.lock:
            record = self._read()["parents"].get(username.strip().lower())
        return self._public(record) if record else None

    def of_child(self, child):
        with self.lock:
            records = self._read()["parents"].values()
            return sorted((self._public(r) for r in records if r["child"] == child),
                          key=lambda r: r["username"].lower())

    def add(self, child, username, password):
        self._check_username(username)
        self._check_password(password)
        with self.lock:
            data = self._read()
            if username.lower() in data["parents"]:
                raise UserError("err_username_taken")
            data["parents"][username.lower()] = self._record(child, username, password)
            _write_json(self.path, data)

    def update(self, username, new_username="", new_password=""):
        """Rename and/or change the password; returns the (possibly new) username."""
        if not new_username and not new_password:
            raise UserError("err_nothing")
        if new_username:
            self._check_username(new_username)
        if new_password:
            self._check_password(new_password)
        with self.lock:
            data = self._read()
            record = data["parents"].get(username.lower())
            if not record:
                raise UserError("err_no_such")
            if new_username and new_username.lower() != username.lower() \
                    and new_username.lower() in data["parents"]:
                raise UserError("err_username_taken")
            del data["parents"][username.lower()]
            record["username"] = new_username or record["username"]
            if new_password:
                fresh = self._record(record["child"], record["username"], new_password)
                record["salt"], record["hash"] = fresh["salt"], fresh["hash"]
            data["parents"][record["username"].lower()] = record
            _write_json(self.path, data)
            self._forget(username)
        return record["username"]

    def remove(self, username):
        with self.lock:
            data = self._read()
            record = data["parents"].get(username.lower())
            if not record:
                raise UserError("err_no_such")
            if sum(1 for r in data["parents"].values() if r["child"] == record["child"]) < 2:
                raise UserError("err_last_parent")
            del data["parents"][username.lower()]
            _write_json(self.path, data)
            self._forget(username)

    def reset(self, username):
        """New random password for `username` (admin action); returns it."""
        password = secrets.token_urlsafe(9)
        with self.lock:
            data = self._read()
            record = data["parents"].get(username.lower())
            if not record:
                raise UserError("err_no_such")
            fresh = self._record(record["child"], record["username"], password)
            record["salt"], record["hash"] = fresh["salt"], fresh["hash"]
            _write_json(self.path, data)
            self._forget(username)
            self._remember(record["child"], record["username"], password)
        return password

    def ensure_for(self, children):
        """Give every child a parent; returns [(child, username, password)] just created."""
        created = []
        with self.lock:
            data = self._read()
            legacy = STATE / "parent-auth.json"
            migrated = False
            if not self.path.exists() and legacy.exists() and len(children) == 1:
                try:
                    old = json.loads(legacy.read_text())
                    data["parents"]["parent"] = {"username": "parent", "child": children[0],
                                                 "salt": old["salt"], "hash": old["hash"]}
                    migrated = True
                except (ValueError, KeyError):
                    pass
            have = {r["child"] for r in data["parents"].values()}
            for child in children:
                if child in have:
                    continue
                base = re.sub(r"[^A-Za-z0-9._@+-]+", "-", child).strip("-") or "child"
                username = "%s-parent" % base[:30]
                for n in range(2, 1000):
                    if username.lower() not in data["parents"]:
                        break
                    username = "%s-parent-%d" % (base[:26], n)
                password = secrets.token_urlsafe(9)
                data["parents"][username.lower()] = self._record(child, username, password)
                self._remember(child, username, password)
                created.append((child, username, password))
            if created or migrated:
                _write_json(self.path, data)
                if migrated:
                    legacy.rename(legacy.with_name("parent-auth.json.migrated"))
        return created


# --------------------------------------------------------------------------
# Xray template
# --------------------------------------------------------------------------

def child_rules(index, email, child, inside, nets, allow, block):
    """Xray rules for one child, given the places the child is in right now.

    Order matters (first match wins): always-blocks, then place-blocks, then
    "open here" exceptions, then the block for everywhere else.
    """
    inside = set(inside)

    def matchers(zone_ids):
        if (ANY_ZONE in zone_ids and inside) or inside & set(zone_ids):
            return [{}]  # currently in one of them: applies to every connection
        wanted = nets.keys() if ANY_ZONE in zone_ids else [z for z in zone_ids if z in nets]
        return [{"source": nets[z]} for z in sorted(wanted)]  # Wi-Fi networks of those places

    always, blocked_in, open_in = [], {}, {}
    for site in child["sites"]:
        if site["mode"] == "always":
            always.append(site["site"])
        else:
            bucket = blocked_in if site["mode"] == "in" else open_in
            bucket.setdefault(tuple(sorted(site["zones"])), []).append(site["site"])
    user, prefix, rules = [email], "c%d-" % index, []
    if always:
        rules.append(rule(prefix + "always", block, user=user, domain=expand_entries(always)))
    for k, (zones, sites) in enumerate(sorted(blocked_in.items())):
        for j, match in enumerate(matchers(zones)):
            rules.append(rule("%sin%d-%d" % (prefix, k, j), block, user=user,
                              domain=expand_entries(sites), **match))
    blocked_elsewhere = []
    for k, (zones, sites) in enumerate(sorted(open_in.items())):
        domains = expand_entries(sites)
        blocked_elsewhere += domains
        for j, match in enumerate(matchers(zones)):
            rules.append(rule("%sopen%d-%d" % (prefix, k, j), allow, user=user,
                              domain=domains, **match))
    if blocked_elsewhere:
        rules.append(rule(prefix + "except", block, user=user,
                          domain=list(dict.fromkeys(blocked_elsewhere))))
    return rules


def build_template(base, cfg, children=None, in_zones=None, nets=None):
    """Return `base` with the policy layered on. Pure and idempotent.

    children: {email: policy}; in_zones: {email: [zone ids]} the child is in now;
    nets: {email: {zone id: [cidr, ...]}} resolved Wi-Fi networks of each place.
    """
    template = strip_managed(base)
    routing = template["routing"]
    outbounds = template["outbounds"]
    front = []

    freedom = next((o["tag"] for o in outbounds
                    if o.get("protocol") == "freedom" and o.get("tag")), None)
    if freedom is None:
        freedom = TAG + "direct"
        outbounds.append({"tag": freedom, "protocol": "freedom", "settings": {}})
    outbounds.append({"tag": TAG + "block", "protocol": "blackhole", "settings": {}})
    block = TAG + "block"

    if flag(cfg, "POLICY_GATE_ENABLED"):
        redirect = "127.0.0.1:%s" % cfg["POLICY_GATE_PORT"]
        # Recent Xray blackholes loopback targets by default; allow only the gate.
        outbounds.append({"tag": TAG + "gate", "protocol": "freedom", "settings": {
            "redirect": redirect,
            "finalRules": [
                {"action": "allow", "ip": ["127.0.0.1"], "port": cfg["POLICY_GATE_PORT"]},
                {"action": "block"},
            ]}})
        front.append(rule("gate", TAG + "gate", ip=[cfg["POLICY_GATE_VIRTUAL_IP"]],
                          port=cfg["POLICY_GATE_PORT"], network="tcp"))

    if flag(cfg, "POLICY_BLOCK_PORN"):
        family = words(cfg, "POLICY_FAMILY_DNS")
        if not family:
            raise PanelError("POLICY_FAMILY_DNS is empty")
        template["dns"] = {"tag": TAG + "dns", "servers": family, "queryStrategy": "UseIP"}
        if routing.get("domainStrategy", "AsIs") == "AsIs":
            routing["domainStrategy"] = "IPIfNonMatch"
        outbounds.append({"tag": TAG + "dns-out", "protocol": "dns"})
        allowed = words(cfg, "POLICY_ALLOW_DOMAINS")
        # Xray's own lookups must reach the resolver, not loop into the hijack.
        front.append(rule("dns-internal", freedom, inboundTag=[TAG + "dns"]))
        front.append(rule("dns-hijack", TAG + "dns-out", port="53"))
        if flag(cfg, "POLICY_BLOCK_DOH"):
            front.append(rule("block-dot", block, port="853"))
            front.append(rule("block-doh-ip", block, ip=DOH_IPS, port="443"))
            front.append(rule("block-doh-name", block, domain=DOH_DOMAINS))
        if allowed:
            front.append(rule("allow", freedom, domain=allowed))
        front.append(rule("block-porn", block,
                          domain=PORN_DOMAINS + words(cfg, "POLICY_EXTRA_BLOCK_DOMAINS")))
        # Family resolvers answer 0.0.0.0 for blocked names.
        front.append(rule("block-null-ip", block, ip=["0.0.0.0/32", "::/128"]))

    for index, (email, child) in enumerate(sorted((children or {}).items())):
        front += child_rules(index, email, child, (in_zones or {}).get(email, ()),
                             (nets or {}).get(email, {}), freedom, block)

    rules = routing.setdefault("rules", [])
    anchor = next((i + 1 for i, r in enumerate(rules) if r.get("outboundTag") == "api"), 0)
    rules[anchor:anchor] = front
    return template


# --------------------------------------------------------------------------
# applying the policy
# --------------------------------------------------------------------------

def sync(cfg, force=False):
    """Give every 3X-UI client a policy and a parent, then apply. True if Xray changed."""
    panel = Panel(cfg)
    panel.login()
    emails = panel.client_emails()
    PolicyStore(cfg).ensure(emails)
    for child, username, _ in ParentStore().ensure_for(emails):
        log("created parent account %r for %r (initial password in %s)"
            % (username, child, ParentStore().credentials_path))
    return apply_policy(cfg, force=force, panel=panel)


def apply_policy(cfg, force=False, panel=None):
    """Layer the policy onto the panel's Xray template. Returns True if changed.

    The previous template is restored if Xray does not come back up.
    """
    if flag(cfg, "POLICY_BLOCK_PORN"):
        ok, message = check_family_dns(cfg)
        if not ok:
            raise PanelError(message + " (refusing to hijack DNS)")
    if panel is None:
        panel = Panel(cfg)
        panel.login()
    sniffing_changed = ensure_sniffing(panel)
    if sniffing_changed:
        log("Enabled traffic sniffing on: %s" % ", ".join(sniffing_changed))

    base, test_url = panel.xray_setting()
    backup = STATE / "xray-template.pre-policy.json"
    if not backup.exists():
        STATE.mkdir(parents=True, exist_ok=True)
        backup.write_text(json.dumps(strip_managed(base), indent=2))
        backup.chmod(0o600)

    children = PolicyStore(cfg).children()
    nets = {email: {z["id"]: resolve_networks(z["networks"]) for z in child["zones"] if z["networks"]}
            for email, child in children.items()}
    template = build_template(base, cfg, children, ZoneState().in_zones(), nets)
    if template == base and not sniffing_changed and not force:
        return False

    panel.save_xray_setting(template, test_url)
    try:
        panel.restart_xray()
    except PanelError as error:
        log("Xray failed with the new policy (%s); restoring previous template" % error)
        panel.save_xray_setting(base, test_url)
        panel.restart_xray()
        raise PanelError("policy rejected by Xray, previous config restored: %s" % error)
    return True


def verify(cfg):
    """Return a list of (ok, message) checks against the live panel."""
    results = []
    try:
        panel = Panel(cfg)
        panel.login()
        base, _ = panel.xray_setting()
        emails = panel.client_emails()
    except PanelError as error:
        return [(False, str(error))]
    names = {r.get("ruleTag") for r in base["routing"]["rules"]}
    expected = ["block-porn", "dns-hijack"] if flag(cfg, "POLICY_BLOCK_PORN") else []
    if flag(cfg, "POLICY_GATE_ENABLED"):
        expected.append("gate")
    for name in expected:
        results.append((TAG + name in names, "routing rule %s%s" % (TAG, name)))
    for inbound in panel.inbounds():
        sniffing = inbound.get("sniffing") or {}
        if isinstance(sniffing, str):
            sniffing = json.loads(sniffing)
        results.append((bool(sniffing.get("enabled")),
                        "sniffing on inbound %s" % (inbound.get("remark") or inbound["id"])))
    policy, parents = PolicyStore(cfg), ParentStore()
    for email in emails:
        results.append((policy.get(email) is not None and bool(parents.of_child(email)),
                        "user %s has a policy and a parent account" % email))
    state = panel.xray_state()
    results.append((state.get("state") == "running", "xray state: %s" % state.get("state")))
    if flag(cfg, "POLICY_BLOCK_PORN"):
        results.append(check_family_dns(cfg))
    if flag(cfg, "POLICY_GATE_ENABLED"):
        try:
            url = "http://127.0.0.1:%s/healthz" % cfg["POLICY_GATE_PORT"]
            with urllib.request.urlopen(url, timeout=3) as response:
                results.append((response.status == 200, "location gate answering on %s" % url))
        except OSError as error:
            # Only GPS places and the parent page need the gate; the porn filter works without it.
            results.append((True, "WARNING location gate not answering (%s): GPS places and "
                                  "the parent page are inactive" % error))
    return results


# --------------------------------------------------------------------------
# location gate
# --------------------------------------------------------------------------

def gate_base(cfg, email):
    return "http://%s:%s/v1/%s/%s" % (cfg["POLICY_GATE_VIRTUAL_IP"], cfg["POLICY_GATE_PORT"],
                                      urllib.parse.quote(email, safe="@"), gate_token(email))


def gate_urls(cfg, email, zones=()):
    base = gate_base(cfg, email)
    urls = {"status": base + "/status", "locate": base + "/locate?lat=LAT&lon=LON"}
    for zone in zones:
        urls[zone["id"] + " enter"] = "%s/%s/enter" % (base, zone["id"])
        urls[zone["id"] + " exit"] = "%s/%s/exit" % (base, zone["id"])
    return urls


def login_token():
    """Anti-forgery value for the (session-less) login form."""
    return hmac.new(gate_secret(), b"login-csrf", hashlib.sha256).hexdigest()


class ZoneState:
    """Which places each child is in right now (survives restarts).

    Entries come from the phone either by name (`enter`/`exit`, source "manual")
    or from a reported position matched against the child's places ("gps").
    """

    def __init__(self):
        self.path = STATE / "zone-state.json"
        self.lock = threading.Lock()

    def _load(self):
        try:
            raw = json.loads(self.path.read_text())
        except (OSError, ValueError):
            return {}
        return {user: {zone: (v if isinstance(v, dict) else {"ts": v, "src": "manual"})
                       for zone, v in zones.items()} for user, zones in raw.items()}

    def _save(self, data):
        _write_json(self.path, {user: z for user, z in data.items() if z})

    def set(self, email, zone, inside):
        with self.lock:
            data = self._load()
            zones = data.setdefault(email, {})
            if inside:
                zones[zone] = {"ts": int(time.time()), "src": "manual"}
            else:
                zones.pop(zone, None)
            self._save(data)
            return sorted(zones)

    def locate(self, email, places, lat, lon):
        """Match a reported position against `places`; returns the zone ids now inside."""
        with self.lock:
            data = self._load()
            zones = data.setdefault(email, {})
            for place in places:
                if place.get("lat") is None:
                    continue
                inside = distance_m(lat, lon, place["lat"], place["lon"]) <= place["radius"]
                if inside:
                    zones.setdefault(place["id"], {"src": "gps"})["ts"] = int(time.time())
                elif zones.get(place["id"], {}).get("src") == "gps":
                    del zones[place["id"]]
            self._save(data)
            return sorted(zones)

    def in_zones(self):
        with self.lock:
            return {user: sorted(z) for user, z in self._load().items() if z}

    def zones_of(self, email):
        return self.in_zones().get(email, [])

    def restricted_users(self):
        return sorted(self.in_zones())


class Syncer(threading.Thread):
    """Applies changes without blocking the request that caused them."""

    DEBOUNCE = 2.0  # lets the HTTP reply leave before Xray restarts

    def __init__(self, cfg):
        super().__init__(daemon=True)
        self.cfg = cfg
        self.wake = threading.Event()
        self.interval = max(15, int(cfg["POLICY_SYNC_SECONDS"]))

    def run(self):
        delay = 0
        while True:
            try:
                if sync(self.cfg):
                    log("policy applied; in a place now: %s" % (ZoneState().in_zones() or "nobody"))
                delay = self.interval  # also picks up new clients and dynamic-DNS changes
            except Exception as error:  # keep the gate alive; retry soon
                log("apply failed: %s" % error)
                delay = 30
            if self.wake.wait(timeout=delay):
                time.sleep(self.DEBOUNCE)
                self.wake.clear()


def make_handler(cfg, state, syncer, policy, parents):
    ui = webui.AdminUI(cfg, policy, parents, state, syncer, gate_base, login_token,
                        tuple(APP_DOMAINS))

    class Handler(http.server.BaseHTTPRequestHandler):
        server_version = "vpn-policy-gate"

        def log_message(self, fmt, *args):
            log("gate %s %s" % (self.address_string(), fmt % args))

        def reply(self, code, body):
            data = json.dumps(body).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def handle_request(self):
            split = urllib.parse.urlsplit(self.path)
            parts = [urllib.parse.unquote(p) for p in split.path.strip("/").split("/")]
            if parts[0] == "admin":
                return ui.handle(self)
            if parts == ["healthz"]:
                return self.reply(200, {"ok": True})
            if len(parts) not in (4, 5) or parts[0] != "v1":
                return self.reply(404, {"ok": False})
            email, token = parts[1], parts[2]
            if not EMAIL_RE.match(email) or not hmac.compare_digest(token, gate_token(email)):
                return self.reply(403, {"ok": False, "error": "bad token"})
            if len(parts) == 4 and parts[3] == "status":
                zones = state.zones_of(email)
                return self.reply(200, {"ok": True, "restricted": bool(zones), "zones": zones})
            if len(parts) == 4 and parts[3] == "locate":
                query = urllib.parse.parse_qs(split.query)
                try:
                    lat, lon = float(query["lat"][0]), float(query["lon"][0])
                    if not (-90 <= lat <= 90 and -180 <= lon <= 180):
                        raise ValueError
                except (KeyError, IndexError, ValueError):
                    return self.reply(400, {"ok": False, "error": "lat and lon are required"})
                child = policy.get(email)
                before = state.zones_of(email)
                zones = state.locate(email, child["zones"] if child else [], lat, lon)
                if zones != before:
                    syncer.wake.set()
                return self.reply(200, {"ok": True, "restricted": bool(zones), "zones": zones})
            if len(parts) == 5 and ZONE_RE.match(parts[3]) and parts[4] in ("enter", "exit"):
                zones = state.set(email, parts[3], parts[4] == "enter")
                syncer.wake.set()
                return self.reply(200, {"ok": True, "restricted": bool(zones), "zones": zones})
            return self.reply(404, {"ok": False})

        do_GET = do_POST = handle_request

    return Handler


def serve(cfg):
    state = ZoneState()
    syncer = Syncer(cfg)
    syncer.start()
    server = http.server.ThreadingHTTPServer(
        ("127.0.0.1", int(cfg["POLICY_GATE_PORT"])),
        make_handler(cfg, state, syncer, PolicyStore(cfg), ParentStore()))
    log("location gate listening on 127.0.0.1:%s" % cfg["POLICY_GATE_PORT"])
    server.serve_forever()


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)
    apply_cmd = sub.add_parser("apply", help="install/refresh the policy in 3X-UI")
    apply_cmd.add_argument("--force", action="store_true", help="save and restart even if unchanged")
    sub.add_parser("remove", help="strip the policy from the Xray template")
    sub.add_parser("verify", help="check the live panel, Xray, DNS filter and gate")
    sub.add_parser("dns-check", help="check that the family DNS resolver is reachable")
    sub.add_parser("status", help="show every child and where they are")
    urls_cmd = sub.add_parser("urls", help="print the phone URLs for a user")
    urls_cmd.add_argument("email", nargs="?")
    set_cmd = sub.add_parser("set", help="manually move a user into/out of a place")
    set_cmd.add_argument("email")
    set_cmd.add_argument("zone")
    set_cmd.add_argument("action", choices=("enter", "exit"))
    sites_cmd = sub.add_parser("sites", help="list, add or remove a user's blocked sites")
    sites_cmd.add_argument("action", choices=("list", "add", "remove"))
    sites_cmd.add_argument("child", nargs="?", help="the 3X-UI client email")
    sites_cmd.add_argument("site", nargs="?")
    sites_cmd.add_argument("--mode", choices=MODES, default="always",
                           help="always | in (blocked only in --zones) | except (open only in --zones)")
    sites_cmd.add_argument("--zones", default="", help="comma separated place ids, or * for any")
    parents_cmd = sub.add_parser("parents", help="list parent accounts or reset a password")
    parents_cmd.add_argument("action", choices=("list", "reset"))
    parents_cmd.add_argument("username", nargs="?")
    sub.add_parser("serve", help="run the location gate and parent page (127.0.0.1 only)")
    args = parser.parse_args(argv)
    cfg = load_config()
    state = ZoneState()
    policy, parents = PolicyStore(cfg), ParentStore()

    try:
        if args.command == "apply":
            log("Policy applied." if sync(cfg, force=args.force) else "Policy already up to date.")
        elif args.command == "remove":
            remove_policy(cfg)
            log("Policy removed.")
        elif args.command == "dns-check":
            if not flag(cfg, "POLICY_BLOCK_PORN"):
                log("porn filter is disabled; nothing to check")
                return 0
            ok, message = check_family_dns(cfg)
            log("%s %s" % ("OK  " if ok else "FAIL", message))
            return 0 if ok else 1
        elif args.command == "verify":
            results = verify(cfg)
            for ok, message in results:
                log("%s %s" % ("OK  " if ok else "FAIL", message))
            return 0 if all(ok for ok, _ in results) else 1
        elif args.command == "status":
            in_zones = state.in_zones()
            for email, child in policy.children().items():
                log("%s: places %s | in now: %s | parents: %s" % (
                    email, [z["id"] for z in child["zones"]] or "-", in_zones.get(email) or "-",
                    ", ".join(p["username"] for p in parents.of_child(email)) or "-"))
        elif args.command == "urls":
            email = args.email or cfg.get("CLIENT_EMAIL", "my-phone")
            child = policy.get(email) or {"zones": []}
            for name, url in gate_urls(cfg, email, child["zones"]).items():
                log("%-16s %s" % (name, url))
        elif args.command == "set":
            if not EMAIL_RE.match(args.email) or not ZONE_RE.match(args.zone):
                parser.error("invalid email or zone name")
            state.set(args.email, args.zone, args.action == "enter")
            sync(cfg)
            log("in a place now: %s" % (state.in_zones() or "nobody"))
        elif args.command == "sites":
            if args.action == "list":
                for email, child in policy.children().items():
                    if args.child in (None, email):
                        log("%s:" % email)
                        for s in child["sites"]:
                            log("  %-28s %-7s %s" % (s["site"], s["mode"], ",".join(s["zones"])))
            else:
                if not args.child or not args.site:
                    parser.error("usage: sites %s CHILD SITE [--mode M --zones a,b]" % args.action)
                if args.action == "add":
                    entry = policy.set_site(args.child, args.site, args.mode,
                                            [z for z in args.zones.split(",") if z])
                else:
                    entry = policy.remove_site(args.child, args.site)
                log("%s %s" % (entry, "saved" if args.action == "add" else "removed"))
                log("Applied to the VPN." if sync(cfg) else "Saved (VPN already matched).")
        elif args.command == "parents":
            if args.action == "list":
                for email in policy.children():
                    for parent in parents.of_child(email):
                        log("%-24s -> %s" % (parent["username"], email))
                if parents.credentials_path.exists():
                    log("\nAccounts still on their generated password (%s):" % parents.credentials_path)
                    log(parents.credentials_path.read_text().rstrip())
            else:
                if not args.username:
                    parser.error("usage: parents reset USERNAME")
                log("New password for %s: %s" % (args.username, parents.reset(args.username)))
        elif args.command == "serve":
            if not flag(cfg, "POLICY_GATE_ENABLED"):
                log("POLICY_GATE_ENABLED is off; nothing to serve")
                return 1
            serve(cfg)
    except (PanelError, UserError) as error:
        log("ERROR: %s" % error)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
