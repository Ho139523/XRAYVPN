import copy
import http.client
import http.server
import json
import socket
import sys
import tempfile
import threading
import unittest
import urllib.parse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "policy"))

import vpn_policy as vp  # noqa: E402
from i18n import UserError  # noqa: E402

# Default Xray template served by 3X-UI 3.8.5 / Xray 26.9.9.
BASE = {
    "api": {"tag": "api", "services": ["HandlerService", "LoggerService", "StatsService", "RoutingService"]},
    "inbounds": [{"listen": "127.0.0.1", "port": 62789, "protocol": "tunnel",
                  "settings": {"rewriteAddress": "127.0.0.1"}, "tag": "api"}],
    "log": {"access": "none", "dnsLog": False, "error": "", "loglevel": "warning", "maskAddress": ""},
    "outbounds": [
        {"protocol": "freedom", "tag": "direct", "settings": {"finalRules": [
            {"action": "block", "ip": ["geoip:private"]}, {"action": "allow"}]}},
        {"protocol": "blackhole", "tag": "blocked", "settings": {}},
    ],
    "routing": {"domainStrategy": "AsIs", "rules": [
        {"inboundTag": ["api"], "outboundTag": "api", "type": "field"},
        {"ip": ["geoip:private"], "outboundTag": "blocked", "type": "field"},
        {"outboundTag": "blocked", "protocol": ["bittorrent"], "type": "field"},
    ]},
    "stats": {},
}

HOME = {"id": "home", "name": "Home", "lat": 35.7, "lon": 51.4, "radius": 150, "networks": []}
LIB = {"id": "library", "name": "Library", "lat": 35.71, "lon": 51.41, "radius": 100,
       "networks": ["203.0.113.0/24"]}


def cfg(**overrides):
    values = dict(vp.DEFAULTS)
    values.update(overrides)
    return values


def child(sites=(), zones=()):
    return {"zones": list(zones), "sites": [dict(s, zones=s.get("zones", [])) for s in sites]}


def site(name, mode="always", zones=()):
    return {"site": name, "mode": mode, "zones": list(zones)}


def rules_of(template):
    return [r for r in template["routing"]["rules"] if r.get("ruleTag", "").startswith(vp.TAG)]


def tags(template):
    return [r["ruleTag"] for r in rules_of(template)]


def rule_named(template, name):
    return next(r for r in template["routing"]["rules"] if r.get("ruleTag") == vp.TAG + name)


def build(children=None, inside=None, nets=None, **overrides):
    return vp.build_template(BASE, cfg(**overrides), children, inside, nets)


class BuildTemplate(unittest.TestCase):
    def test_idempotent_and_reversible(self):
        kids = {"a": child([site("tiktok.com"), site("youtube", "in", ["*"])], [HOME])}
        once = vp.build_template(BASE, cfg(), kids, {"a": ["home"]}, {})
        twice = vp.build_template(once, cfg(), kids, {"a": ["home"]}, {})
        self.assertEqual(once, twice)
        self.assertEqual(vp.strip_managed(once), BASE)

    def test_does_not_mutate_input(self):
        snapshot = copy.deepcopy(BASE)
        build({"a": child([site("x.com")])})
        self.assertEqual(BASE, snapshot)

    def test_rules_sit_between_api_rule_and_panel_rules(self):
        rules = build({"a": child([site("x.com")])})["routing"]["rules"]
        self.assertEqual(rules[0]["outboundTag"], "api")
        self.assertEqual(rules[-2:], BASE["routing"]["rules"][1:])
        self.assertTrue(all(r["ruleTag"].startswith(vp.TAG) for r in rules[1:-2]))

    def test_default_outbound_stays_first(self):
        self.assertEqual(build()["outbounds"][0]["tag"], "direct")

    def test_dns_hijack_precedes_blocks_and_internal_lookups_bypass_it(self):
        order = tags(build())
        self.assertLess(order.index("vpnapp-dns-internal"), order.index("vpnapp-dns-hijack"))
        self.assertLess(order.index("vpnapp-dns-hijack"), order.index("vpnapp-block-porn"))

    def test_porn_and_null_ip_blocked(self):
        template = build()
        self.assertIn("geosite:category-porn", rule_named(template, "block-porn")["domain"])
        self.assertIn("0.0.0.0/32", rule_named(template, "block-null-ip")["ip"])
        self.assertEqual(template["routing"]["domainStrategy"], "IPIfNonMatch")
        self.assertEqual(template["dns"]["servers"], ["1.1.1.3", "1.0.0.3"])

    def test_doh_blocking_is_optional(self):
        off = tags(build(POLICY_BLOCK_DOH="false"))
        self.assertNotIn("vpnapp-block-doh-ip", off)
        self.assertIn("vpnapp-block-porn", off)

    def test_porn_filter_can_be_disabled(self):
        template = build(POLICY_BLOCK_PORN="false", POLICY_GATE_ENABLED="false")
        self.assertNotIn("dns", template)
        self.assertEqual(template["routing"]["domainStrategy"], "AsIs")
        self.assertEqual(tags(template), [])

    def test_allow_list_beats_porn_list_but_not_parents(self):
        kids = {"a": child([site("tiktok.com")])}
        order = tags(build(kids, POLICY_ALLOW_DOMAINS="example.org"))
        self.assertLess(order.index("vpnapp-allow"), order.index("vpnapp-block-porn"))
        self.assertLess(order.index("vpnapp-block-porn"), order.index("vpnapp-c0-always"))

    # ---- the three site modes

    def test_always_blocks_only_that_user(self):
        template = build({"a": child([site("TikTok.com".lower()), site("youtube")])})
        rule = rule_named(template, "c0-always")
        self.assertEqual(rule["user"], ["a"])
        self.assertIn("domain:tiktok.com", rule["domain"])
        self.assertIn("domain:youtube.com", rule["domain"])  # app name expands to its domains
        self.assertNotIn("source", rule)

    def test_each_child_gets_their_own_rules(self):
        template = build({"a": child([site("x.com")]), "b": child([site("y.com")])})
        self.assertEqual(rule_named(template, "c0-always")["user"], ["a"])
        self.assertEqual(rule_named(template, "c1-always")["user"], ["b"])
        self.assertEqual(rule_named(template, "c1-always")["domain"], ["domain:y.com"])

    def test_in_mode_applies_only_while_in_the_place(self):
        kids = {"a": child([site("youtube", "in", ["home"])], [HOME, LIB])}
        self.assertEqual(tags(build(kids, {})), tags(build()))  # nowhere: nothing extra
        inside = rule_named(build(kids, {"a": ["home"]}), "c0-in0-0")
        self.assertEqual(inside["user"], ["a"])
        self.assertNotIn("source", inside)
        self.assertEqual(tags(build(kids, {"a": ["library"]})), tags(build()))  # a different place

    def test_in_mode_with_wifi_network_matches_on_source_address(self):
        kids = {"a": child([site("youtube", "in", ["library"])], [HOME, LIB])}
        template = build(kids, {}, {"a": {"library": ["203.0.113.0/24"]}})
        rule = rule_named(template, "c0-in0-0")
        self.assertEqual((rule["user"], rule["source"]), (["a"], ["203.0.113.0/24"]))

    def test_any_place_wildcard(self):
        kids = {"a": child([site("youtube", "in", ["*"])], [HOME, LIB])}
        self.assertNotIn("vpnapp-c0-in0-0", tags(build(kids, {})))
        self.assertIn("vpnapp-c0-in0-0", tags(build(kids, {"a": ["some-unknown-place"]})))
        wifi = build(kids, {}, {"a": {"library": ["203.0.113.0/24"]}})
        self.assertEqual(rule_named(wifi, "c0-in0-0")["source"], ["203.0.113.0/24"])

    def test_except_mode_blocks_everywhere_but_the_listed_places(self):
        kids = {"a": child([site("instagram", "except", ["home"])], [HOME])}
        away = build(kids, {})
        self.assertEqual(rule_named(away, "c0-except")["user"], ["a"])
        self.assertNotIn("vpnapp-c0-open0-0", tags(away))
        at_home = build(kids, {"a": ["home"]})
        allow = rule_named(at_home, "c0-open0-0")
        self.assertEqual(allow["outboundTag"], "direct")
        self.assertEqual(allow["user"], ["a"])
        order = tags(at_home)
        self.assertLess(order.index("vpnapp-c0-open0-0"), order.index("vpnapp-c0-except"))

    def test_rule_order_always_then_in_then_open_then_except(self):
        kids = {"a": child([site("a.com"), site("b.com", "in", ["home"]),
                            site("c.com", "except", ["home"])], [HOME])}
        order = [t_ for t_ in tags(build(kids, {"a": ["home"]})) if "-c0-" in t_ or t_.endswith("c0-except")]
        self.assertEqual(order, ["vpnapp-c0-always", "vpnapp-c0-in0-0", "vpnapp-c0-open0-0", "vpnapp-c0-except"])

    def test_sites_with_same_places_share_a_rule(self):
        kids = {"a": child([site("a.com", "in", ["home"]), site("b.com", "in", ["home"])], [HOME])}
        rule = rule_named(build(kids, {"a": ["home"]}), "c0-in0-0")
        self.assertEqual(rule["domain"], ["domain:a.com", "domain:b.com"])

    def test_keyword_entries(self):
        rule = rule_named(build({"a": child([site("keyword:casino")])}), "c0-always")
        self.assertEqual(rule["domain"], ["keyword:casino"])

    # ---- gate and misc

    def test_gate_outbound_only_reaches_the_gate(self):
        template = build()
        gate = next(o for o in template["outbounds"] if o["tag"] == "vpnapp-gate")
        self.assertEqual(gate["settings"]["redirect"], "127.0.0.1:9099")
        self.assertEqual(gate["settings"]["finalRules"][0],
                         {"action": "allow", "ip": ["127.0.0.1"], "port": "9099"})
        self.assertEqual(gate["settings"]["finalRules"][-1], {"action": "block"})
        self.assertEqual(rule_named(template, "gate")["ip"], ["192.0.2.1"])
        self.assertEqual(template["routing"]["rules"][-2]["ip"], ["geoip:private"])

    def test_gate_can_be_disabled(self):
        template = build(POLICY_GATE_ENABLED="false")
        self.assertNotIn("vpnapp-gate", tags(template))
        self.assertNotIn("vpnapp-gate", [o["tag"] for o in template["outbounds"]])

    def test_admins_own_dns_section_is_replaced(self):
        custom = copy.deepcopy(BASE)
        custom["dns"] = {"servers": ["9.9.9.9"]}
        self.assertEqual(vp.build_template(custom, cfg())["dns"]["tag"], vp.TAG + "dns")
        self.assertEqual(vp.strip_managed(custom)["dns"], {"servers": ["9.9.9.9"]})


class Sandbox(unittest.TestCase):
    """A throwaway state directory."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        original = vp.STATE
        vp.STATE = Path(self.tmp.name)
        self.addCleanup(setattr, vp, "STATE", original)
        self.dir = Path(self.tmp.name)


class Entries(unittest.TestCase):
    def test_normalizes_what_parents_paste(self):
        for typed, stored in (("TikTok.com", "tiktok.com"), ("https://www.tiktok.com/@x?y=1", "tiktok.com"),
                              ("  m.example.co.uk ", "m.example.co.uk"), ("YouTube", "youtube"),
                              ("keyword:Casino", "keyword:casino"), ("bücher.example", "xn--bcher-kva.example")):
            self.assertEqual(vp.normalize_entry(typed), stored, typed)

    def test_rejects_junk_with_a_translatable_error(self):
        for junk in ("", "localhost", "1.2.3.4", "geosite:category-ads", "domain:x.com", "a b.com",
                     "keyword:x", "x.com;rm -rf", '"><script>.com'):
            with self.assertRaises(UserError, msg=junk) as ctx:
                vp.normalize_entry(junk)
            self.assertTrue(ctx.exception.key.startswith("err_"))

    def test_networks(self):
        self.assertEqual(vp.parse_networks("203.0.113.7, Home.Example.com\n10.0.0.0/8"),
                         ["203.0.113.7", "home.example.com", "10.0.0.0/8"])
        self.assertEqual(vp.parse_networks("  "), [])
        with self.assertRaises(UserError):
            vp.parse_networks("not a host")

    def test_resolve_networks(self):
        got = vp.resolve_networks(["203.0.113.7", "198.51.100.9/24", "localhost", "nope.invalid"])
        self.assertIn("203.0.113.7/32", got)
        self.assertIn("198.51.100.0/24", got)
        self.assertIn("127.0.0.1/32", got)
        self.assertNotIn("nope.invalid", " ".join(got))

    def test_distance(self):
        self.assertAlmostEqual(vp.distance_m(35.0, 51.0, 36.0, 51.0), 111195, delta=200)
        self.assertEqual(vp.distance_m(35.7, 51.4, 35.7, 51.4), 0)
        self.assertLess(vp.distance_m(35.7, 51.4, 35.7005, 51.4), 60)

    def test_env_file_parsing(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "x.env"
            path.write_text('# c\nA=1\nB="two words"  # trailing\nC=\nnot-a-pair\n')
            self.assertEqual(vp.read_env_file(path), {"A": "1", "B": "two words", "C": ""})

    def test_dns_lookup_parses_compressed_answers(self):
        def serve(sock):
            query, addr = sock.recvfrom(512)
            sock.sendto(query[:2] + b"\x81\x80" + query[4:6] + b"\x00\x01\x00\x00\x00\x00" + query[12:]
                        + b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x00\x00\x00\x00", addr)

        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.bind(("127.0.0.1", 0))
            threading.Thread(target=serve, args=(sock,), daemon=True).start()
            self.assertEqual(vp.dns_lookup("127.0.0.1", "pornhub.com", port=sock.getsockname()[1]),
                             (0, ["0.0.0.0"]))


class Policy(Sandbox):
    def store(self, **overrides):
        return vp.PolicyStore(cfg(**overrides))

    def test_new_child_gets_the_seed_policy_once(self):
        store = self.store()
        self.assertEqual(store.ensure(["Us"]), ["Us"])
        self.assertEqual(store.get("Us")["sites"],
                         [site("youtube", "in", ["*"]), site("instagram", "in", ["*"])])
        store.remove_site("Us", "youtube")
        self.assertEqual(store.ensure(["Us"]), [])  # existing policy is never reseeded
        self.assertEqual([s["site"] for s in store.get("Us")["sites"]], ["instagram"])
        self.assertEqual(oct((self.dir / "policy.json").stat().st_mode & 0o777), "0o600")

    def test_network_env_seeds_a_place(self):
        store = self.store(POLICY_ZONE_SOURCE_IPS="203.0.113.7")
        store.ensure(["Us"])
        self.assertEqual(store.get("Us")["zones"][0]["networks"], ["203.0.113.7"])

    def test_unknown_seed_app_is_a_config_error(self):
        with self.assertRaises(vp.PanelError):
            self.store(POLICY_ZONE_APPS="youtube tiktokk").ensure(["Us"])

    def test_old_global_lists_are_migrated_once(self):
        (self.dir / "blocklists.json").write_text(json.dumps({"always": ["tiktok.com"], "geo": ["youtube"]}))
        store = self.store()
        store.ensure(["Us"])
        self.assertEqual(store.get("Us")["sites"], [site("tiktok.com"), site("youtube", "in", ["*"])])
        self.assertFalse((self.dir / "blocklists.json").exists())
        self.assertTrue((self.dir / "blocklists.json.migrated").exists())
        store.ensure(["Us", "Kid2"])  # a later child gets the plain seed, not the old lists
        self.assertEqual([s["site"] for s in store.get("Kid2")["sites"]], ["youtube", "instagram"])

    def test_legacy_file_untouched_while_there_are_no_clients(self):
        (self.dir / "blocklists.json").write_text(json.dumps({"always": ["tiktok.com"], "geo": []}))
        self.assertEqual(self.store().ensure([]), [])
        self.assertTrue((self.dir / "blocklists.json").exists())

    def test_set_site_replaces_and_keeps_only_known_places(self):
        store = self.store()
        store.ensure(["Us"])
        store.save_zone("Us", "", "Home", 35.7, 51.4, 150)
        store.set_site("Us", "https://www.tiktok.com/x", "in", ["home", "ghost", "*"])
        self.assertEqual(store.get("Us")["sites"][-1], site("tiktok.com", "in", ["home", "*"]))
        store.set_site("Us", "tiktok.com", "always", ["home"])
        entries = [s for s in store.get("Us")["sites"] if s["site"] == "tiktok.com"]
        self.assertEqual(entries, [site("tiktok.com", "always", [])])
        with self.assertRaises(UserError):
            store.set_site("Us", "x.com", "sometimes")
        with self.assertRaises(UserError):
            store.set_site("Nobody", "x.com", "always")

    def test_site_limit(self):
        store = self.store(POLICY_ZONE_APPS="")
        store.ensure(["Us"])
        for i in range(vp.MAX_SITES):
            store.set_site("Us", "site%d.com" % i, "always")
        with self.assertRaises(UserError):
            store.set_site("Us", "one-too-many.com", "always")

    def test_zones(self):
        store = self.store()
        store.ensure(["Us"])
        home = store.save_zone("Us", "", "  Home  ", "35.7", "51.4", "200")
        self.assertEqual((home["id"], home["radius"]), ("home", 200))
        self.assertEqual(store.save_zone("Us", "", "Home", 35.8, 51.5, 100)["id"], "home-2")
        self.assertEqual(store.save_zone("Us", "", "خانه", 35.9, 51.6, 100)["id"], "zone")
        wifi = store.save_zone("Us", "", "Cafe", "", "", "150", "203.0.113.5")  # network-only place
        self.assertIsNone(wifi["lat"])
        edited = store.save_zone("Us", "home", "Home sweet", 35.71, 51.41, 300)
        self.assertEqual(edited["id"], "home")
        self.assertEqual([z["name"] for z in store.get("Us")["zones"]][0], "Home sweet")

    def test_zone_validation(self):
        store = self.store()
        store.ensure(["Us"])
        cases = [
            (("", "", "", "", 150, ""), "err_zone_name"),
            (("x", "", "", "", 150, ""), "err_zone_position"),
            (("x", "95", "51", "", 150, ""), "err_zone_coords"),
            (("x", "35", "181", "", 150, ""), "err_zone_coords"),
            (("x", "abc", "51", "", 150, ""), "err_zone_coords"),
            (("x", "35", "51", "", 5, ""), "err_zone_radius"),
            (("x", "35", "51", "", 999999, ""), "err_zone_radius"),
            (("x", "35", "51", "", 150, "not a host"), "err_networks"),
        ]
        for (name, lat, lon, _, radius, networks), key in cases:
            with self.assertRaises(UserError, msg=key) as ctx:
                store.save_zone("Us", "", name, lat, lon, radius, networks)
            self.assertEqual(ctx.exception.key, key)
        with self.assertRaises(UserError):
            store.save_zone("Us", "missing", "x", 35, 51, 150)

    def test_removing_a_place_removes_it_from_sites(self):
        store = self.store()
        store.ensure(["Us"])
        store.save_zone("Us", "", "Home", 35.7, 51.4, 150)
        store.set_site("Us", "x.com", "in", ["home", "*"])
        store.remove_zone("Us", "home")
        self.assertEqual(store.get("Us")["zones"], [])
        self.assertEqual(store.get("Us")["sites"][-1]["zones"], ["*"])

    def test_corrupt_file_is_an_error_not_an_empty_policy(self):
        (self.dir / "policy.json").write_text("{nope")
        with self.assertRaises(vp.PanelError):
            self.store().children()


class Zones(Sandbox):
    def test_manual_enter_exit(self):
        state = vp.ZoneState()
        self.assertEqual(state.set("Us", "home", True), ["home"])
        self.assertEqual(state.in_zones(), {"Us": ["home"]})
        self.assertEqual(state.set("Us", "home", False), [])
        self.assertEqual(state.in_zones(), {})

    def test_reported_position_enters_and_leaves_places(self):
        state = vp.ZoneState()
        places = [HOME, LIB, {"id": "wifi", "name": "W", "lat": None, "lon": None, "radius": 0, "networks": ["1.2.3.4"]}]
        self.assertEqual(state.locate("Us", places, 35.7, 51.4), ["home"])
        self.assertEqual(state.locate("Us", places, 35.7003, 51.4), ["home"])      # 33 m away, still inside
        self.assertEqual(state.locate("Us", places, 35.71, 51.41), ["library"])    # moved to the library
        self.assertEqual(state.locate("Us", places, 40.0, 50.0), [])               # far away
        self.assertEqual(state.in_zones(), {})

    def test_position_reports_never_undo_a_manual_zone(self):
        state = vp.ZoneState()
        state.set("Us", "home", True)
        self.assertEqual(state.locate("Us", [HOME], 40.0, 50.0), ["home"])
        self.assertEqual(state.set("Us", "home", False), [])

    def test_old_state_format_is_read(self):
        (self.dir / "zone-state.json").write_text(json.dumps({"Us": {"home": 1790000000}}))
        self.assertEqual(vp.ZoneState().in_zones(), {"Us": ["home"]})

    def test_file_permissions(self):
        vp.ZoneState().set("Us", "home", True)
        self.assertEqual(oct((self.dir / "zone-state.json").stat().st_mode & 0o777), "0o600")


class Parents(Sandbox):
    def test_every_child_gets_a_parent_with_a_generated_password(self):
        store = vp.ParentStore()
        created = store.ensure_for(["Us", "Kid Two"])
        self.assertEqual([c[:2] for c in created], [("Us", "Us-parent"), ("Kid Two", "Kid-Two-parent")])
        self.assertEqual(store.ensure_for(["Us", "Kid Two"]), [])
        child, username, password = created[0]
        self.assertEqual(store.authenticate("us-PARENT", password), {"username": "Us-parent", "child": "Us"})
        self.assertIsNone(store.authenticate("Us-parent", "wrong"))
        self.assertIsNone(store.authenticate("nobody", password))
        self.assertIn("Us\tUs-parent\t%s" % password, store.credentials_path.read_text())
        self.assertEqual(oct(store.credentials_path.stat().st_mode & 0o777), "0o600")
        self.assertNotIn(password, (self.dir / "parents.json").read_text())  # only a hash is kept

    def test_a_child_added_later_gets_a_parent(self):
        store = vp.ParentStore()
        store.ensure_for(["Us"])
        self.assertEqual([c[0] for c in store.ensure_for(["Us", "New"])], ["New"])

    def test_old_single_password_is_not_guessed_onto_one_of_several_children(self):
        salt = b"\x01" * 16
        (self.dir / "parent-auth.json").write_text(json.dumps(
            {"salt": salt.hex(), "hash": vp.ParentStore._digest("old password", salt).hex()}))
        store = vp.ParentStore()
        self.assertEqual(len(store.ensure_for(["Us", "Kid"])), 2)  # both get generated accounts
        self.assertIsNone(store.authenticate("parent", "old password"))
        self.assertTrue((self.dir / "parent-auth.json").exists())  # left alone, nothing lost

    def test_old_single_password_becomes_the_only_childs_parent(self):
        salt = b"\x01" * 16
        (self.dir / "parent-auth.json").write_text(json.dumps(
            {"salt": salt.hex(), "hash": vp.ParentStore._digest("old password", salt).hex()}))
        store = vp.ParentStore()
        self.assertEqual(store.ensure_for(["Us"]), [])  # no second, generated account
        self.assertEqual(store.authenticate("parent", "old password")["child"], "Us")
        self.assertTrue((self.dir / "parent-auth.json.migrated").exists())

    def test_add_rename_change_password_remove(self):
        store = vp.ParentStore()
        store.ensure_for(["Us"])
        store.add("Us", "mom", "s3cret-pass")
        self.assertEqual([p["username"] for p in store.of_child("Us")], ["mom", "Us-parent"])
        self.assertEqual(store.update("mom", "Mother"), "Mother")
        self.assertIsNone(store.get("mom"))
        self.assertIsNotNone(store.authenticate("mother", "s3cret-pass"))
        store.update("Mother", new_password="another-pass")
        self.assertIsNone(store.authenticate("Mother", "s3cret-pass"))
        self.assertIsNotNone(store.authenticate("Mother", "another-pass"))
        store.remove("Mother")
        self.assertIsNone(store.get("Mother"))

    def test_validation(self):
        store = vp.ParentStore()
        store.ensure_for(["Us"])
        for args, key in ((("Us", "ab", "longenough1"), "err_username"),
                          (("Us", "bad name", "longenough1"), "err_username"),
                          (("Us", "dad", "short"), "err_password_short"),
                          (("Us", "US-PARENT", "longenough1"), "err_username_taken")):
            with self.assertRaises(UserError) as ctx:
                store.add(*args)
            self.assertEqual(ctx.exception.key, key)
        store.add("Us", "dad", "longenough1")
        with self.assertRaises(UserError) as ctx:
            store.update("dad", "US-parent")
        self.assertEqual(ctx.exception.key, "err_username_taken")
        with self.assertRaises(UserError):
            store.update("dad")

    def test_last_parent_cannot_be_removed(self):
        store = vp.ParentStore()
        store.ensure_for(["Us"])
        with self.assertRaises(UserError) as ctx:
            store.remove("Us-parent")
        self.assertEqual(ctx.exception.key, "err_last_parent")

    def test_credentials_file_only_lists_generated_passwords(self):
        store = vp.ParentStore()
        _, username, _ = store.ensure_for(["Us"])[0]
        store.add("Us", "dad", "longenough1")
        store.update(username, new_password="mine-now-1")
        self.assertNotIn("Us-parent", store.credentials_path.read_text())
        password = store.reset("dad")
        self.assertIn("dad\t%s" % password, store.credentials_path.read_text())


class FakePanel(Sandbox):
    """A stand-in 3X-UI panel: enough of the API for sync()/apply_policy()."""

    def setUp(self):
        super().setUp()
        outer = self
        self.emails = ["Us"]
        self.template = copy.deepcopy(BASE)
        self.saved = []
        self.crash_marker = None   # Xray "fails to start" while this text is in the template
        self.clients_endpoint = True

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def send(self, obj, code=200):
                data = (obj if isinstance(obj, str) else json.dumps(obj)).encode()
                self.send_response(code)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):
                if self.path == "/":
                    return self.send('<meta name="csrf-token" content="tok">')
                if self.path == "/panel/api/clients/list":
                    if not outer.clients_endpoint:
                        return self.send("", 404)
                    return self.send({"success": True, "obj": [{"email": e} for e in outer.emails]})
                if self.path == "/panel/api/inbounds/list":
                    settings = json.dumps({"clients": [{"email": e} for e in outer.emails]})
                    return self.send({"success": True, "obj": [
                        {"id": 1, "remark": "in", "settings": settings,
                         "sniffing": {"enabled": True, "destOverride": ["http", "tls"]}}]})
                if self.path == "/panel/api/server/status":
                    crashed = outer.crash_marker and outer.crash_marker in json.dumps(outer.template)
                    return self.send({"success": True, "obj": {"xray": {
                        "state": "error" if crashed else "running", "errorMsg": "boom"}}})
                self.send("", 404)

            def do_POST(self):
                body = self.rfile.read(int(self.headers.get("Content-Length") or 0)).decode()
                if self.path == "/login":
                    return self.send({"success": True})
                if self.path == "/panel/api/xray/":
                    return self.send({"success": True, "obj": json.dumps(
                        {"xraySetting": outer.template, "outboundTestUrl": ""})})
                if self.path == "/panel/api/xray/update":
                    outer.template = json.loads(urllib.parse.parse_qs(body)["xraySetting"][0])
                    outer.saved.append(outer.template)
                    return self.send({"success": True})
                if self.path == "/panel/api/server/restartXrayService":
                    return self.send({"success": True})
                self.send("", 404)

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.cfg = cfg(XUI_PANEL_PORT=str(self.server.server_address[1]), PANEL_USERNAME="a",
                       PANEL_PASSWORD="b", POLICY_BLOCK_PORN="false")
        self.real_restart = vp.Panel.restart_xray
        # skip the 5 s "stays up" wait except in the test that is about it
        vp.Panel.restart_xray = lambda panel, **kw: panel.call("POST", "/panel/api/server/restartXrayService")
        self.addCleanup(setattr, vp.Panel, "restart_xray", self.real_restart)

    def test_new_3xui_users_get_a_policy_and_a_parent_automatically(self):
        self.assertTrue(vp.sync(self.cfg))
        self.assertEqual(list(vp.PolicyStore(self.cfg).children()), ["Us"])
        self.assertEqual([p["username"] for p in vp.ParentStore().of_child("Us")], ["Us-parent"])
        self.assertIn("vpnapp-gate", [r.get("ruleTag") for r in self.template["routing"]["rules"]])
        self.assertFalse(vp.sync(self.cfg))                     # nothing changed: no restart, no rewrite
        self.emails.append("New Kid")                           # the admin creates a user in 3X-UI
        vp.sync(self.cfg)
        self.assertEqual([p["username"] for p in vp.ParentStore().of_child("New Kid")], ["New-Kid-parent"])
        self.assertIn("New Kid\t", vp.ParentStore().credentials_path.read_text())

    def test_zone_changes_reach_the_xray_template(self):
        vp.sync(self.cfg)
        store = vp.PolicyStore(self.cfg)
        store.save_zone("Us", "", "Home", 35.7, 51.4, 150)
        store.set_site("Us", "example.net", "except", ["home"])
        vp.sync(self.cfg)
        self.assertEqual(rule_named(self.template, "c0-except")["user"], ["Us"])
        vp.ZoneState().set("Us", "home", True)
        vp.sync(self.cfg)
        self.assertEqual(rule_named(self.template, "c0-open0-0")["outboundTag"], "direct")

    def test_older_panels_without_the_clients_api(self):
        self.clients_endpoint = False
        panel = vp.Panel(self.cfg)
        panel.login()
        self.assertEqual(panel.client_emails(), ["Us"])

    def test_policy_the_panel_rejects_is_rolled_back(self):
        vp.sync(self.cfg)
        good = copy.deepcopy(self.template)
        vp.PolicyStore(self.cfg).set_site("Us", "example.net", "always")
        self.crash_marker = "example.net"
        vp.Panel.restart_xray = self.real_restart
        with self.assertRaises(vp.PanelError) as ctx:
            vp.sync(self.cfg)
        self.assertIn("previous config restored", str(ctx.exception))
        self.assertEqual(self.template, good)


class Cli(Sandbox):
    def test_dns_check_reports_through_the_exit_code(self):
        original = vp.check_family_dns
        self.addCleanup(setattr, vp, "check_family_dns", original)
        vp.check_family_dns = lambda cfg: (True, "fine")
        self.assertEqual(vp.main(["dns-check"]), 0)
        vp.check_family_dns = lambda cfg: (False, "unreachable")
        self.assertEqual(vp.main(["dns-check"]), 1)

    def test_dns_check_is_skipped_when_the_filter_is_off(self):
        import os
        original = vp.check_family_dns
        self.addCleanup(setattr, vp, "check_family_dns", original)
        os.environ["POLICY_BLOCK_PORN"] = "false"
        self.addCleanup(os.environ.pop, "POLICY_BLOCK_PORN", None)
        vp.check_family_dns = lambda cfg: self.fail("must not be called")
        self.assertEqual(vp.main(["dns-check"]), 0)


class Client:
    """Tiny HTTP client that keeps cookies and never follows redirects."""

    def __init__(self, port):
        self.port, self.cookies = port, {}

    def request(self, method, path, form=None, headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        body = urllib.parse.urlencode(form, doseq=True) if form is not None else None
        head = dict(headers or {})
        if self.cookies:
            head["Cookie"] = "; ".join("%s=%s" % kv for kv in self.cookies.items())
        if body is not None:
            head["Content-Type"] = "application/x-www-form-urlencoded"
        conn.request(method, path, body, head)
        response = conn.getresponse()
        text = response.read().decode("utf-8", errors="replace")
        for value in response.getheaders():
            if value[0].lower() == "set-cookie":
                name, _, rest = value[1].partition("=")
                val = rest.split(";")[0]
                if val:
                    self.cookies[name] = val
                else:
                    self.cookies.pop(name, None)
        conn.close()
        return response.status, text, dict(response.getheaders())

    def get(self, path, **kw):
        return self.request("GET", path, **kw)

    def post(self, path, form, **kw):
        return self.request("POST", path, form, **kw)


class Gate(Sandbox):
    def setUp(self):
        super().setUp()
        self.state = vp.ZoneState()
        self.policy = vp.PolicyStore(cfg())
        self.parents = vp.ParentStore()
        self.policy.ensure(["Us", "Kid"])
        self.policy.save_zone("Us", "", "Home", 35.7, 51.4, 150)
        self.creds = {c[0]: (c[1], c[2]) for c in self.parents.ensure_for(["Us", "Kid"])}

        class Syncer:
            wake = threading.Event()

        self.syncer = Syncer()
        handler = vp.make_handler(cfg(), self.state, self.syncer, self.policy, self.parents)
        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.port = self.server.server_address[1]
        self.anon = Client(self.port)

    def api(self, email, tail):
        status, text, _ = self.anon.get("/v1/%s/%s/%s" % (email, vp.gate_token(email), tail))
        return status, json.loads(text)

    def login(self, child="Us", password=None, username=None):
        client = Client(self.port)
        user, pw = self.creds[child]
        status, text, _ = client.get("/admin/login")
        token = text.split('name="csrf" value="')[1].split('"')[0]
        result = client.post("/admin/login", {"csrf": token, "username": username or user,
                                              "password": password or pw})
        return client, result

    def csrf(self, client):
        return client.get("/admin")[1].split('name="csrf" value="')[1].split('"')[0]

    # ---- phone-facing gate

    def test_enter_exit_cycle_and_overlapping_places(self):
        self.assertEqual(self.api("Us", "home/enter")[1]["zones"], ["home"])
        self.assertTrue(self.syncer.wake.is_set())
        self.api("Us", "library/enter")
        self.assertTrue(self.api("Us", "home/exit")[1]["restricted"])
        self.assertFalse(self.api("Us", "library/exit")[1]["restricted"])

    def test_locate_reports_matched_against_the_childs_places(self):
        self.assertEqual(self.api("Us", "locate?lat=35.7&lon=51.4")[1]["zones"], ["home"])
        self.assertEqual(self.state.in_zones(), {"Us": ["home"]})
        self.syncer.wake.clear()
        self.api("Us", "locate?lat=35.7&lon=51.4")
        self.assertFalse(self.syncer.wake.is_set())  # unchanged: no needless re-apply
        self.assertEqual(self.api("Us", "locate?lat=10&lon=10")[1], {"ok": True, "restricted": False, "zones": []})
        self.assertTrue(self.syncer.wake.is_set())

    def test_locate_needs_valid_coordinates(self):
        for tail in ("locate", "locate?lat=1", "locate?lat=abc&lon=1", "locate?lat=91&lon=1", "locate?lat=1&lon=181"):
            self.assertEqual(self.api("Us", tail)[0], 400, tail)

    def test_locate_for_someone_else_uses_their_own_places(self):
        self.assertEqual(self.api("Kid", "locate?lat=35.7&lon=51.4")[1]["zones"], [])  # Kid has no Home

    def test_token_is_per_user(self):
        self.assertEqual(self.anon.get("/v1/Us/%s/status" % vp.gate_token("Kid"))[0], 403)
        self.assertEqual(self.anon.get("/v1/Us/deadbeef/home/enter")[0], 403)
        self.assertEqual(self.state.in_zones(), {})

    def test_rejects_malformed_requests(self):
        token = vp.gate_token("Us")
        for path in ("/", "/v1", "/v1/Us/%s/ho%%20me/enter" % token, "/v1/Us/%s/home/dance" % token,
                     "/v1/%s/x/status" % ("a" * 70)):
            self.assertIn(self.anon.get(path)[0], (403, 404), path)

    def test_healthz(self):
        self.assertEqual(self.anon.get("/healthz")[0], 200)

    # ---- parent web page

    def test_panel_needs_login(self):
        status, _, headers = self.anon.get("/admin")
        self.assertEqual((status, headers["Location"]), (303, "/admin/login"))
        self.assertEqual(self.anon.post("/admin/site/add", {"site": "x.com"})[0], 303)

    def test_login_shows_only_your_child_and_sets_a_strict_cookie(self):
        client, (status, _, headers) = self.login("Us")
        self.assertEqual((status, headers["Location"]), (303, "/admin"))
        self.assertIn("HttpOnly", headers["Set-Cookie"])
        self.assertIn("SameSite=Strict", headers["Set-Cookie"])
        page = client.get("/admin")[1]
        self.assertIn("Us", page)
        self.assertIn("خانواده", page)  # Persian by default
        self.assertIn('dir="rtl"', page)
        self.assertNotIn("Kid-parent", page)

    def test_language_switch(self):
        client, _ = self.login("Us")
        client.get("/admin/lang/en")
        page = client.get("/admin")[1]
        self.assertIn('dir="ltr"', page)
        self.assertIn("Blocked sites", page)

    def test_wrong_password_and_lockout(self):
        self.assertEqual(self.login("Us", password="wrong-password")[1][0], 401)
        for _ in range(vp.webui.LOCKOUT_FAILURES - 1):
            self.login("Us", password="wrong-password")
        self.assertEqual(self.login("Us")[1][0], 429)         # even the right password while locked
        self.assertEqual(self.login("Kid")[1][0], 303)        # another account is unaffected

    def test_browsing_without_credentials_never_locks(self):
        for _ in range(vp.webui.LOCKOUT_FAILURES + 3):
            self.assertEqual(self.anon.get("/admin/login")[0], 200)
        self.assertEqual(self.login("Us")[1][0], 303)

    def test_login_form_needs_its_token(self):
        user, pw = self.creds["Us"]
        self.assertEqual(self.anon.post("/admin/login", {"csrf": "forged", "username": user, "password": pw})[0], 401)

    def test_forms_need_the_session_token(self):
        client, _ = self.login("Us")
        client.post("/admin/site/add", {"csrf": "forged", "site": "x.com", "mode": "always"})
        self.assertNotIn("x.com", [s["site"] for s in self.policy.get("Us")["sites"]])
        self.assertIn("csrf", client.get("/admin")[1].lower())

    def test_parent_edits_sites_in_all_three_modes(self):
        client, _ = self.login("Us")
        token = self.csrf(client)
        for form in ({"site": "https://www.tiktok.com/@x", "mode": "always"},
                     {"site": "youtube", "mode": "in", "zones": ["home"]},
                     {"site": "instagram", "mode": "except", "zones": ["home"]}):
            self.assertEqual(client.post("/admin/site/add", dict(form, csrf=token))[0], 303)
        sites = {s["site"]: s for s in self.policy.get("Us")["sites"]}
        self.assertEqual(sites["tiktok.com"]["mode"], "always")
        self.assertEqual((sites["youtube"]["mode"], sites["youtube"]["zones"]), ("in", ["home"]))
        self.assertEqual((sites["instagram"]["mode"], sites["instagram"]["zones"]), ("except", ["home"]))
        self.assertTrue(self.syncer.wake.is_set())
        client.post("/admin/site/remove", {"csrf": token, "site": "tiktok.com"})
        self.assertNotIn("tiktok.com", [s["site"] for s in self.policy.get("Us")["sites"]])
        page = client.get("/admin")[1]
        self.assertIn("badge in", page)
        self.assertIn("badge except", page)

    def test_bad_site_shows_a_persian_error_and_changes_nothing(self):
        client, _ = self.login("Us")
        before = self.policy.get("Us")
        client.post("/admin/site/add", {"csrf": self.csrf(client), "site": "not a site", "mode": "always"})
        self.assertEqual(self.policy.get("Us"), before)
        self.assertIn("معتبر نیست", client.get("/admin")[1])

    def test_parent_saves_a_place_from_the_map(self):
        client, _ = self.login("Kid")
        token = self.csrf(client)
        client.post("/admin/zone/save", {"csrf": token, "id": "", "name": "Library", "lat": "35.71",
                                         "lon": "51.41", "radius": "120", "networks": "203.0.113.9"})
        zone = self.policy.get("Kid")["zones"][0]
        self.assertEqual((zone["id"], zone["radius"], zone["networks"]), ("library", 120, ["203.0.113.9"]))
        client.post("/admin/zone/save", {"csrf": token, "id": "", "name": "Nowhere", "lat": "", "lon": "",
                                         "radius": "150", "networks": ""})
        self.assertEqual(len(self.policy.get("Kid")["zones"]), 1)  # rejected: no position at all
        client.post("/admin/zone/remove", {"csrf": token, "id": "library"})
        self.assertEqual(self.policy.get("Kid")["zones"], [])

    def test_parents_cannot_touch_other_childrens_settings(self):
        client, _ = self.login("Kid")
        token = self.csrf(client)
        client.post("/admin/site/add", {"csrf": token, "site": "kid-only.com", "mode": "always"})
        self.assertNotIn("kid-only.com", [s["site"] for s in self.policy.get("Us")["sites"]])
        us_parent = self.creds["Us"][0]
        client.post("/admin/parent/update", {"csrf": token, "username": us_parent, "new_password": "hijacked-pw1"})
        self.assertIsNone(self.parents.authenticate(us_parent, "hijacked-pw1"))
        client.post("/admin/parent/remove", {"csrf": token, "username": us_parent})
        self.assertIsNotNone(self.parents.get(us_parent))

    def test_managing_parents(self):
        client, _ = self.login("Us")
        token = self.csrf(client)
        me = self.creds["Us"][0]
        client.post("/admin/parent/add", {"csrf": token, "username": "mom", "password": "mom-password-1"})
        self.assertIsNotNone(self.parents.authenticate("mom", "mom-password-1"))
        # change another parent's username and password without knowing hers
        client.post("/admin/parent/update", {"csrf": token, "username": "mom", "new_username": "Mother",
                                             "new_password": "new-password-2"})
        self.assertIsNotNone(self.parents.authenticate("Mother", "new-password-2"))
        # own password needs the current one
        client.post("/admin/parent/update", {"csrf": token, "username": me, "new_password": "my-new-pass1",
                                             "current": "wrong"})
        self.assertIsNone(self.parents.authenticate(me, "my-new-pass1"))
        client.post("/admin/parent/update", {"csrf": token, "username": me, "new_password": "my-new-pass1",
                                             "current": self.creds["Us"][1]})
        self.assertIsNotNone(self.parents.authenticate(me, "my-new-pass1"))
        # rename yourself: the session keeps working under the new name
        client.post("/admin/parent/update", {"csrf": token, "username": me, "new_username": "dad"})
        self.assertIn("dad", client.get("/admin")[1])
        client.post("/admin/parent/remove", {"csrf": token, "username": "dad"})   # cannot remove yourself
        self.assertIsNotNone(self.parents.get("dad"))
        client.post("/admin/parent/remove", {"csrf": token, "username": "Mother"})
        self.assertIsNone(self.parents.get("Mother"))

    def test_garbage_content_length_is_not_a_server_error(self):
        client, _ = self.login("Us")
        status, _, _ = client.request("POST", "/admin/site/add", None,
                                      {"Content-Length": "abc", "Content-Type": "application/x-www-form-urlencoded"})
        self.assertEqual(status, 303)  # treated as an empty form: rejected by the csrf check, redirected

    def test_logout_ends_the_session(self):
        client, _ = self.login("Us")
        client.post("/admin/logout", {"csrf": self.csrf(client)})
        self.assertEqual(client.get("/admin")[0], 303)

    def test_output_is_escaped(self):
        self.policy.save_zone("Us", "", "<img src=x onerror=alert(1)>", 35.7, 51.4, 100)
        client, _ = self.login("Us")
        page = client.get("/admin")[1]
        self.assertNotIn("<img src=x", page)
        self.assertIn("&lt;img src=x", page)
        payload = json.loads(page.split('id="data">')[1].split("</script>")[0].replace("\\u003c", "<"))
        self.assertEqual(payload["zones"][-1]["name"], "<img src=x onerror=alert(1)>")

    def test_security_headers_and_no_inline_script(self):
        client, _ = self.login("Us")
        status, page, headers = client.get("/admin")
        self.assertIn("script-src 'self'", headers["Content-Security-Policy"])
        self.assertEqual(headers["X-Frame-Options"], "DENY")
        self.assertNotRegex(page, r"<script(?![^>]*(src=|type=\"application/json\"))")

    def test_phone_setup_lists_this_childs_urls(self):
        client, _ = self.login("Us")
        page = client.get("/admin")[1]
        self.assertIn(vp.gate_base(cfg(), "Us") + "/home/enter", page)
        self.assertIn(vp.gate_base(cfg(), "Us") + "/locate?lat=LAT", page)
        self.assertNotIn(vp.gate_token("Kid"), page)

    def test_static_files(self):
        for path, kind in (("/admin/static/admin.css", "text/css"), ("/admin/static/admin.js", "javascript"),
                           ("/admin/static/leaflet/leaflet.js", "javascript"),
                           ("/admin/static/leaflet/images/marker-icon.png", "image/png")):
            status, _, headers = self.anon.get(path)
            self.assertEqual(status, 200, path)
            self.assertIn(kind, headers["Content-Type"])
        for path in ("/admin/static/../vpn_policy.py", "/admin/static/%2e%2e/vpn_policy.py",
                     "/admin/static/nope.css", "/admin/static/leaflet"):
            self.assertEqual(self.anon.get(path)[0], 404, path)


if __name__ == "__main__":
    unittest.main()
