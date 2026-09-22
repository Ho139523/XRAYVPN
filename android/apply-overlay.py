#!/usr/bin/env python3
"""Adds the Family filter module to a checkout of the v2rayNG Android client.

    python3 android/apply-overlay.py <path to the v2rayNG checkout>

It (1) copies android/overlay/parentpanel next to the app module, (2) includes
it in the Gradle build, (3) makes the app depend on it, and (4) allows plain
HTTP in the app manifest, because the parent page lives at an http:// address
inside the tunnel. Running it twice changes nothing more. It only edits by
searching for standard Gradle/manifest constructs and stops with a clear error
if it cannot find them.
"""
from __future__ import annotations

import re
import shutil
import sys
from pathlib import Path

OVERLAY = Path(__file__).resolve().parent / "overlay" / "parentpanel"
MODULE = "parentpanel"


def fail(message):
    print("ERROR: %s" % message, file=sys.stderr)
    sys.exit(1)


def add_module(gradle_root):
    settings = next((gradle_root / n for n in ("settings.gradle.kts", "settings.gradle")
                     if (gradle_root / n).exists()), None)
    if settings is None:
        fail("no settings.gradle(.kts) in %s" % gradle_root)
    text = settings.read_text()
    if ":%s" % MODULE in text:
        return settings
    line = 'include(":%s")' % MODULE if settings.suffix == ".kts" else "include ':%s'" % MODULE
    settings.write_text(text.rstrip("\n") + "\n" + line + "\n")
    return settings


def add_dependency(app_dir):
    build = next((app_dir / n for n in ("build.gradle.kts", "build.gradle") if (app_dir / n).exists()), None)
    if build is None:
        fail("no build.gradle(.kts) in the app module %s" % app_dir)
    text = build.read_text()
    if ":%s" % MODULE in text:
        return build
    kts = build.suffix == ".kts"
    dependency = ('    implementation(project(":%s"))' if kts else "    implementation project(':%s')") % MODULE
    # the module's own top-level `dependencies {` block (column 0), not one nested elsewhere
    match = re.search(r"^dependencies\s*\{[ \t]*\n", text, re.M)
    if not match:
        fail("no top-level dependencies { } block in %s" % build)
    build.write_text(text[:match.end()] + dependency + "\n" + text[match.end():])
    return build


def allow_cleartext(manifest):
    text = manifest.read_text()
    tag = re.search(r"<application\b[^>]*>", text, re.S)
    if not tag:
        fail("no <application> element in %s" % manifest)
    old = tag.group(0)
    attribute = 'android:usesCleartextTraffic="true"'
    if re.search(r"android:usesCleartextTraffic\s*=", old):
        new = re.sub(r'android:usesCleartextTraffic\s*=\s*"[^"]*"', attribute, old)
    else:
        end = "/>" if old.endswith("/>") else ">"
        new = old[:-len(end)].rstrip() + "\n        " + attribute + end
    manifest.write_text(text.replace(old, new, 1))


def main(argv):
    if len(argv) != 2:
        fail("usage: apply-overlay.py <v2rayNG checkout>")
    upstream = Path(argv[1]).resolve()
    if not upstream.is_dir():
        fail("not a directory: %s" % upstream)
    if not OVERLAY.is_dir():
        fail("overlay not found: %s" % OVERLAY)

    manifests = sorted((p for p in upstream.rglob("AndroidManifest.xml")
                        if p.parts[-4:-1] == ("app", "src", "main") and ".git" not in p.parts),
                       key=lambda p: len(p.parts))
    if not manifests:
        fail("no app/src/main/AndroidManifest.xml under %s" % upstream)
    manifest = manifests[0]
    app_dir = manifest.parents[2]
    gradle_root = app_dir.parent

    target = gradle_root / MODULE
    if target.exists():
        shutil.rmtree(target)
    shutil.copytree(OVERLAY, target)

    settings = add_module(gradle_root)
    build = add_dependency(app_dir)
    allow_cleartext(manifest)

    print("Family filter module added:")
    print("  module     : %s" % target)
    print("  settings   : %s" % settings)
    print("  app build  : %s" % build)
    print("  manifest   : %s" % manifest)


if __name__ == "__main__":
    main(sys.argv)
