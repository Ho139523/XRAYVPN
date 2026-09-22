import re
import subprocess
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

ANDROID = Path(__file__).resolve().parent.parent / "android"
SCRIPT = ANDROID / "apply-overlay.py"
MODULE = ANDROID / "overlay" / "parentpanel"

MANIFEST = '''<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
    <application
        android:name=".AngApplication"
        android:label="@string/app_name">
        <activity android:name=".ui.MainActivity" />
    </application>
</manifest>
'''


def project(root, kts=True, manifest=MANIFEST):
    ext = ".kts" if kts else ""
    (root / "V2rayNG" / "app" / "src" / "main").mkdir(parents=True)
    (root / "V2rayNG" / ("settings.gradle" + ext)).write_text('include(":app")\n' if kts else "include ':app'\n")
    (root / "V2rayNG" / "app" / ("build.gradle" + ext)).write_text(
        'plugins {\n    id("com.android.application")\n}\n\nandroid {\n    dependencies { }\n}\n\n'
        'dependencies {\n    implementation("x:y:1")\n}\n' if kts else
        "plugins {\n    id 'com.android.application'\n}\n\ndependencies {\n    implementation 'x:y:1'\n}\n")
    (root / "V2rayNG" / "app" / "src" / "main" / "AndroidManifest.xml").write_text(manifest)
    return root


def run(root):
    return subprocess.run([sys.executable, str(SCRIPT), str(root)], capture_output=True, text=True)


class ApplyOverlay(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def read(self, *parts):
        return self.root.joinpath("V2rayNG", *parts).read_text()

    def test_kotlin_dsl_project(self):
        project(self.root)
        result = run(self.root)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('include(":parentpanel")', self.read("settings.gradle.kts"))
        build = self.read("app", "build.gradle.kts")
        self.assertIn('implementation(project(":parentpanel"))', build)
        # in the top-level block, not the one nested inside android { }
        self.assertLess(build.index('project(":parentpanel")'), build.index('implementation("x:y:1")'))
        self.assertGreater(build.index('project(":parentpanel")'), build.rindex("dependencies {", 0, build.index('implementation("x:y:1")')))
        self.assertTrue((self.root / "V2rayNG" / "parentpanel" / "build.gradle.kts").exists())
        self.assertTrue((self.root / "V2rayNG" / "parentpanel" / "src" / "main" / "AndroidManifest.xml").exists())

    def test_groovy_project(self):
        project(self.root, kts=False)
        self.assertEqual(run(self.root).returncode, 0)
        self.assertIn("include ':parentpanel'", self.read("settings.gradle"))
        self.assertIn("implementation project(':parentpanel')", self.read("app", "build.gradle"))

    def test_cleartext_is_enabled_and_the_manifest_stays_valid_xml(self):
        project(self.root)
        run(self.root)
        text = self.read("app", "src", "main", "AndroidManifest.xml")
        self.assertIn('android:usesCleartextTraffic="true"', text)
        ET.fromstring(text)

    def test_existing_cleartext_setting_is_overridden_not_duplicated(self):
        project(self.root, manifest=MANIFEST.replace('android:label=', 'android:usesCleartextTraffic="false"\n        android:label='))
        run(self.root)
        text = self.read("app", "src", "main", "AndroidManifest.xml")
        self.assertEqual(text.count("usesCleartextTraffic"), 1)
        self.assertIn('usesCleartextTraffic="true"', text)

    def test_self_closing_application_element(self):
        project(self.root, manifest='<manifest xmlns:android="http://schemas.android.com/apk/res/android">'
                                    '<application android:label="x" /></manifest>')
        self.assertEqual(run(self.root).returncode, 0)
        ET.fromstring(self.read("app", "src", "main", "AndroidManifest.xml"))

    def test_running_twice_changes_nothing_more(self):
        project(self.root)
        run(self.root)
        before = {p: p.read_text() for p in self.root.rglob("*") if p.is_file() and p.suffix in (".kts", ".xml")}
        self.assertEqual(run(self.root).returncode, 0)
        after = {p: p.read_text() for p in before}
        self.assertEqual(before, after)
        self.assertEqual(self.read("app", "build.gradle.kts").count(":parentpanel"), 1)
        self.assertEqual(self.read("settings.gradle.kts").count(":parentpanel"), 1)

    def test_clear_errors_when_the_project_is_not_what_was_expected(self):
        self.assertEqual(run(self.root).returncode, 1)  # no manifest at all
        project(self.root)
        (self.root / "V2rayNG" / "settings.gradle.kts").unlink()
        result = run(self.root)
        self.assertEqual(result.returncode, 1)
        self.assertIn("settings.gradle", result.stderr)


class OverlaySources(unittest.TestCase):
    def test_xml_is_well_formed(self):
        for path in list(MODULE.rglob("*.xml")):
            ET.parse(path)

    def test_manifest_declares_everything_the_code_uses(self):
        manifest = (MODULE / "src/main/AndroidManifest.xml").read_text()
        for name in ("ParentPanelActivity", "LocationReportService", "BootReceiver"):
            self.assertIn(name, manifest)
            self.assertTrue(list(MODULE.rglob(name + ".kt")), name)
        self.assertIn('foregroundServiceType="location"', manifest)
        for permission in ("INTERNET", "ACCESS_FINE_LOCATION", "ACCESS_BACKGROUND_LOCATION",
                           "FOREGROUND_SERVICE_LOCATION", "POST_NOTIFICATIONS"):
            self.assertIn("android.permission." + permission, manifest)

    def test_every_string_the_code_uses_exists_in_both_languages(self):
        code = "".join(p.read_text() for p in MODULE.rglob("*.kt")) + (MODULE / "src/main/AndroidManifest.xml").read_text()
        used = set(re.findall(r"R\.string\.(\w+)|@string/(\w+)", code))
        used = {a or b for a, b in used}
        for values in ("values", "values-fa"):
            defined = {e.get("name") for e in ET.parse(MODULE / "src/main/res" / values / "strings.xml").getroot()}
            self.assertEqual(used - defined, set(), values)
        en = {e.get("name") for e in ET.parse(MODULE / "src/main/res/values/strings.xml").getroot()}
        fa = {e.get("name") for e in ET.parse(MODULE / "src/main/res/values-fa/strings.xml").getroot()}
        self.assertEqual(en, fa)

    def test_kotlin_brackets_balance(self):
        for path in MODULE.rglob("*.kt"):
            code = re.sub(r'"(?:\\.|[^"\\\n])*"', '""', path.read_text())      # string literals
            code = re.sub(r"/\*.*?\*/|//[^\n]*", "", code, flags=re.S)           # comments
            for open_, close in ("()", "{}", "[]"):
                self.assertEqual(code.count(open_), code.count(close), "%s %s%s" % (path.name, open_, close))

    def test_the_code_only_talks_through_the_local_proxy_to_the_gate(self):
        code = (MODULE / "src/main/kotlin/com/familyfilter/parentpanel/CoreHttp.kt").read_text()
        self.assertIn("Proxy.Type.SOCKS", code)
        self.assertIn('"127.0.0.1"', code)


class Workflow(unittest.TestCase):
    def test_workflow_is_valid_yaml_with_the_expected_steps(self):
        text = (ANDROID.parent / ".github/workflows/android-apk.yml").read_text()
        for needle in ("workflow_dispatch", "repository: 2dust/v2rayNG", "apply-overlay.py", "assembleDebug",
                       "upload-artifact"):
            self.assertIn(needle, text)
        self.assertNotIn("\t", text)  # YAML forbids tabs


if __name__ == "__main__":
    unittest.main()
