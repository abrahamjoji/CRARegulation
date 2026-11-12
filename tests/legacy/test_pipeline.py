"""Tests for the SPDX converter, the CRA checks and the CI gate. Run: python -m unittest discover tests"""
import copy
import datetime as dt
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
ROOT = REPO / "poc" / "legacy"
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))
import cra_checks as checks  # noqa: E402

DEMO_DAY = "2026-11-05"

YOCTO_JSON = {
    "spdxVersion": "SPDX-2.2",
    "name": "recipe-openssl",
    "packages": [{
        "name": "openssl",
        "versionInfo": "3.0.1",
        "licenseDeclared": "Apache-2.0",
        "supplier": "Organization: OpenEmbedded ()",
        "externalRefs": [{
            "referenceCategory": "SECURITY",
            "referenceType": "cpe23Type",
            "referenceLocator": "cpe:2.3:a:openssl:openssl:3.0.1:*:*:*:*:*:*:*",
        }],
    }],
}
ZEPHYR_TAG_VALUE = """SPDXVersion: SPDX-2.3
DocumentName: zephyr-sources
PackageName: mbedtls
PackageVersion: 3.5.0
PackageLicenseConcluded: NOASSERTION
PackageCopyrightText: <text>
PackageName: not-a-package
</text>
ExternalRef: PACKAGE-MANAGER purl pkg:github/Mbed-TLS/mbedtls@3.5.0
FileName: ./ignored.c
PackageName: zephyr-app
"""


def run(script, *args):
    return subprocess.run([sys.executable, str(SCRIPTS / script), *map(str, args)], capture_output=True, text=True)


class TempDirTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name)


class SpdxToCdx(TempDirTest):
    def convert(self, *inputs):
        out = self.tmp / "out.cdx.json"
        result = run("spdx_to_cdx.py", *inputs, "-o", out)
        return result, json.loads(out.read_text(encoding="utf-8")) if result.returncode == 0 else None

    def test_json_document(self):
        path = self.tmp / "recipe-openssl.spdx.json"
        path.write_text(json.dumps(YOCTO_JSON), encoding="utf-8")
        result, bom = self.convert(path)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(bom["bomFormat"], "CycloneDX")
        c = bom["components"][0]
        self.assertEqual((c["name"], c["version"]), ("openssl", "3.0.1"))
        self.assertEqual(c["cpe"], "cpe:2.3:a:openssl:openssl:3.0.1:*:*:*:*:*:*:*")
        self.assertEqual(c["licenses"], [{"expression": "Apache-2.0"}])
        self.assertEqual(c["supplier"], {"name": "OpenEmbedded ()"})
        self.assertEqual(c["purl"], "pkg:generic/openssl@3.0.1")

    def test_tag_value_skips_multiline_text_and_warns(self):
        path = self.tmp / "zephyr.spdx"
        path.write_text(ZEPHYR_TAG_VALUE, encoding="utf-8")
        result, bom = self.convert(path)
        self.assertEqual(result.returncode, 0, result.stderr)
        names = [c["name"] for c in bom["components"]]
        self.assertEqual(names, ["mbedtls", "zephyr-app"])
        self.assertEqual(bom["components"][0]["purl"], "pkg:github/Mbed-TLS/mbedtls@3.5.0")
        self.assertNotIn("licenses", bom["components"][0])
        self.assertIn("1 component(s) have no version", result.stdout)
        self.assertIn("2 component(s) have no CPE", result.stdout)

    def test_operating_system_purpose_stays_scannable(self):
        path = self.tmp / "kernel.spdx.json"
        path.write_text(json.dumps({"spdxVersion": "SPDX-2.3", "name": "kernel", "packages": [
            {"name": "linux-yocto", "versionInfo": "5.15.0", "primaryPackagePurpose": "OPERATING-SYSTEM"},
        ]}), encoding="utf-8")
        _, bom = self.convert(path)
        self.assertEqual(bom["components"][0]["type"], "library")

    def test_directory_merge_keeps_cpe_from_later_document(self):
        (self.tmp / "a.spdx.json").write_text(json.dumps({
            "spdxVersion": "SPDX-2.2", "name": "a", "packages": [{"name": "openssl", "versionInfo": "3.0.1"}],
        }), encoding="utf-8")
        (self.tmp / "b.spdx.json").write_text(json.dumps(YOCTO_JSON), encoding="utf-8")
        (self.tmp / "index.json").write_text("{}", encoding="utf-8")
        result, bom = self.convert(self.tmp)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(bom["components"]), 1)
        self.assertIn("cpe", bom["components"][0])

    def test_rejected_inputs_fail(self):
        spdx3 = self.tmp / "image.spdx.json"
        spdx3.write_text(json.dumps({"@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld", "@graph": []}), encoding="utf-8")
        cyclonedx = self.tmp / "other.json"
        cyclonedx.write_text(json.dumps({"bomFormat": "CycloneDX"}), encoding="utf-8")
        empty = self.tmp / "empty.spdx.json"
        empty.write_text(json.dumps({"spdxVersion": "SPDX-2.2", "packages": []}), encoding="utf-8")
        for path, message in ((spdx3, "SPDX 3"), (cyclonedx, "not an SPDX 2.x"), (empty, "no packages"), (self.tmp / "missing", "no such file")):
            result, _ = self.convert(path)
            self.assertEqual(result.returncode, 1, path)
            self.assertIn(message, result.stderr)


class ManualComponents(unittest.TestCase):
    def test_types_are_scanned_by_grype(self):
        bom = json.loads((ROOT / "sbom/manual-components.cdx.json").read_text(encoding="utf-8"))
        for c in bom["components"]:
            self.assertNotIn(c["type"], ("operating-system", "device", "file", "container"), c["name"])


class KevGate(TempDirTest):
    def gate(self, kev=None, vex="vex/demo200.openvex.json"):
        args = ["--product", ROOT / "product.json", "--sbom", ROOT / "sample-data/sbom.syft.cdx.json",
                "--scan", ROOT / "sample-data/scan.grype.json", "--vex", ROOT / vex,
                "--out", self.tmp / "report.html", "--summary", self.tmp / "summary.json", "--gate", "--date", DEMO_DAY]
        if kev:
            args += ["--kev", kev]
        return run("cra_report.py", *args)

    def test_triaged_sample_passes(self):
        result = self.gate(ROOT / "sample-data/kev.json")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(json.loads((self.tmp / "summary.json").read_text(encoding="utf-8"))["kev_loaded"])

    def test_untriaged_known_exploited_fails(self):
        vex = self.tmp / "empty.openvex.json"
        vex.write_text(json.dumps({"statements": []}), encoding="utf-8")
        result = self.gate(ROOT / "sample-data/kev.json", vex)
        self.assertEqual(result.returncode, 2)
        self.assertIn("CVE-2022-0847", result.stdout)

    def test_unusable_catalogue_fails(self):
        bad = {"empty.json": '{"vulnerabilities":[]}', "html.json": "<html>503</html>", "wrong.json": "[]"}
        for name, text in bad.items():
            path = self.tmp / name
            path.write_text(text, encoding="utf-8")
            result = self.gate(path)
            self.assertEqual(result.returncode, 2, name)
            self.assertIn("did not run", (self.tmp / "report.html").read_text(encoding="utf-8"))
        for missing in (None, self.tmp / "absent.json"):
            self.assertEqual(self.gate(missing).returncode, 2, missing)


class Report(TempDirTest):
    """Runs the whole report over edited copies of the demo data."""

    def report(self, *flags, product=None, vex=None, register=None, risk=None, date=DEMO_DAY, root=None):
        def use(name, default, value):
            if value is None:
                return ROOT / default
            path = self.tmp / name
            path.write_text(json.dumps(value), encoding="utf-8")
            return path
        args = ["--product", use("product.json", "product.json", product),
                "--sbom", ROOT / "sample-data/sbom.syft.cdx.json",
                "--manual", ROOT / "sbom/manual-components.cdx.json",
                "--scan", ROOT / "sample-data/scan.grype.json",
                "--vex", use("vex.json", "vex/demo200.openvex.json", vex),
                "--kev", ROOT / "sample-data/kev.json",
                "--risk", use("risk.json", "risk/risk-assessment.json", risk),
                "--register", use("register.json", "vuln/register.json", register),
                "--evidence-root", root or ROOT,
                "--out", self.tmp / "r.html", "--summary", self.tmp / "s.json", "--date", date, *flags]
        result = run("cra_report.py", *args)
        summary = self.tmp / "s.json"
        return result, json.loads(summary.read_text(encoding="utf-8")) if summary.exists() else None

    @staticmethod
    def data(path):
        return json.loads((ROOT / path).read_text(encoding="utf-8"))

    def test_self_declared_met_no_longer_inflates_the_score(self):
        product = self.data("product.json")
        for part in product["annex_i"].values():
            for item in part:
                item["status"] = "met"
        _, base = self.report()
        result, claimed = self.report(product=product)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertLess(claimed["checklist_pct"], 80)
        self.assertGreater(claimed["counts"]["unverified"], 15)
        self.assertEqual(claimed["counts"]["met"], 1)  # only II.1, which the pipeline itself checks
        self.assertGreaterEqual(claimed["score"], base["score"])

    def test_met_with_real_evidence_counts(self):
        product = self.data("product.json")
        (self.tmp / "evidence.txt").write_text("test log", encoding="utf-8")
        item = next(i for i in product["annex_i"]["part_1"] if i["id"] == "I.2(c)")
        item["evidence_refs"] = ["evidence.txt"]
        _, summary = self.report(product=product, root=self.tmp)
        row = next(i for i in summary["checklist"] if i["id"] == "I.2(c)")
        self.assertEqual(row["effective"], "met")

    def test_evidence_outside_the_root_is_refused(self):
        outside = self.tmp.parent / "cra-outside-evidence.txt"
        outside.write_text("x", encoding="utf-8")
        self.addCleanup(outside.unlink)
        self.assertFalse(checks.evidence_exists("../cra-outside-evidence.txt", self.tmp))
        self.assertFalse(checks.evidence_exists(str(outside), self.tmp))

    def test_not_applicable_needs_a_reason_in_the_risk_assessment(self):
        product, risk = self.data("product.json"), self.data("risk/risk-assessment.json")
        item = next(i for i in product["annex_i"]["part_1"] if i["id"] == "I.2(m)")
        item["status"] = "not_applicable"
        _, summary = self.report(product=product)
        self.assertEqual(next(i for i in summary["checklist"] if i["id"] == "I.2(m)")["effective"], "missing")
        risk["applicability"] = [{"requirement": "I.2(m)", "applies": False, "rationale": "Stores no user data"}]
        _, summary = self.report(product=product, risk=risk)
        self.assertEqual(next(i for i in summary["checklist"] if i["id"] == "I.2(m)")["effective"], "not_applicable")
        self.assertEqual(summary["counts"]["not_applicable"], 1)

    def test_met_i2a_is_downgraded_while_findings_are_open(self):
        product = self.data("product.json")
        next(i for i in product["annex_i"]["part_1"] if i["id"] == "I.2(a)")["status"] = "met"
        _, summary = self.report(product=product)
        self.assertEqual(next(i for i in summary["checklist"] if i["id"] == "I.2(a)")["effective"], "partial")

    def test_general_requirement_follows_the_risk_assessment(self):
        _, summary = self.report()
        self.assertEqual(next(i for i in summary["checklist"] if i["id"] == "I.1")["effective"], "partial")
        risk = self.data("risk/risk-assessment.json")
        for r in risk["risks"]:
            r["status"] = "treated"
        _, summary = self.report(risk=risk)
        self.assertEqual(next(i for i in summary["checklist"] if i["id"] == "I.1")["effective"], "met")

    def test_not_affected_without_reasoning_is_rejected(self):
        vex = self.data("vex/demo200.openvex.json")
        for st in vex["statements"]:
            if st["vulnerability"]["name"] == "CVE-2022-0847":
                st["status"] = "not_affected"
                st.pop("impact_statement", None)
        result, summary = self.report("--gate", vex=vex)
        self.assertEqual(result.returncode, 2)
        self.assertIn("VEX decision rejected for CVE-2022-0847", result.stdout)
        self.assertEqual(next(f for f in summary["findings"] if f["id"] == "CVE-2022-0847")["status"], "needs_triage")

    def test_stale_investigation_fails_the_gate(self):
        self.assertEqual(self.report("--gate", date="2026-11-19")[0].returncode, 0)
        result, _ = self.report("--gate", date="2026-11-20")
        self.assertEqual(result.returncode, 2)
        self.assertIn("investigation of CVE-2022-0847", result.stdout)

    def test_invented_register_problem_fails_the_gate(self):
        register = {"entries": [{"id": "A", "type": "vulnerability", "vulnerability": "CVE-1", "source": "rumour"}]}
        result, _ = self.report("--gate", register=register)
        self.assertEqual(result.returncode, 2)
        self.assertIn("source must be one of", result.stdout)

    def test_non_scanner_vulnerability_becomes_a_finding(self):
        register = self.data("vuln/register.json")
        register["entries"].append({"id": "VR-3", "type": "vulnerability", "vulnerability": "EXAMPLE-2026-1", "source": "researcher",
                                    "component": "motion-api", "version": "2.4.1", "severity": "High"})
        _, summary = self.report(register=register)
        found = next(f for f in summary["findings"] if f["id"] == "EXAMPLE-2026-1")
        self.assertEqual((found["status"], found["source"]), ("needs_triage", "researcher"))

    def test_unassessed_entry_does_not_say_nothing_to_report(self):
        register = {"entries": [{"id": "A", "type": "vulnerability", "vulnerability": "CVE-2022-0847", "source": "kev"}]}
        self.report(register=register)
        page = (self.tmp / "r.html").read_text(encoding="utf-8")
        self.assertIn("Assess exploitation", page)
        self.assertNotIn("Nothing to report", page)

    def test_assessed_as_not_exploited_clears_the_reporting_check(self):
        register = self.data("vuln/register.json")
        register["entries"][0]["actively_exploited_in_product"] = False
        _, summary = self.report(register=register)
        self.assertEqual(summary["reporting_checks"], [])

    def test_overdue_article_14_step_fails_the_gate(self):
        register = self.data("vuln/register.json")
        register["entries"][0].update({"actively_exploited_in_product": True, "aware_at": "2026-11-04T08:00:00Z"})
        result, _ = self.report("--gate", register=register)
        self.assertEqual(result.returncode, 2)
        self.assertIn("Early warning (24 hours)", result.stdout)
        register["entries"][0]["early_warning_at"] = "2026-11-04T20:00:00Z"
        self.assertEqual(self.report("--gate", register=register)[0].returncode, 0)

    def test_release_gate_fails_on_the_demo_and_explains_why(self):
        result, _ = self.report("--release-gate")
        self.assertEqual(result.returncode, 2)
        for expected in ("not triaged: CVE-2022-37434", "no recorded release decision for open finding CVE-2022-0847",
                         "record whether it is exploited in this product", "I.2(c) is marked met without evidence"):
            self.assertIn(expected, result.stdout)

    def test_missing_risk_assessment_blocks_release_only(self):
        args = ["--product", ROOT / "product.json", "--sbom", ROOT / "sample-data/sbom.syft.cdx.json",
                "--scan", ROOT / "sample-data/scan.grype.json", "--vex", ROOT / "vex/demo200.openvex.json",
                "--kev", ROOT / "sample-data/kev.json", "--out", self.tmp / "r.html", "--summary", self.tmp / "s.json",
                "--date", DEMO_DAY]
        self.assertEqual(run("cra_report.py", *args, "--gate").returncode, 0)
        result = run("cra_report.py", *args, "--release-gate")
        self.assertEqual(result.returncode, 2)
        self.assertIn("no risk assessment supplied", result.stdout)

    def test_empty_inputs_cannot_pass_as_clean(self):
        for name, text, message in (("sbom.json", '{"components": []}', "SBOM has no components"), ("scan.json", "{}", "scan did not run"),
                                    ("scan.json", '{"matches": null}', "scan did not run"),
                                    ("scan.json", '{"matches": {}}', "scan did not run")):
            path = self.tmp / name
            path.write_text(text, encoding="utf-8")
            args = ["--product", ROOT / "product.json",
                    "--sbom", path if name == "sbom.json" else ROOT / "sample-data/sbom.syft.cdx.json",
                    "--scan", path if name == "scan.json" else ROOT / "sample-data/scan.grype.json",
                    "--vex", ROOT / "vex/demo200.openvex.json", "--kev", ROOT / "sample-data/kev.json",
                    "--out", self.tmp / "r.html", "--summary", self.tmp / "s.json", "--date", DEMO_DAY, "--gate"]
            result = run("cra_report.py", *args)
            self.assertEqual(result.returncode, 2, name)
            self.assertIn(message, result.stdout)

    def test_malformed_register_is_reported_not_a_crash(self):
        register = {"entries": ["text", {"id": "A", "type": "vulnerability", "source": "other"},
                                {"id": "B", "type": "vulnerability", "vulnerability": "CVE-1", "source": "other",
                                 "upstream": "yes", "release_decision": "ship it"}]}
        result, _ = self.report("--gate", register=register)
        self.assertEqual(result.returncode, 2, result.stderr)
        for expected in ("every entry needs an id", "name the vulnerability", "upstream.status must be", "release_decision.decision must be"):
            self.assertIn(expected, result.stdout)

    def test_report_escapes_register_and_risk_text(self):
        risk = self.data("risk/risk-assessment.json")
        risk["risks"][0]["description"] = "<script>alert(1)</script>"
        register = self.data("vuln/register.json")
        register["entries"][0]["id"] = "<img src=x>"
        self.report(risk=risk, register=register)
        page = (self.tmp / "r.html").read_text(encoding="utf-8")
        self.assertNotIn("<script>alert(1)", page)
        self.assertNotIn("<img src=x>", page)

    def test_unscoped_vex_cannot_suppress_a_finding(self):
        vex = self.data("vex/demo200.openvex.json")
        for statement in vex["statements"]:
            statement.pop("products", None)
        result, summary = self.report("--gate", vex=vex)
        self.assertEqual(result.returncode, 2)
        self.assertTrue(all(f["status"] == "needs_triage" for f in summary["findings"]))

    def test_duplicate_vex_is_rejected(self):
        vex = self.data("vex/demo200.openvex.json")
        vex["statements"].append(copy.deepcopy(vex["statements"][0]))
        result, _ = self.report("--gate", vex=vex)
        self.assertEqual(result.returncode, 2)
        self.assertIn("duplicate VEX", result.stderr)

    def test_html_blocks_active_urls_and_attribute_injection(self):
        register = {"entries": [{"id": "X", "type": "vulnerability", "vulnerability": "LOCAL-1",
                    "source": "researcher", "url": "javascript:alert(1)",
                    "severity": 'high" onmouseover="alert(1)'}]}
        result, _ = self.report(register=register)
        self.assertEqual(result.returncode, 0, result.stderr)
        page = (self.tmp / "r.html").read_text()
        self.assertNotIn('href="javascript:', page)
        self.assertNotIn(' onmouseover="', page)
        self.assertNotIn("fonts.googleapis.com", page)

    def test_fix_before_release_blocks_open_finding(self):
        register = self.data("vuln/register.json")
        register["entries"][0]["release_decision"] = {
            "decision": "fix_before_release", **{k: "reviewed" for k in checks.DECISION_FIELDS}}
        result, _ = self.report("--release-gate", register=register)
        self.assertIn("must be fixed before release", result.stdout)
        self.assertEqual(result.returncode, 2)

    def test_future_submission_does_not_satisfy_reporting_gate(self):
        register = self.data("vuln/register.json")
        register["entries"][0].update({"actively_exploited_in_product": True,
            "aware_at": "2026-11-04T08:00:00Z", "early_warning_at": "2026-11-06T00:00:00Z"})
        result, _ = self.report("--gate", register=register)
        self.assertEqual(result.returncode, 2)
        self.assertIn("early_warning_at is in the future", result.stdout)

    def test_missing_and_partial_checklist_items_block_release(self):
        result, _ = self.report("--release-gate")
        self.assertEqual(result.returncode, 2)
        self.assertIn("is incomplete: missing", result.stdout)
        self.assertIn("is incomplete: partial", result.stdout)

    def test_checklist_rows_cannot_be_deleted_duplicated_or_marked_computed(self):
        for mutation in ("delete", "duplicate", "computed", "unknown", "refs"):
            product = self.data("product.json")
            items = product["annex_i"]["part_1"]
            if mutation == "delete":
                items.pop()
            elif mutation == "duplicate":
                items.append(copy.deepcopy(items[0]))
            elif mutation == "computed":
                items[0]["computed"] = True
            elif mutation == "unknown":
                items[0]["id"] = "I.99"
            else:
                items[0]["evidence_refs"] = "README.md"
            result, _ = self.report("--release-gate", product=product)
            self.assertEqual(result.returncode, 2, mutation)
            self.assertIn("Invalid input", result.stderr)

    def test_register_decision_is_bound_to_its_component(self):
        register = self.data("vuln/register.json")
        register["entries"][0]["purl"] = "pkg:generic/another-kernel@1.0"
        register["entries"][0]["actively_exploited_in_product"] = False
        _, summary = self.report(register=register)
        kernel = next(f for f in summary["findings"] if f["component"] == "linux-kernel")
        self.assertIsNone(kernel["exploited"])
        self.assertIn("CVE-2022-0847", summary["reporting_checks"])

    def test_unscoped_register_decision_cannot_authorize_a_component(self):
        register = self.data("vuln/register.json")
        register["entries"][0].pop("purl")
        register["entries"][0]["actively_exploited_in_product"] = False
        _, summary = self.report(register=register)
        kernel = next(f for f in summary["findings"] if f["component"] == "linux-kernel")
        self.assertIsNone(kernel["exploited"])

    def test_duplicate_component_decisions_are_rejected(self):
        register = self.data("vuln/register.json")
        duplicate = copy.deepcopy(register["entries"][0])
        duplicate["id"] = "ANOTHER-ID"
        register["entries"].append(duplicate)
        result, _ = self.report("--gate", register=register)
        self.assertEqual(result.returncode, 2)
        self.assertIn("duplicate vulnerability/component identity", result.stdout)

    def test_gate_result_is_recorded_in_summary(self):
        result, summary = self.report("--release-gate")
        self.assertEqual(result.returncode, 2)
        self.assertFalse(summary["gate"]["passed"])
        self.assertTrue(summary["gate"]["failures"])
        _, summary = self.report("--gate")
        self.assertTrue(summary["gate"]["passed"])

    def test_reporting_events_cannot_precede_awareness(self):
        register = {"entries": [{"id": "INC-1", "type": "incident",
            "aware_at": "2026-11-05T00:00:00Z", "notification_at": "2026-11-04T00:00:00Z"}]}
        result, _ = self.report("--gate", register=register)
        self.assertEqual(result.returncode, 2)
        self.assertIn("notification_at precedes awareness", result.stdout)

    def test_templates_load_and_block_release(self):
        product, risk, register = (self.data(f"templates/{n}") for n in ("product.json", "risk-assessment.json", "register.json"))
        result, summary = self.report("--release-gate", product=product, risk=risk, register=register)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(summary["counts"]["met"], 0)
        self.assertIn("classification_rationale is empty", result.stdout)


class LargeScan(TempDirTest):
    """A real kernel scan produces thousands of findings. The report has to stay usable."""

    def build(self, *flags, count=5000):
        matches = [{"vulnerability": {"id": f"CVE-2099-{n}", "severity": "High", "cvss": [], "fix": {"versions": []}},
                    "artifact": {"name": "linux-kernel", "version": "5.15.0", "purl": "pkg:generic/linux-kernel@5.15.0"}}
                   for n in range(count)]
        matches.append({"vulnerability": {"id": "CVE-2099-LOW", "severity": "Low", "cvss": [], "fix": {"versions": []}},
                        "artifact": {"name": "zlib", "version": "1.2.11", "purl": "pkg:conan/zlib@1.2.11"}})
        scan, kev = self.tmp / "scan.json", self.tmp / "kev.json"
        scan.write_text(json.dumps({"matches": matches}), encoding="utf-8")
        kev.write_text(json.dumps({"vulnerabilities": [{"cveID": f"CVE-2099-{n}"} for n in (4000, 4001, 4002, 4003, 4004)]}), encoding="utf-8")
        self.page_path, self.summary_path = self.tmp / "r.html", self.tmp / "s.json"
        return run("cra_report.py", "--product", ROOT / "product.json", "--sbom", ROOT / "sample-data/sbom.syft.cdx.json",
                   "--scan", scan, "--vex", ROOT / "vex/demo200.openvex.json", "--kev", kev,
                   "--out", self.page_path, "--summary", self.summary_path, "--date", DEMO_DAY, *flags)

    def test_report_is_limited_and_summary_is_complete(self):
        result = self.build()
        self.assertEqual(result.returncode, 0, result.stderr)
        page = self.page_path.read_text(encoding="utf-8")
        summary = json.loads(self.summary_path.read_text(encoding="utf-8"))
        self.assertLess(len(page), 300_000)
        self.assertIn("Showing the 200 highest-priority of 5001 findings", page)
        self.assertEqual(len(summary["findings"]), 5001)
        self.assertEqual(page.count('class="sev-'), 200)
        self.assertIn("2 more known-exploited findings", page)

    def test_known_exploited_rank_first_in_table_and_components(self):
        self.build()
        page = self.page_path.read_text(encoding="utf-8")
        summary = json.loads(self.summary_path.read_text(encoding="utf-8"))
        self.assertLess(page.index("CVE-2099-4004</a>"), page.index("CVE-2099-0</a>"))
        top = summary["by_component"][0]
        self.assertEqual((top["component"], top["total"], top["kev"], top["untriaged"]), ("linux-kernel", 5000, 5, 5000))

    def test_missing_fix_reads_properly(self):
        self.build()
        page = self.page_path.read_text(encoding="utf-8")
        self.assertIn("The scan data lists no upstream fix.", page)
        self.assertNotIn("upstream in none", page)

    def test_gate_output_is_limited_but_complete_in_count(self):
        result = self.build("--release-gate", count=300)
        self.assertEqual(result.returncode, 2)
        self.assertIn("more; see the summary file", result.stdout)
        self.assertLess(result.stdout.count("\n"), 70)
        self.assertIn("linux-kernel 5.15.0: 300 findings, 0 known exploited", result.stdout)


class Presentation(TempDirTest):
    def page(self, *flags, product=None):
        path = ROOT / "product.json"
        if product is not None:
            path = self.tmp / "product.json"
            path.write_text(json.dumps(product), encoding="utf-8")
        out = self.tmp / "r.html"
        result = run("cra_report.py", "--product", path, "--sbom", ROOT / "sample-data/sbom.syft.cdx.json",
                     "--scan", ROOT / "sample-data/scan.grype.json", "--kev", ROOT / "sample-data/kev.json",
                     "--out", out, "--summary", self.tmp / "s.json", "--date", DEMO_DAY, *flags)
        self.assertEqual(result.returncode, 0, result.stderr)
        return out.read_text(encoding="utf-8")

    def test_report_loads_nothing_from_other_sites(self):
        page = self.page()
        self.assertNotIn("googleapis", page)
        self.assertNotIn("gstatic", page)
        self.assertNotRegex(page, r"<(link|script|img)[^>]+(href|src)=\"https?://")

    def test_every_demo_report_is_labelled(self):
        self.assertIn("curated sample data", self.page("--sample"))
        self.assertIn("Demo product", self.page())

    def test_real_product_has_no_demo_label(self):
        product = json.loads((ROOT / "product.json").read_text(encoding="utf-8"))
        product["demo"] = False
        page = self.page(product=product)
        self.assertNotIn("Demo product", page)
        self.assertNotIn("curated sample data", page)


class Workflow(unittest.TestCase):
    def test_syft_output_version_matches_manual_sbom(self):
        import re
        workflow = (REPO / ".github/workflows/cra-pipeline.yml").read_text(encoding="utf-8")
        generation = next(line.strip() for line in workflow.splitlines() if "run: syft scan" in line)
        output = re.search(r"-o cyclonedx-json@([0-9]+\.[0-9]+)=out/sbom\.cdx\.json", generation)
        self.assertIsNotNone(output, "Syft output schema must be explicit, not the moving default")
        manual = json.loads((ROOT / "sbom/manual-components.cdx.json").read_text(encoding="utf-8"))
        self.assertEqual(output.group(1), manual["specVersion"])


    def test_tools_are_pinned(self):
        text = (REPO / ".github/workflows/cra-pipeline.yml").read_text(encoding="utf-8")
        self.assertNotIn("/main/install.sh", text)
        self.assertNotRegex(text, r"uses: [^\s]+@v\d")
        self.assertIn("sha256sum -c", text)


class Article14Clock(unittest.TestCase):
    NOW = dt.datetime(2026, 11, 10, 12, tzinfo=dt.timezone.utc)

    def steps(self, entry):
        return {s["label"].split(" (")[0]: s for s in checks.reporting_clock(entry, self.NOW)["steps"]}

    def test_listed_but_not_exploited_has_no_clock(self):
        self.assertIsNone(checks.reporting_clock({"type": "vulnerability", "actively_exploited_in_product": False}, self.NOW))
        self.assertIsNone(checks.reporting_clock({"type": "vulnerability", "actively_exploited_in_product": None}, self.NOW))

    def test_vulnerability_deadlines(self):
        entry = {"type": "vulnerability", "actively_exploited_in_product": True, "aware_at": "2026-11-09T12:00:00Z"}
        steps = self.steps(entry)
        self.assertEqual(steps["Early warning"]["due"], "2026-11-10T12:00:00+00:00")
        self.assertEqual(steps["Early warning"]["state"], "due")
        self.assertEqual(steps["Notification"]["due"], "2026-11-12T12:00:00+00:00")
        self.assertEqual(steps["Final report"]["state"], "waiting")
        entry["fix_available_at"] = "2026-11-10T00:00:00Z"
        self.assertEqual(self.steps(entry)["Final report"]["due"], "2026-11-24T00:00:00+00:00")

    def test_incident_final_report_is_one_month_after_notification(self):
        entry = {"type": "incident", "aware_at": "2026-12-29T00:00:00Z", "notification_at": "2027-01-31T00:00:00Z"}
        self.assertEqual(self.steps(entry)["Final report"]["due"], "2027-02-28T00:00:00+00:00")

    def test_late_submission_is_recorded(self):
        entry = {"type": "incident", "aware_at": "2026-11-01T00:00:00Z", "early_warning_at": "2026-11-03T00:00:00Z"}
        self.assertEqual(self.steps(entry)["Early warning"]["state"], "done late")

    def test_awareness_before_the_reporting_start_is_not_retroactive(self):
        day_before = {"type": "vulnerability", "actively_exploited_in_product": True, "aware_at": "2026-09-10T23:00:00Z"}
        self.assertTrue(checks.reporting_clock(day_before, self.NOW)["exempt"])
        first_day = copy.deepcopy(day_before)
        first_day["aware_at"] = "2026-09-11T00:00:00Z"
        self.assertFalse(checks.reporting_clock(first_day, self.NOW)["exempt"])


class Product(unittest.TestCase):
    TODAY = dt.date(2026, 11, 5)
    BASE = {"classification_rationale": "x", "support_period_end": "2032-12-31",
            "market": {"first_placed": "2026-03-01", "units_after_application": True}}

    def test_valid_product(self):
        self.assertEqual(checks.product_problems(self.BASE, self.TODAY), [])

    def test_short_support_needs_a_reason(self):
        short = {**self.BASE, "support_period_end": "2030-01-01"}
        self.assertIn("para 128", checks.product_problems(short, self.TODAY)[0])
        self.assertEqual(checks.product_problems({**short, "support_period_rationale": "Expected use is 2 years"}, self.TODAY), [])

    def test_duties_depend_on_market_dates(self):
        ended = {"market": {"first_placed": "2026-03-01", "units_after_application": False}}
        self.assertIn("Not required", checks.duties(ended, self.TODAY)["annex_i"])
        self.assertIn("Applies now", checks.duties(ended, self.TODAY)["reporting"])
        self.assertIn("first placement", checks.duties({"market": {"first_placed": None}}, self.TODAY)["reporting"])


if __name__ == "__main__":
    unittest.main()
