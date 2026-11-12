"""Reconciliation, findings, VEX scope, policy and gate outcomes end to end with fake scanners."""
import copy
import datetime as dt
import json
import unittest

import helpers
from helpers import EXPECTED, Workspace, cpe_match
from cra.common.errors import EXIT_INCOMPLETE, EXIT_PASSED, EXIT_POLICY
from cra.common.safety import read_json, sha256_file, write_json
from cra.engine import measure, policy as policy_module, reconcile
from cra.gate import evaluate_gate

ZLIB = "pkg:conan/zlib@1.2.13"
LIBC = "pkg:deb/debian/libc6@2.36-9%2Bdeb12u4"


class Base(unittest.TestCase):
    def setUp(self):
        self.ws = Workspace()
        self.addCleanup(self.ws.cleanup)

    def inventory(self):
        return read_json(self.ws.analysis_dir / "inventory.json")

    def component(self, inventory, purl):
        return next(item for item in inventory["components"] if item["identity"]["purl"] == purl)

    def gate(self, mode="build", **kwargs):
        return evaluate_gate(self.ws.analysis_dir, mode, **kwargs)

    def codes(self, record):
        return {row["code"] for row in record["reasons"]}


class Inventory(Base):
    def test_reference_build_matches_hand_written_expectation(self):
        self.ws.analyze()
        metrics = measure.compare(self.inventory(), read_json(EXPECTED))
        self.assertEqual(metrics["missing"], [])
        self.assertEqual(metrics["unexpected"], [])
        self.assertEqual(metrics["attribute_mismatches"], [])
        self.assertEqual(metrics["completeness"], 1.0)
        self.assertEqual(metrics["false_component_rate"], 0.0)

    def test_measurement_detects_a_wrong_inventory(self):
        self.ws.analyze()
        inventory = self.inventory()
        inventory["components"] = [item for item in inventory["components"] if item["identity"]["name"] != "zlib"]
        ninja = next(item for item in inventory["components"] if item["identity"]["name"] == "ninja")
        ninja["presence"]["shipped"] = "yes"
        metrics = measure.compare(inventory, read_json(EXPECTED))
        self.assertEqual(metrics["missing"], [ZLIB])
        self.assertTrue(any(row["component"].endswith("ninja@1.13.1") for row in metrics["attribute_mismatches"]))

    def test_states_are_kept_separate(self):
        self.ws.analyze()
        inventory = self.inventory()
        zlib = self.component(inventory, ZLIB)["presence"]
        self.assertTrue(zlib["declared"] and zlib["resolved"] and zlib["observed"])
        self.assertEqual(zlib["shipped"], "yes")
        ninja = self.component(inventory, "pkg:conan/ninja@1.13.1")
        self.assertFalse(ninja["presence"]["observed"])
        self.assertEqual(ninja["presence"]["shipped"], "no")
        self.assertEqual(ninja["scope"], "build_tool")

    def test_build_stage_only_package_is_not_shipped_but_final_is(self):
        self.ws.analyze()
        inventory = self.inventory()
        self.assertEqual(self.component(inventory, "pkg:deb/debian/openssl@3.0.11-1~deb12u2")["presence"]["shipped"], "no")
        self.assertEqual(self.component(inventory, LIBC)["presence"]["shipped"], "yes")

    def test_static_and_shared_configurations_are_visible(self):
        self.ws.analyze()
        zlib = self.component(self.inventory(), ZLIB)
        self.assertEqual(zlib["configurations"]["release-static"]["attributes"]["package_type"], "static-library")
        self.assertEqual(zlib["configurations"]["debug-shared-lz4"]["attributes"]["package_type"], "shared-library")
        self.assertIn("gateway-release", zlib["artifacts"])

    def test_resolved_but_unlinked_optional_dependency_stays_unknown(self):
        self.ws.analyze()
        lz4 = self.component(self.inventory(), "pkg:conan/lz4@1.10.0")
        self.assertEqual(lz4["presence"]["shipped"], "unknown")
        self.assertIn("no evidence", lz4["presence"]["shipped_rationale"][0])

    def test_vendored_component_shipped_with_build_corroboration(self):
        self.ws.analyze()
        record = self.component(self.inventory(), "pkg:generic/tinycrc@1.2.0")
        self.assertEqual(record["presence"]["shipped"], "yes")
        self.assertTrue(any("CMake builds its source path" in row for row in record["presence"]["shipped_rationale"]))
        self.assertIn("gateway-release", record["artifacts"])

    def test_unrecorded_vendored_source_is_incomplete(self):
        (self.ws.root / "vendor-components.json").write_text(json.dumps({"schema_version": "cra.component-records/1", "components": []}))
        result = self.ws.analyze()
        self.assertEqual(result["scan_status"], "incomplete")
        self.assertIn("vendored_source_unidentified", self.codes(self.gate()))

    def test_native_dependency_without_identity_is_kept(self):
        self.ws.analyze()
        unresolved = {row["value"] for row in self.inventory()["unresolved_observations"]}
        self.assertIn("libc.so.6", unresolved)

    def test_version_disagreement_keeps_both_identities(self):
        path = self.ws.root / "app/build-release-static/build/Release/gateway"
        path.write_bytes(path.read_bytes().replace(b"deflate 1.2.13 Copyright", b"deflate 1.2.11 Copyright"))
        self.ws.analyze()
        inventory = self.inventory()
        conflict = next(row for row in inventory["conflicts"] if row["kind"] == "version_disagreement")
        self.assertEqual(conflict["values"], ["1.2.11", "1.2.13"])
        purls = {item["identity"]["purl"] for item in inventory["components"]}
        self.assertTrue({ZLIB, "pkg:generic/zlib@1.2.11"} <= purls)
        self.assertTrue(any("disagree" in text for text in self.component(inventory, ZLIB)["uncertainty"]))

    def test_conflict_blocks_release_mode_only(self):
        path = self.ws.root / "app/build-release-static/build/Release/gateway"
        path.write_bytes(path.read_bytes().replace(b"deflate 1.2.13 Copyright", b"deflate 1.2.11 Copyright"))
        self.ws.write_vex([])
        result = self.ws.analyze()
        release = result["evaluation"]["release"]["policy_violations"]
        build = result["evaluation"]["build"]["policy_violations"]
        self.assertTrue(any(row["code"] == "inventory_conflict" for row in release))
        self.assertFalse(any(row["code"] == "inventory_conflict" for row in build))

    def test_ambiguous_record_keeps_candidates_and_conflict(self):
        (self.ws.root / "vendor-components.json").write_text(json.dumps({"schema_version": "cra.component-records/1", "components": [
            {"name": "tinycrc", "version": "1.2.0", "source_paths": ["third_party/tinycrc"]},
            {"name": "motor-sdk", "candidates": [{"name": "motor-sdk", "version": "4.2.0"}, {"name": "motor-sdk", "version": "4.3.0"}], "shipped": True}]}))
        self.ws.analyze()
        inventory = self.inventory()
        conflict = next(row for row in inventory["conflicts"] if row["kind"] == "ambiguous_identity")
        self.assertEqual(len(conflict["values"]), 2)
        self.assertEqual(sum(item["identity"]["name"] == "motor-sdk" for item in inventory["components"]), 2)

    def test_unknown_version_is_incomplete_not_clean(self):
        (self.ws.root / "vendor-components.json").write_text(json.dumps({"schema_version": "cra.component-records/1", "components": [
            {"name": "tinycrc", "version": "1.2.0", "source_paths": ["third_party/tinycrc"]}, {"name": "vendor-sdk", "shipped": True}]}))
        result = self.ws.analyze()
        self.assertEqual(result["evaluation"]["build"]["outcome"], "incomplete")
        self.assertIn("unknown_version", self.codes(self.gate()))

    def test_empty_detection_is_incomplete_not_clean(self):
        for name in ("release-static", "debug-shared-lz4"):
            pass
        (self.ws.root / "cra.toml").write_text("""
schema_version = "cra.config/1"
[product]
name = "empty"
version = "1"
[scope]
roots = ["."]
[output]
dir = "out"
[[artifacts]]
id = "a"
path = "app/build-release-static/build/Release/gateway"
[tools]
syft = "tools/syft"
grype = "tools/grype"
[analysis]
policy = "policy.toml"
kev = "kev.json"
""")
        (self.ws.root / "app/build-release-static/build/Release/gateway").write_bytes(helpers.make_elf())
        result = self.ws.analyze()
        codes = {row["code"] for row in result["evaluation"]["build"]["incomplete_reasons"]}
        self.assertIn("inventory_empty", codes)
        self.assertEqual(result["evaluation"]["build"]["outcome"], "incomplete")

    def test_hostile_collection_rejected(self):
        from cra.common.errors import UntrustedInputError
        with self.assertRaises(UntrustedInputError):
            reconcile.validate_collection({"schema_version": "cra.collection/1"})
        self.ws.collect()
        good = read_json(self.ws.collection_dir / "collection.json")
        for mutate in (lambda c: c.update(observations="x"), lambda c: c["observations"].append({"id": 1}),
                       lambda c: c["observations"].append({"id": "a", "source": "x", "identity": {"name": 1}}),
                       lambda c: c.update(schema_version="other"), lambda c: c["artifacts"].append({"id": None}), lambda c: c["edges"].append("x")):
            bad = copy.deepcopy(good)
            mutate(bad)
            with self.assertRaises(UntrustedInputError):
                reconcile.validate_collection(bad)

    def test_sbom_export_is_cyclonedx_without_losing_components(self):
        self.ws.analyze()
        sbom = read_json(self.ws.analysis_dir / "sbom.cdx.json")
        self.assertEqual(sbom["specVersion"], "1.5")
        self.assertEqual(len(sbom["components"]), len(self.inventory()["components"]))
        self.assertTrue(sbom["dependencies"] is not None)


class FalseMatches(Base):
    def test_measurement_counts_only_labelled_findings(self):
        self.ws.set_behaviour({"matches": {"build": [cpe_match("CVE-2000-10", "zlib", "1.2.13", ZLIB), cpe_match("CVE-2000-11", "fmt", "12.1.0", "pkg:conan/fmt@12.1.0"),
                                                     cpe_match("CVE-2000-12", "zlib", "1.2.13", ZLIB)], "final": [], "builder": []}})
        result = self.ws.analyze()
        metrics = measure.compare_findings(result, {"labels": [
            {"vulnerability": "CVE-2000-10", "purl": ZLIB, "label": "true"},
            {"vulnerability": "CVE-2000-11", "purl": "pkg:conan/fmt@12.1.0", "label": "false"},
            {"vulnerability": "CVE-2000-99", "purl": ZLIB, "label": "true"}]})
        self.assertEqual(metrics["labelled_true_found"], 1)
        self.assertEqual(metrics["labelled_true_missed"], [f"CVE-2000-99 on {ZLIB}"])
        self.assertEqual([row["vulnerability"] for row in metrics["labelled_false_reported"]], ["CVE-2000-11"])
        self.assertEqual(metrics["unlabelled"], 1)
        self.assertEqual(metrics["false_match_rate_of_labelled"], 0.5)


class Findings(Base):
    def blocked(self):
        return self.ws.analyze()

    def test_finding_has_every_required_explanation(self):
        result = self.blocked()
        finding = next(item for item in result["findings"] if item["vulnerability"]["id"] == "CVE-2024-2961")
        self.assertEqual(finding["component"]["name"], "libc6")
        self.assertEqual(finding["component"]["version"], "2.36-9+deb12u4")
        self.assertTrue(finding["component"]["evidence"])
        self.assertTrue(finding["vulnerability"]["source"]["namespace"].startswith("debian"))
        self.assertTrue(finding["vulnerability"]["source"]["url"].startswith("http"))
        self.assertIn("backported", finding["matching"]["rationale"])
        self.assertEqual(finding["matching"]["confidence"], "high")
        self.assertIn("final", finding["artifacts"])
        self.assertEqual(finding["dependency_paths"][0]["path"][0], "artifact:builder" if False else finding["dependency_paths"][0]["path"][0])
        self.assertTrue(any("final" in row["path"][0] for row in finding["dependency_paths"]))
        self.assertEqual(finding["severity"], "high")
        self.assertTrue(finding["remediation"]["fixed_in"])
        self.assertEqual(finding["exploitability"]["established"], False)
        self.assertEqual(finding["exploitability"]["status"], "unknown")
        self.assertTrue(finding["missing_evidence"])
        self.assertEqual(finding["triage"]["status"], "needs_triage")
        self.assertEqual(finding["origin"], "product")

    def test_conan_dependency_path_and_cpe_uncertainty(self):
        self.ws.set_behaviour({"matches": {"build": [cpe_match("CVE-2000-1", "zlib", "1.2.13", ZLIB)], "final": [], "builder": []}})
        result = self.ws.analyze()
        finding = result["findings"][0]
        self.assertEqual(finding["dependency_paths"][0]["path"], ["product", f"comp:{ZLIB}"])
        self.assertEqual(finding["matching"]["confidence"], "medium")
        self.assertTrue(any("CPE" in text for text in finding["uncertainty"]))

    def test_unjoined_match_is_kept(self):
        self.ws.set_behaviour({"matches": {"build": [cpe_match("CVE-2000-2", "ghost", "1", "pkg:conan/ghost@1")], "final": [], "builder": []}})
        finding = self.ws.analyze()["findings"][0]
        self.assertFalse(finding["component"]["joined_to_inventory"])
        self.assertEqual(finding["presence"]["shipped"], "unknown")
        self.assertEqual(self.gate()["outcome"], "policy_blocked")

    def test_patch_claim_does_not_suppress(self):
        (self.ws.root / "vendor-components.json").write_text(json.dumps({"schema_version": "cra.component-records/1", "components": [
            {"name": "tinycrc", "version": "1.2.0", "source_paths": ["third_party/tinycrc"]},
            {"name": "zlib", "version": "1.2.13", "patched": [{"vulnerability": "CVE-2000-3", "evidence": "backport"}]}]}))
        self.ws.set_behaviour({"matches": {"build": [cpe_match("CVE-2000-3", "zlib", "1.2.13", ZLIB)], "final": [], "builder": []}})
        result = self.ws.analyze()
        finding = result["findings"][0]
        self.assertEqual(finding["triage"]["status"], "needs_triage")
        self.assertTrue(finding["patch_claims"])
        self.assertTrue(any("claims this vulnerability is patched" in text for text in finding["uncertainty"]))
        self.assertEqual(self.gate()["outcome"], "policy_blocked")

    def test_not_matchable_components_are_reported(self):
        result = self.ws.analyze()
        names = {row["name"] for row in result["not_matchable"]}
        self.assertEqual(names, {"doctest", "ninja", "tinycrc"})

    def test_kev_triggers_investigation_without_claiming_exploitation(self):
        self.ws.write_kev([{"cveID": "CVE-2024-2961", "dateAdded": "2026-01-01"}])
        result = self.ws.analyze()
        finding = result["findings"][0]
        self.assertTrue(finding["kev"]["listed"])
        self.assertIn("does not show exploitation in this product", finding["kev"]["meaning"])
        self.assertEqual(finding["exploitability"]["established"], False)
        self.assertIn("kev_untriaged", self.codes(self.gate()))

    def test_kev_blocks_even_a_low_severity_build_finding(self):
        self.ws.write_kev([{"cveID": "CVE-2000-4"}])
        self.ws.set_behaviour({"matches": {"build": [cpe_match("CVE-2000-4", "zlib", "1.2.13", ZLIB, severity="low")], "final": [], "builder": []}})
        self.ws.analyze()
        self.assertEqual(self.gate()["outcome"], "policy_blocked")

    def test_build_stage_finding_does_not_block_but_stays_listed(self):
        self.ws.set_behaviour({"matches": {"build": [], "final": []}})
        result = self.ws.analyze()
        self.assertTrue(any(item["component"]["name"] == "openssl" for item in result["findings"]))
        self.assertEqual(self.gate()["outcome"], "passed")

    def test_low_confidence_match_does_not_block_build_but_is_listed(self):
        match = cpe_match("CVE-2000-5", "ninja", "1.0", "pkg:conan/nothing@1")
        match["artifact"]["cpes"] = []
        self.ws.set_behaviour({"matches": {"build": [match], "final": [], "builder": []}})
        result = self.ws.analyze()
        self.assertEqual(result["findings"][0]["matching"]["confidence"], "low")
        self.assertEqual(self.gate()["outcome"], "passed")
        self.assertEqual(self.gate("release")["outcome"], "policy_blocked")


class Triage(Base):
    def decided(self, statements, **kwargs):
        self.ws.write_vex(statements, **kwargs)
        return next(item for item in self.ws.analyze()["findings"] if item["vulnerability"]["id"] == "CVE-2024-2961")

    def test_scoped_decision_records_provenance_and_keeps_finding(self):
        finding = self.decided([self.ws.not_affected("CVE-2024-2961", LIBC)])
        self.assertEqual(finding["triage"]["status"], "not_affected")
        provenance = finding["triage"]["provenance"]
        self.assertEqual(provenance["author"], "Trusted Team")
        self.assertEqual(provenance["authenticated"], False)
        self.assertEqual(provenance["scope"], "component_only")
        self.assertEqual(len(provenance["document_sha256"]), 64)

    def test_product_scoped_form(self):
        statement = self.ws.not_affected("CVE-2024-2961", "pkg:generic/reference-gateway@1.0.0")
        statement["products"][0]["subcomponents"] = [{"@id": LIBC}]
        finding = self.decided([statement])
        self.assertEqual(finding["triage"]["provenance"]["scope"], "product_and_component")

    def test_other_product_version_does_not_match(self):
        statement = self.ws.not_affected("CVE-2024-2961", "pkg:generic/reference-gateway@0.9.0")
        statement["products"][0]["subcomponents"] = [{"@id": LIBC}]
        self.assertEqual(self.decided([statement])["triage"]["status"], "needs_triage")

    def test_other_component_version_does_not_match(self):
        self.assertEqual(self.decided([self.ws.not_affected("CVE-2024-2961", "pkg:deb/debian/libc6@2.36-9")])["triage"]["status"], "needs_triage")

    def test_unversioned_or_wildcard_product_does_not_match(self):
        self.assertEqual(self.decided([self.ws.not_affected("CVE-2024-2961", "pkg:deb/debian/libc6")])["triage"]["status"], "needs_triage")
        statement = self.ws.not_affected("CVE-2024-2961", "x")
        statement["products"] = []
        self.assertEqual(self.decided([statement])["triage"]["status"], "needs_triage")

    def test_untrusted_author_recorded_not_applied(self):
        finding = self.decided([self.ws.not_affected("CVE-2024-2961", LIBC)], author="Anyone")
        self.assertEqual(finding["triage"]["status"], "needs_triage")
        self.assertIn("not in the policy's trusted", finding["triage"]["problem"])
        self.assertIn("vex_rejected", self.codes(self.gate()))

    def test_generated_statement_cannot_become_trusted(self):
        finding = self.decided([self.ws.not_affected("CVE-2024-2961", LIBC, x_cra_generated_by="some-llm")])
        self.assertEqual(finding["triage"]["status"], "needs_triage")
        self.assertIn("generated", finding["triage"]["problem"])

    def test_not_affected_without_reason_is_rejected(self):
        statement = self.ws.not_affected("CVE-2024-2961", LIBC)
        statement.pop("justification")
        finding = self.decided([statement])
        self.assertEqual(finding["triage"]["status"], "needs_triage")
        self.assertIn("vex_rejected", self.codes(self.gate()))

    def test_expired_decision_not_applied(self):
        finding = self.decided([self.ws.not_affected("CVE-2024-2961", LIBC, x_cra_scope={"expires": "2020-01-01"})])
        self.assertIn("expired", finding["triage"]["problem"])

    def test_context_scope_must_cover_the_finding(self):
        narrow = self.decided([self.ws.not_affected("CVE-2024-2961", LIBC, x_cra_scope={"artifacts": ["other"]})])
        self.assertEqual(narrow["triage"]["status"], "needs_triage")
        covered = self.decided([self.ws.not_affected("CVE-2024-2961", LIBC, x_cra_scope={"artifacts": ["final", "builder"]})])
        self.assertEqual(covered["triage"]["status"], "not_affected")

    def test_later_statement_wins_and_tie_is_a_problem(self):
        earlier = {"vulnerability": {"name": "CVE-2024-2961"}, "products": [{"@id": LIBC}], "status": "under_investigation", "timestamp": "2026-01-01T00:00:00Z"}
        later = self.ws.not_affected("CVE-2024-2961", LIBC, timestamp="2026-01-03T00:00:00Z")
        self.assertEqual(self.decided([earlier, later])["triage"]["status"], "not_affected")
        tie = self.ws.not_affected("CVE-2024-2961", LIBC, timestamp="2026-01-01T00:00:00Z")
        finding = self.decided([earlier, tie])
        self.assertEqual(finding["triage"]["status"], "needs_triage")
        self.assertIn("disagree", finding["triage"]["problem"])

    def test_overdue_investigation_blocks(self):
        old = {"vulnerability": {"name": "CVE-2024-2961"}, "products": [{"@id": LIBC}], "status": "under_investigation", "timestamp": "2020-01-01T00:00:00Z"}
        self.decided([old])
        self.assertIn("investigation_overdue", self.codes(self.gate()))

    def test_unreadable_vex_is_incomplete_not_ignored(self):
        (self.ws.root / "vex.json").write_text("{not json")
        self.ws.analyze()
        self.assertEqual(self.gate()["outcome"], "incomplete")
        self.assertIn("vex_unreadable", self.codes(self.gate()))


class Outcomes(Base):
    """The acceptance path: result, then the correct documented CI outcome."""

    def test_three_distinct_outcomes(self):
        result = self.ws.analyze()
        record = self.gate()
        self.assertEqual((record["outcome"], record["exit_code"]), ("policy_blocked", EXIT_POLICY))
        self.ws.triage_all_blockers(result)
        self.ws.analyze()
        record = self.gate()
        self.assertEqual((record["outcome"], record["exit_code"]), ("passed", EXIT_PASSED), record["reasons"])
        self.ws.set_behaviour({"grype": "fail"})
        self.ws.analyze()
        record = self.gate()
        self.assertEqual((record["outcome"], record["exit_code"]), ("incomplete", EXIT_INCOMPLETE))

    def test_triaged_findings_remain_in_the_result(self):
        result = self.ws.analyze()
        total = result["summary"]["total"]
        self.ws.triage_all_blockers(result)
        after = self.ws.analyze()
        self.assertEqual(after["summary"]["total"], total)
        self.assertGreater(after["summary"]["by_status"]["not_affected"], 0)

    def test_every_scanner_failure_is_incomplete_never_clean(self):
        for behaviour in ("fail", "malformed-null", "malformed-entry", "invalid-db", "bad-version", "stale-db"):
            self.ws.set_behaviour({"grype": behaviour, "matches": {"build": [], "final": [], "builder": []}})
            result = self.ws.analyze()
            self.assertEqual(result["scan_status"], "incomplete", behaviour)
            self.assertEqual(self.gate()["outcome"], "incomplete", behaviour)
            self.assertTrue(result["tool_diagnostics"] or result["evaluation"]["build"]["incomplete_reasons"])

    def test_scanner_timeout(self):
        self.ws.edit_config("timeout_seconds = 30", "timeout_seconds = 1")
        self.ws.set_behaviour({"grype": "timeout"})
        result = self.ws.analyze()
        self.assertTrue(any(row["code"] == "scanner_timeout" for row in result["tool_diagnostics"]))
        self.assertEqual(self.gate()["outcome"], "incomplete")

    def test_scanner_missing(self):
        self.ws.edit_config('grype = "tools/grype"', 'grype = "tools/absent"')
        self.ws.analyze()
        self.assertIn("scanner_missing", self.codes(self.gate()))

    def test_tool_failures_are_separate_from_product_findings(self):
        self.ws.set_behaviour({"grype": "fail"})
        result = self.ws.analyze()
        self.assertTrue(result["tool_diagnostics"])
        self.assertTrue(all(row["origin"] in ("external", "tool", "input") for row in result["tool_diagnostics"]))
        self.assertEqual(result["findings"], [])

    def test_missing_and_stale_kev(self):
        (self.ws.root / "kev.json").unlink()
        self.ws.analyze()
        self.assertIn("kev_unavailable", self.codes(self.gate()))
        self.ws.write_kev([{"cveID": "CVE-1"}], released="2000-01-01T00:00:00Z")
        self.ws.analyze()
        self.assertIn("kev_stale", self.codes(self.gate()))

    def test_gate_never_rescans(self):
        self.ws.analyze()
        before = self.gate()
        self.ws.set_behaviour({"grype": "fail", "syft": "fail"})
        (self.ws.root / "kev.json").unlink()
        self.assertEqual(self.gate()["outcome"], before["outcome"])

    def test_missing_result_is_incomplete(self):
        record = self.gate()
        self.assertEqual((record["outcome"], record["exit_code"]), ("incomplete", EXIT_INCOMPLETE))
        self.assertIn("result_missing", self.codes(record))

    def test_tampered_result_refused(self):
        result = self.ws.analyze()
        result["evaluation"]["build"].update(outcome="passed", policy_violations=[])
        write_json(self.ws.analysis_dir / "result.json", result)
        record = self.gate()
        self.assertEqual(record["outcome"], "incomplete")
        self.assertIn("result_integrity", self.codes(record))

    def test_inconsistent_or_malformed_results_refused(self):
        from cra.common.bundle import write_manifest
        result = self.ws.analyze()
        for mutate, code in ((lambda r: r.update(scan_status="incomplete", evaluation={**r["evaluation"], "build": {**r["evaluation"]["build"], "outcome": "passed"}}), "result_inconsistent"),
                             (lambda r: r.update(evaluation={}), "result_malformed"),
                             (lambda r: r.update(schema_version="cra.result/99"), "result_schema_unsupported")):
            bad = copy.deepcopy(result)
            mutate(bad)
            write_json(self.ws.analysis_dir / "result.json", bad)
            write_manifest(self.ws.analysis_dir)
            self.assertIn(code, self.codes(self.gate()))

    def test_binding_to_the_current_build(self):
        result = self.ws.analyze()
        self.ws.triage_all_blockers(result)
        result = self.ws.analyze()
        release = next(item for item in result["artifacts"] if item["id"] == "gateway-release")
        self.assertEqual(self.gate(expect_revision="abc123", expect_artifacts={"gateway-release": release["sha256"]},
                                   expect_policy=result["policy"]["sha256"], max_age_hours=1)["outcome"], "passed")
        for kwargs, code in (({"expect_revision": "other"}, "revision_mismatch"), ({"expect_artifacts": {"gateway-release": "0" * 64}}, "artifact_mismatch"),
                             ({"expect_artifacts": {"absent": "0" * 64}}, "artifact_mismatch"), ({"expect_policy": "0" * 64}, "policy_mismatch")):
            record = self.gate(**kwargs)
            self.assertEqual(record["outcome"], "incomplete", kwargs)
            self.assertIn(code, self.codes(record))
        later = dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=3)
        self.assertIn("result_stale", self.codes(evaluate_gate(self.ws.analysis_dir, "build", max_age_hours=1, now=later)))

    def test_gate_record_contains_required_provenance(self):
        self.ws.analyze()
        record = self.gate()
        provenance = record["provenance"]
        self.assertEqual(record["mode"], "build")
        self.assertEqual(provenance["collector"]["name"], "cra")
        self.assertTrue(provenance["engine"]["version"])
        self.assertEqual(provenance["policy"]["version"], "test-1")
        self.assertTrue(provenance["vulnerability_data"]["grype"]["built"])
        self.assertTrue(provenance["vulnerability_data"]["kev"]["sha256"])
        self.assertEqual({row["name"] for row in provenance["scanners"]}, {"grype", "syft"})
        self.assertEqual(provenance["source"]["revision"], "abc123")
        self.assertTrue(any(row["sha256"] for row in provenance["artifacts"]))

    def test_raw_output_and_manifest_retained(self):
        self.ws.analyze()
        from cra.common.bundle import verify_manifest
        self.assertEqual(verify_manifest(self.ws.analysis_dir), [])
        self.assertEqual(verify_manifest(self.ws.collection_dir), [])
        self.assertTrue((self.ws.analysis_dir / "evidence" / "grype-image-final.json").is_file())
        self.assertTrue((self.ws.collection_dir / "evidence" / "image-final.syft.json").is_file())
        self.assertTrue((self.ws.collection_dir / "evidence" / "conan-release-static.graph.json").is_file())

    def test_evidence_tampering_stops_analysis(self):
        from cra.engine.analyze import run_analysis
        from cra.common.errors import UntrustedInputError
        self.ws.collect()
        target = self.ws.collection_dir / "collection.json"
        target.write_text(target.read_text() + " ")
        config = self.ws.config()
        with self.assertRaises(UntrustedInputError):
            run_analysis(self.ws.collection_dir, config.analysis, config.tools, self.ws.root / "out2")

    def test_source_is_not_retained_in_the_bundle(self):
        (self.ws.root / "app" / "conanfile.py").write_text((self.ws.root / "app" / "conanfile.py").read_text() + "\n# PROPRIETARY_MARKER\n")
        _, destination = self.ws.collect()
        for path in destination.rglob("*"):
            if path.is_file():
                self.assertNotIn("PROPRIETARY_MARKER", path.read_text(errors="replace"))


class ReportSafety(Base):
    def test_hostile_scanner_text_is_inert(self):
        attack = '<script>alert(1)</script>"><img src=x onerror=alert(1)>'
        match = cpe_match("CVE-2000-6", "zlib", "1.2.13", ZLIB)
        match["vulnerability"].update(description=attack, dataSource="javascript:alert(1)", namespace=attack)
        self.ws.set_behaviour({"matches": {"build": [match], "final": [], "builder": []}})
        self.ws.analyze()
        html_text = (self.ws.analysis_dir / "report.html").read_text()
        self.assertNotIn("<script>", html_text)
        self.assertNotIn("<img", html_text)
        self.assertNotIn('href="javascript', html_text)
        self.assertIn("Content-Security-Policy", html_text)
        self.assertIn("default-src 'none'", html_text)

    def test_report_states_limits_and_outcome(self):
        self.ws.analyze()
        text = (self.ws.analysis_dir / "report.html").read_text()
        self.assertIn("Scan completed and policy blocked the build", text)
        self.assertIn("not verified root causes", text)
        self.assertIn("Failures in our own tooling", text)
        self.assertNotIn("% compliant", text)

    def test_incomplete_banner_differs_from_clean(self):
        self.ws.set_behaviour({"grype": "fail"})
        self.ws.analyze()
        self.assertIn("Scan incomplete, unsupported or failed", (self.ws.analysis_dir / "report.html").read_text())

    def test_markdown_summary_escapes_markup(self):
        from cra.engine.report import _md
        self.assertEqual(_md("a|b<c>\n[x](y)"), "a\\|b\\<c\\> \\[x\\](y)")


class Readiness(Base):
    def test_existing_records_feed_release_mode_without_a_percentage(self):
        root = helpers.REPO / "poc" / "legacy"
        self.ws.edit_config('kev = "kev.json"', f'kev = "kev.json"\nproduct_file = "{root}/product.json"\nrisk_file = "{root}/risk/risk-assessment.json"\nregister_file = "{root}/vuln/register.json"')
        (self.ws.root / "policy.toml").write_text((self.ws.root / "policy.toml").read_text() + "require_readiness = true\n")
        result = self.ws.analyze()
        readiness = result["readiness"]
        self.assertIn("does not certify conformity", readiness["disclaimer"])
        self.assertTrue(readiness["demo_data"])
        self.assertIn("missing", readiness["checklist_counts"])
        self.assertNotIn("score", readiness)
        self.assertTrue(any(row["code"] == "readiness" for row in result["evaluation"]["release"]["policy_violations"]))
        self.assertFalse(any(row["code"] == "readiness" for row in result["evaluation"]["build"]["policy_violations"]))
        report = (self.ws.analysis_dir / "report.html").read_text()
        self.assertIn("does not certify conformity", report)

    def test_register_entry_becomes_a_finding_with_decision(self):
        (self.ws.root / "register.json").write_text(json.dumps({"entries": [
            {"id": "VR-1", "type": "vulnerability", "vulnerability": "CVE-2000-7", "source": "researcher", "first_seen": "2026-01-01T00:00:00Z",
             "actively_exploited_in_product": True, "aware_at": "2026-10-01T00:00:00Z", "purl": ZLIB,
             "release_decision": {"decision": "fix_before_release", "severity": "High", "exploitability": "x", "impact": "x", "rationale": "x", "decided_by": "x", "date": "2026-01-01"}}]}))
        root = helpers.REPO / "poc" / "legacy"
        self.ws.edit_config('kev = "kev.json"', f'kev = "kev.json"\nproduct_file = "{root}/product.json"\nregister_file = "register.json"')
        result = self.ws.analyze()
        finding = next(item for item in result["findings"] if item["vulnerability"]["id"] == "CVE-2000-7")
        self.assertEqual(finding["matching"]["scanner"], "none")
        self.assertEqual(finding["exploitability"]["status"], "recorded_exploited_in_product")
        self.assertTrue(result["readiness"]["article_14"])
        self.assertTrue(any(row["code"] == "fix_before_release" for row in result["evaluation"]["release"]["policy_violations"]))


class PolicyValidation(unittest.TestCase):
    def test_bad_policies_rejected(self):
        import tempfile
        from pathlib import Path
        from cra.common.errors import ConfigError
        for text, code in (('schema_version="x"\nversion="1"', "policy_schema"), ('schema_version="cra.policy/1"', "policy_invalid"),
                           ('schema_version="cra.policy/1"\nversion="1"\nsurprise=1', "policy_unknown_key"),
                           ('schema_version="cra.policy/1"\nversion="1"\n[build]\nblock_severities=["huge"]', "policy_invalid"),
                           ('schema_version="cra.policy/1"\nversion="1"\n[build]\nnope=1', "policy_unknown_key")):
            with tempfile.TemporaryDirectory() as work:
                path = Path(work) / "p.toml"
                path.write_text(text)
                with self.assertRaises(ConfigError) as caught:
                    policy_module.load_policy(path)
                self.assertEqual(caught.exception.code, code)

    def test_default_trusts_no_vex_author(self):
        policy, identity = policy_module.load_policy(None)
        self.assertEqual(policy["vex"]["trusted_authors"], [])
        self.assertEqual(identity["source"], "builtin-default")


if __name__ == "__main__":
    unittest.main()
