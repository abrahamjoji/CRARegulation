"""Collection from captured real Conan, CMake and Syft output, and failures around it."""
import json
import unittest
from pathlib import Path

import helpers
from helpers import Workspace, make_elf
from cra.collector import artifact as artifact_module, cmake, conan, container, records
from cra.collector.prepare import prepare
from cra.common.config import load_config
from cra.common.errors import ConfigError, UntrustedInputError


class Base(unittest.TestCase):
    def setUp(self):
        self.ws = Workspace()
        self.addCleanup(self.ws.cleanup)

    def status(self, out, source, subject):
        return next(row for row in out["sources"] if row["source"] == source and row["subject"] == subject)


class ConanGraph(Base):
    def graph(self, name="debug-shared-lz4"):
        return json.loads((self.ws.root / f"{name}.graph.json").read_text())

    def observations(self, document, state="resolved"):
        return {row["identity"]["name"]: row for row in conan.collect_graph(document, "cfg", "ev")["observations"] if row["state"] == state}

    def test_contexts_identity_and_settings_are_preserved(self):
        rows = self.observations(self.graph())
        self.assertEqual(rows["ninja"]["scope"], "build_tool")
        self.assertEqual(rows["doctest"]["scope"], "test")
        self.assertEqual(rows["zlib"]["scope"], "runtime")
        self.assertEqual(rows["zlib"]["linkage"], "shared")
        self.assertEqual(rows["nlohmann_json"]["linkage"], "header")
        attributes = rows["zlib"]["attributes"]
        self.assertTrue(attributes["recipe_revision"])
        self.assertTrue(attributes["package_id"])
        self.assertTrue(attributes["package_revision"])
        self.assertEqual(attributes["options"]["shared"], "True")
        self.assertEqual(attributes["settings"]["build_type"], "Debug")
        self.assertEqual(attributes["libraries"], ["z"])

    def test_root_settings_options_recorded(self):
        build = conan.collect_graph(self.graph(), "cfg", "ev")["build"]
        self.assertEqual(build["root_reference"], "reference-gateway/1.0.0")
        self.assertEqual(build["options"]["with_lz4"], "True")
        self.assertEqual(build["settings"]["compiler.version"], "16")

    def test_graph_error_and_missing_binary_are_reported(self):
        document = self.graph()
        document["graph"]["error"] = "conflict in versions"
        document["graph"]["nodes"]["1"]["binary"] = "Missing"
        problems = conan.collect_graph(document, "cfg", "ev")["problems"]
        self.assertTrue(any("graph error" in item for item in problems))
        self.assertTrue(any("missing" in item for item in problems))

    def test_transitive_test_dependency_is_test_scope(self):
        document = {"graph": {"root": {"0": "app"}, "nodes": {
            "0": {"ref": "app/1", "dependencies": {"1": {"ref": "a/1", "direct": True, "test": True}}},
            "1": {"ref": "a/1", "context": "host", "dependencies": {"2": {"ref": "b/1", "direct": True}}},
            "2": {"ref": "b/1", "context": "host", "dependencies": {}}}}}
        self.assertEqual(self.observations(document)["b"]["scope"], "test")

    def test_runtime_path_wins_over_test_path(self):
        document = {"graph": {"root": {"0": "app"}, "nodes": {
            "0": {"ref": "app/1", "dependencies": {"1": {"ref": "a/1", "direct": True, "test": True}, "2": {"ref": "b/1", "direct": True}}},
            "1": {"ref": "a/1", "context": "host", "dependencies": {"2": {"ref": "b/1"}}},
            "2": {"ref": "b/1", "context": "host", "dependencies": {}}}}}
        self.assertEqual(self.observations(document)["b"]["scope"], "runtime")

    def test_malformed_graphs_rejected(self):
        for document in ({}, {"graph": {}}, {"graph": {"nodes": []}}, {"graph": {"nodes": {"0": "x"}}}, [], {"graph": {"nodes": {"0": {"ref": "a b/1"}, "1": {"ref": "bad ref/1"}}, "root": {"0": ""}}}):
            with self.assertRaises(UntrustedInputError):
                conan.collect_graph(document, "cfg", "ev")

    def test_recipe_is_parsed_and_never_executed(self):
        marker = self.ws.root / "pwned"
        text = f"import os\nos.system('touch {marker}')\nclass A:\n    requires = ('zlib/1.2.13', 'range/[>=1 <2]')\n    def requirements(self):\n        if self.options.x:\n            self.requires('opt/1.0')\n"
        rows, notes = conan.parse_manifest(text, "conanfile.py", "cfg", "ev")
        self.assertFalse(marker.exists())
        by_name = {row["identity"]["name"]: row for row in rows}
        self.assertIsNone(by_name["range"]["identity"]["version"])
        self.assertTrue(by_name["opt"]["attributes"]["conditional"])
        self.assertTrue(any("not seen" in note for note in notes))

    def test_txt_manifest(self):
        rows, _ = conan.parse_manifest("[requires]\nzlib/1.2.13 # c\n[tool_requires]\nninja/1.0\n[generators]\nCMakeDeps\n", "conanfile.txt", "cfg", "ev")
        self.assertEqual({row["identity"]["name"]: row["scope"] for row in rows}, {"zlib": "runtime", "ninja": "build_tool"})


class CMake(Base):
    def test_prepare_writes_query_before_configure(self):
        results = prepare(self.ws.config())
        query = self.ws.root / "app/build-release-static/build/Release/.cmake/api/v1/query/client-cra/query.json"
        self.assertEqual({item["kind"] for item in json.loads(query.read_text())["requests"]}, {"codemodel", "cache", "toolchains", "cmakeFiles"})
        self.assertEqual(results[0]["status"], "prepared")

    def test_prepare_warns_when_already_configured_without_reply(self):
        tree = self.ws.root / "app/build-release-static/build/Release"
        import shutil
        shutil.rmtree(tree / ".cmake")
        (tree / "CMakeCache.txt").write_text("")
        self.assertIn("already configured", prepare(self.ws.config())[0]["note"])

    def test_prepare_out_of_scope_rejected(self):
        self.ws.edit_config('roots = ["."]', 'roots = ["tools"]')
        with self.assertRaises(ConfigError):
            prepare(self.ws.config())

    def test_missed_prepare_is_explained_and_incomplete(self):
        tree = self.ws.root / "app/build-release-static/build/Release"
        import shutil
        shutil.rmtree(tree / ".cmake")
        out, _ = self.ws.collect()
        row = self.status(out, "cmake", "release-static")
        self.assertEqual(row["status"], "missing")
        self.assertEqual(row["code"], "cmake_prepare_missed")
        self.assertIn("cra prepare", row["reason"])

    def test_link_paths_map_to_packages_and_links_not_guessed_from_names(self):
        out, _ = self.ws.collect()
        rows = [row for row in out["observations"] if row["source"] == "cmake" and row["configuration"] == "release-static"]
        by = {row["identity"]["name"]: row for row in rows}
        self.assertEqual(by["zlib"]["attributes"]["via"], "link_path")
        self.assertEqual(by["zlib"]["linkage"], "static")
        self.assertEqual(by["nlohmann_json"]["attributes"]["via"], "include_path")
        self.assertEqual(by["nlohmann_json"]["confidence"], "medium")
        self.assertNotIn("doctest", by)
        self.assertTrue(any(row["fragment"] == "-lm" for row in out["unresolved_links"]))

    def test_vendored_source_is_noticed(self):
        out, _ = self.ws.collect()
        self.assertIn("third_party/tinycrc", [row["path"] for row in out["vendored_candidates"]])

    def test_reply_cannot_read_outside_its_directory(self):
        tree = self.ws.root / "app/build-release-static/build/Release/.cmake/api/v1/reply"
        index = next(tree.glob("index-*.json"))
        data = json.loads(index.read_text())
        for entry in data["objects"]:
            if entry["kind"] == "codemodel":
                entry["jsonFile"] = "../../../../../../../../../../etc/passwd"
        index.write_text(json.dumps(data))
        out, _ = self.ws.collect()
        row = self.status(out, "cmake", "release-static")
        self.assertEqual(row["status"], "failed")
        self.assertEqual(row["code"], "cmake_reply_invalid")

    def test_unknown_configuration_reported(self):
        self.ws.edit_config('cmake_config = "Release"', 'cmake_config = "RelWithDebInfo"')
        row = self.status(self.ws.collect()[0], "cmake", "release-static")
        self.assertEqual(row["code"], "cmake_config_missing")

    def test_multi_config_reply_needs_explicit_choice(self):
        with self.assertRaises(UntrustedInputError) as caught:
            cmake._select_configuration({"configurations": [{"name": "Debug"}, {"name": "Release"}]}, None)
        self.assertEqual(caught.exception.code, "cmake_config_ambiguous")

    def test_secret_cache_values_are_not_retained(self):
        reply = self.ws.root / "app/build-release-static/build/Release/.cmake/api/v1/reply"
        cache = next(reply.glob("cache-*.json"))
        data = json.loads(cache.read_text())
        data["entries"].append({"name": "DEPLOY_TOKEN", "value": "s3cretvalue", "type": "STRING", "properties": []})
        cache.write_text(json.dumps(data))
        _, destination = self.ws.collect()
        for path in Path(destination).rglob("*"):
            if path.is_file():
                self.assertNotIn("s3cretvalue", path.read_text(errors="replace"), path)


class Artifacts(Base):
    def test_elf_facts(self):
        facts = artifact_module.parse_elf(make_elf(needed=("libz.so.1",), soname="libx.so.1"))
        self.assertEqual(facts["needed"], ["libz.so.1"])
        self.assertEqual(facts["soname"], "libx.so.1")
        self.assertFalse(facts["statically_linked"])
        self.assertFalse(facts["stripped"])

    def test_stripped_static_binary_reports_limitations_not_an_empty_list(self):
        path = self.ws.root / "static"
        path.write_bytes(make_elf(symtab=False))
        from cra.common.config import Artifact
        record, observations, status, _ = artifact_module.collect_artifact(Artifact(id="s", path=path), "ev")
        self.assertEqual(observations, [])
        joined = " ".join(record["limitations"])
        self.assertIn("Statically linked", joined)
        self.assertIn("Stripped", joined)
        self.assertIn("does not show a component is absent", joined)
        self.assertEqual(status, "complete")

    def test_unsupported_format_is_reported(self):
        path = self.ws.root / "fw.bin"
        path.write_bytes(b"\x00\x01firmware")
        from cra.common.config import Artifact
        record, _, status, _ = artifact_module.collect_artifact(Artifact(id="f", path=path), "ev")
        self.assertEqual(status, "unsupported")
        self.assertEqual(len(record["sha256"]), 64)

    def test_hostile_elf_never_crashes_uncontrolled(self):
        base = make_elf(needed=("libz.so.1",))
        import random
        generator = random.Random(1234)
        outcomes = set()
        for _ in range(400):
            data = bytearray(base)
            for _ in range(generator.randint(1, 12)):
                data[generator.randrange(4, len(data))] = generator.randrange(256)
            try:
                artifact_module.parse_elf(bytes(data))
                outcomes.add("parsed")
            except UntrustedInputError:
                outcomes.add("rejected")
        self.assertTrue(outcomes)

    def test_truncated_elf_rejected(self):
        with self.assertRaises(UntrustedInputError):
            artifact_module.parse_elf(b"\x7fELF\x02\x01")
        self.assertIsNone(artifact_module.parse_elf(b"MZ not elf"))

    def test_signature_scan(self):
        path = self.ws.root / "sig"
        path.write_bytes(b"xx inflate 1.2.13 Copyright 1995 yy OpenSSL 3.0.1 \x00")
        hits, _ = artifact_module.scan_signatures(path)
        self.assertEqual(hits, {"openssl": ["3.0.1"], "zlib": ["1.2.13"]})

    def test_missing_artifact_is_reported(self):
        self.ws.edit_config('path = "app/build-release-static/build/Release/gateway"', 'path = "app/absent"')
        row = self.status(self.ws.collect()[0], "artifact", "gateway-release")
        self.assertEqual(row["status"], "missing")

    def test_artifact_outside_scope_is_refused(self):
        self.ws.edit_config('path = "app/build-release-static/build/Release/gateway"', 'path = "/etc/hostname"')
        with self.assertRaises(UntrustedInputError):
            self.ws.collect()


class Containers(Base):
    def test_digest_and_role_recorded(self):
        out, _ = self.ws.collect()
        final = next(item for item in out["artifacts"] if item["id"] == "final")
        self.assertTrue(final["digest"].startswith("sha256:"))
        self.assertEqual(len(final["sha256"]), 64)
        self.assertEqual(final["distro"], {"id": "debian", "version": "12"})
        builder_rows = [row for row in out["observations"] if row.get("artifact") == "builder"]
        self.assertTrue(builder_rows)
        self.assertTrue(all(row["scope"] == "build_stage" for row in builder_rows))

    def test_mutable_reference_refused(self):
        self.ws.edit_config('archive = "reference-final.oci.tar"', 'reference = "docker.io/library/debian:latest"')
        with self.assertRaises(ConfigError) as caught:
            self.ws.config()
        self.assertEqual(caught.exception.code, "image_reference_mutable")

    def test_syft_failures_are_incomplete_and_redacted(self):
        for behaviour, status in (("fail", "failed"), ("empty", "partial"), ("bad-version", "unsupported"), ("malformed", "failed")):
            self.ws.set_behaviour({"syft": behaviour})
            row = self.status(self.ws.collect()[0], "image", "final")
            self.assertEqual(row["status"], status, behaviour)
            self.assertNotIn("supersecretvalue", json.dumps(row))

    def test_syft_timeout(self):
        self.ws.edit_config("timeout_seconds = 30", "timeout_seconds = 1")
        self.ws.set_behaviour({"syft": "timeout"})
        self.assertIn("timed out", self.status(self.ws.collect()[0], "image", "final")["reason"])

    def test_missing_scanner_is_reported(self):
        self.ws.edit_config('syft = "tools/syft"', 'syft = "tools/absent"')
        self.assertEqual(self.status(self.ws.collect()[0], "image", "final")["status"], "failed")

    def test_hostile_outer_archive_refused_before_scanner_runs(self):
        import io
        import tarfile
        path = self.ws.root / "reference-final.oci.tar"
        with tarfile.open(path, "w") as archive:
            info = tarfile.TarInfo("../../evil")
            info.size = 1
            archive.addfile(info, io.BytesIO(b"x"))
        self.ws.set_behaviour({"syft": "fail"})
        row = self.status(self.ws.collect()[0], "image", "final")
        self.assertEqual(row["code"], "archive_traversal")

    def test_expected_digest_mismatch(self):
        self.ws.edit_config('archive = "reference-final.oci.tar"', 'archive = "reference-final.oci.tar"\nexpected_digest = "sha256:0000"')
        self.assertIn("differs from expected", self.status(self.ws.collect()[0], "image", "final")["reason"])

    def test_pinned_reference_accepts_index_digest_and_refuses_other(self):
        import types
        from cra.common.bundle import EvidenceStore
        pinned = "a" * 64
        for repo_digest, status in ((f"repo@sha256:{pinned}", "complete"), ("repo@sha256:" + "b" * 64, "failed")):
            document = json.loads((helpers.FIXTURES / "final.syft.json").read_text())
            document["source"]["metadata"]["repoDigests"] = [repo_digest]
            (self.ws.root / "tools" / "final.syft.json").write_text(json.dumps(document))
            image = types.SimpleNamespace(id="final", role="final", archive=None, format="oci-archive", reference=f"repo@sha256:{pinned}", expected_digest=None)
            store = EvidenceStore(self.ws.root / "ev")
            config = self.ws.config()
            self.assertEqual(container.collect_image(image, config.tools, store)[2], status, repo_digest)

    def test_docker_daemon_is_never_requested(self):
        import types
        image = types.SimpleNamespace(reference=None, format="oci-archive", archive="/x.tar")
        self.assertEqual(container.scheme_argument(image), "oci-archive:/x.tar")
        image = types.SimpleNamespace(reference="r@sha256:" + "0" * 64, format="", archive=None)
        self.assertTrue(container.scheme_argument(image).startswith("registry:"))


class Records(unittest.TestCase):
    def test_unknown_key_and_bad_shape_rejected(self):
        for document in ({"schema_version": "x", "components": []}, {"schema_version": records.SCHEMA, "components": [{"name": "a", "bad": 1}]},
                         {"schema_version": records.SCHEMA, "components": [{"name": "a", "cpes": ["nope"]}]},
                         {"schema_version": records.SCHEMA, "components": [{"name": "a", "purl": "nope"}]}):
            with self.assertRaises(UntrustedInputError):
                records.parse_records(document, "ev")


class ConfigValidation(Base):
    def test_unknown_key_and_schema_rejected(self):
        self.ws.edit_config('[product]', '[product]\nsurprise = 1')
        with self.assertRaises(ConfigError) as caught:
            self.ws.config()
        self.assertEqual(caught.exception.code, "config_unknown_key")

    def test_wrong_schema_version(self):
        self.ws.edit_config('schema_version = "cra.config/1"', 'schema_version = "cra.config/99"')
        with self.assertRaises(ConfigError) as caught:
            self.ws.config()
        self.assertEqual(caught.exception.code, "config_schema")

    def test_scope_is_required(self):
        self.ws.edit_config('[scope]\nroots = ["."]\n', '')
        with self.assertRaises(ConfigError):
            self.ws.config()

    def test_missing_file(self):
        with self.assertRaises(ConfigError):
            load_config(self.ws.root / "absent.toml")


if __name__ == "__main__":
    unittest.main()
