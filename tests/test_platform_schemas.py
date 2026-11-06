"""Published JSON Schemas must describe what the tool actually writes and accepts."""
import json
import tomllib
import unittest
from pathlib import Path

import helpers
from helpers import Workspace
from cra.common.safety import read_json
from cra.gate import evaluate_gate

try:
    import jsonschema
    HAVE = True
except ImportError:
    HAVE = False

SCHEMAS = helpers.REPO / "src" / "cra" / "schemas"


@unittest.skipUnless(HAVE, "jsonschema is a development dependency")
class Schemas(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ws = Workspace()
        cls.addClassCleanup(cls.ws.cleanup)
        cls.ws.analyze()

    def check(self, schema, value):
        loaded = json.loads((SCHEMAS / f"{schema}.schema.json").read_text())
        jsonschema.Draft202012Validator.check_schema(loaded)
        jsonschema.validate(value, loaded, cls=jsonschema.Draft202012Validator)

    def test_outputs_match_schemas(self):
        self.check("collection", read_json(self.ws.collection_dir / "collection.json"))
        self.check("inventory", read_json(self.ws.analysis_dir / "inventory.json"))
        self.check("result", read_json(self.ws.analysis_dir / "result.json"))
        self.check("gate", evaluate_gate(self.ws.analysis_dir))
        self.check("gate", evaluate_gate(self.ws.root / "nothing"))

    def test_customer_files_match_schemas(self):
        repo = helpers.REPO / "reference"
        self.check("config", tomllib.loads((repo / "cra.toml").read_text()))
        self.check("policy", tomllib.loads((repo / "policy.toml").read_text()))
        self.check("component-records", read_json(repo / "records" / "vendor-components.json"))

    def test_schema_rejects_a_passed_incomplete_mismatch_value(self):
        result = read_json(self.ws.analysis_dir / "result.json")
        result["evaluation"]["build"]["outcome"] = "clean"
        with self.assertRaises(jsonschema.ValidationError):
            self.check("result", result)


if __name__ == "__main__":
    unittest.main()
