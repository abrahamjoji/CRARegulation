"""Compatibility alias: the rules moved to src/cra/readiness/checks.py."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from cra.readiness import checks as _module  # noqa: E402

sys.modules[__name__] = _module
