"""Compatibility alias: the checks moved to src/cra/readiness/validation.py."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "src"))
from cra.readiness import validation as _module  # noqa: E402

sys.modules[__name__] = _module
