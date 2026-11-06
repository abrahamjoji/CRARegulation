"""cra gate: decide the CI outcome from an existing result. It never rescans.

The gate needs no analysis engine, so it runs in the collector-only distribution.
A missing, malformed or unverifiable result is incomplete, and never a pass.
"""
import datetime as dt
from pathlib import Path

from . import __version__
from .common.bundle import verify_manifest
from .common.errors import OUTCOME_EXIT, UntrustedInputError
from .common.safety import read_json, sha256_file

SUPPORTED_RESULT = "cra.result/1"
GATE_SCHEMA = "cra.gate/1"


def _failure(mode, code, message):
    return {"schema_version": GATE_SCHEMA, "gate_version": __version__, "mode": mode, "outcome": "incomplete",
            "exit_code": OUTCOME_EXIT["incomplete"], "reasons": [{"code": code, "message": message}], "provenance": None}


def evaluate_gate(analysis_dir, mode="build", expect_revision=None, expect_artifacts=None, expect_policy=None, max_age_hours=None, now=None):
    """Return the gate record. Expectations bind the decision to the current build."""
    now = now or dt.datetime.now(dt.timezone.utc)
    analysis_dir = Path(analysis_dir)
    result_path = analysis_dir / "result.json"
    if not result_path.is_file():
        return _failure(mode, "result_missing", f"No analysis result at {result_path}. Analysis did not run or failed.")
    try:
        problems = verify_manifest(analysis_dir)
        result = read_json(result_path)
    except UntrustedInputError as exc:
        return _failure(mode, exc.code, f"The result cannot be verified: {exc}")
    if problems:
        return _failure(mode, "result_integrity", "The result bundle does not match its manifest: " + "; ".join(problems[:5]))
    if not isinstance(result, dict) or result.get("schema_version") != SUPPORTED_RESULT:
        return _failure(mode, "result_schema_unsupported", f"Expected result schema {SUPPORTED_RESULT}.")
    evaluation = (result.get("evaluation") or {}).get(mode) if isinstance(result.get("evaluation"), dict) else None
    if not isinstance(evaluation, dict) or evaluation.get("outcome") not in OUTCOME_EXIT:
        return _failure(mode, "result_malformed", f"The result has no usable evaluation for gate mode {mode}.")
    for field in ("incomplete_reasons", "policy_violations"):
        rows = evaluation.get(field)
        if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
            return _failure(mode, "result_malformed", f"The evaluation {field} must be a list of reason objects.")
    if evaluation.get("mode") != mode:
        return _failure(mode, "result_inconsistent", "The evaluation mode does not match the requested gate mode.")
    if (evaluation["outcome"] == "passed" and (evaluation["incomplete_reasons"] or evaluation["policy_violations"])):
        return _failure(mode, "result_inconsistent", "A passed result contains incomplete reasons or policy violations.")
    if not isinstance(result.get("source"), dict) or not isinstance(result.get("policy"), dict):
        return _failure(mode, "result_malformed", "Result source and policy must be objects.")
    if not isinstance(result.get("artifacts"), list):
        return _failure(mode, "result_malformed", "Result artifacts must be a list.")
    if result.get("scan_status") != "complete" and evaluation["outcome"] != "incomplete":
        return _failure(mode, "result_inconsistent", "The result says the scan was incomplete but evaluates to a final outcome.")

    outcome = evaluation["outcome"]
    reasons = [dict(item) for item in evaluation.get("incomplete_reasons") or []] + [dict(item) for item in evaluation.get("policy_violations") or []]
    binding = []
    source = result.get("source") or {}
    if expect_revision and source.get("revision") != expect_revision:
        binding.append({"code": "revision_mismatch", "message": f"The result is for revision {source.get('revision')}, and this build is {expect_revision}."})
    artifacts = {item.get("id"): item for item in result.get("artifacts") or [] if isinstance(item, dict)}
    for identifier, digest in (expect_artifacts or {}).items():
        record = artifacts.get(identifier)
        actual = (record or {}).get("sha256") or (record or {}).get("digest") or ""
        if actual.removeprefix("sha256:") != digest.removeprefix("sha256:"):
            binding.append({"code": "artifact_mismatch", "message": f"Artifact {identifier} in the result is {actual or 'absent'}, expected {digest}."})
    policy = result.get("policy") or {}
    if expect_policy and policy.get("sha256") != expect_policy:
        binding.append({"code": "policy_mismatch", "message": f"The result used policy hash {policy.get('sha256') or 'built-in'}, expected {expect_policy}."})
    if max_age_hours is not None:
        try:
            created = dt.datetime.fromisoformat(result.get("created_at"))
            age = (now - created).total_seconds() / 3600
        except (TypeError, ValueError, OverflowError):
            age = None
        if age is None or age > max_age_hours or age < 0:
            binding.append({"code": "result_stale", "message": f"The result is outside the {max_age_hours}-hour age limit."})
    if binding:
        outcome = "incomplete"
        reasons = binding + reasons
    return {"schema_version": GATE_SCHEMA, "gate_version": __version__, "mode": mode, "outcome": outcome, "exit_code": OUTCOME_EXIT[outcome],
            "reasons": reasons, "evaluated_at": now.isoformat(timespec="seconds"),
            "provenance": {"result_sha256": sha256_file(result_path), "collector": result.get("collector"), "engine": result.get("engine"),
                           "policy": policy, "scanners": result.get("scanners"), "vulnerability_data": result.get("vulnerability_data"),
                           "source": source, "artifacts": list(artifacts.values())}}
