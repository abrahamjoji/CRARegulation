"""Customer-approved policy, and evaluation of findings against it for each gate mode."""
import datetime as dt
import math
import tomllib
from pathlib import Path

from ..common.errors import ConfigError
from ..common.safety import sha256_bytes

SCHEMA = "cra.policy/1"
SEVERITIES = ("critical", "high", "medium", "low", "negligible", "unknown")
SCOPES = ("shipped", "shipped_or_unknown", "all")
DEFAULT = {
    "schema_version": SCHEMA, "version": "default",
    "vex": {"trusted_authors": []},
    "freshness": {"max_vulnerability_data_age_hours": 168, "max_kev_age_hours": 168, "kev_required": True},
    "triage": {"max_investigation_days": 14},
    "build": {"block_severities": ["critical", "high"], "block_scope": "shipped_or_unknown", "block_kev_untriaged": True, "block_vex_problems": True,
              "minimum_confidence": "medium", "block_conflicts": False},
    "release": {"block_severities": ["critical", "high", "medium"], "block_scope": "shipped_or_unknown", "block_kev_untriaged": True, "block_vex_problems": True,
                "minimum_confidence": "low", "block_conflicts": True, "require_all_triaged": True, "require_readiness": False},
}
_ALLOWED = {"build": set(DEFAULT["build"]), "release": set(DEFAULT["release"]), "vex": {"trusted_authors"},
            "freshness": set(DEFAULT["freshness"]), "triage": {"max_investigation_days"}}
CONFIDENCE = {"low": 0, "medium": 1, "high": 2}


def _validated(raw, label):
    if not isinstance(raw, dict):
        raise ConfigError("policy_invalid", f"{label}: policy must be a table")
    unknown = set(raw) - {"schema_version", "version", *_ALLOWED}
    if unknown:
        raise ConfigError("policy_unknown_key", f"{label}: unknown keys {sorted(unknown)}")
    if raw.get("schema_version") != SCHEMA:
        raise ConfigError("policy_schema", f"{label}: schema_version must be {SCHEMA!r}")
    if not isinstance(raw.get("version"), str) or not raw["version"].strip():
        raise ConfigError("policy_invalid", f"{label}: a policy needs a version string")
    policy = {"schema_version": SCHEMA, "version": raw["version"]}
    for section, allowed in _ALLOWED.items():
        table = raw.get(section, {})
        if not isinstance(table, dict) or set(table) - allowed:
            raise ConfigError("policy_unknown_key", f"{label}: bad keys in [{section}]")
        policy[section] = {**DEFAULT[section], **table}
    for mode in ("build", "release"):
        table = policy[mode]
        if not isinstance(table["block_severities"], list) or any(not isinstance(value, str) or value not in SEVERITIES for value in table["block_severities"]):
            raise ConfigError("policy_invalid", f"{label}: {mode}.block_severities has unknown values")
        if table["block_scope"] not in SCOPES:
            raise ConfigError("policy_invalid", f"{label}: {mode}.block_scope must be one of {SCOPES}")
        if not isinstance(table["minimum_confidence"], str) or table["minimum_confidence"] not in CONFIDENCE:
            raise ConfigError("policy_invalid", f"{label}: {mode}.minimum_confidence must be low, medium or high")
        for key, default in DEFAULT[mode].items():
            if isinstance(default, bool) and not isinstance(table[key], bool):
                raise ConfigError("policy_invalid", f"{label}: {mode}.{key} must be a boolean")
    authors = policy["vex"]["trusted_authors"]
    if not isinstance(authors, list) or any(not isinstance(author, str) or not author.strip() for author in authors):
        raise ConfigError("policy_invalid", f"{label}: vex.trusted_authors must list nonempty strings")
    for key in ("max_vulnerability_data_age_hours", "max_kev_age_hours"):
        value = policy["freshness"][key]
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value <= 0:
            raise ConfigError("policy_invalid", f"{label}: freshness.{key} must be finite and positive")
    if not isinstance(policy["freshness"]["kev_required"], bool):
        raise ConfigError("policy_invalid", f"{label}: freshness.kev_required must be a boolean")
    days = policy["triage"]["max_investigation_days"]
    if isinstance(days, bool) or not isinstance(days, int) or days <= 0:
        raise ConfigError("policy_invalid", f"{label}: triage.max_investigation_days must be a positive integer")
    return policy


def load_policy(path):
    """Load and validate a TOML policy. Returns (policy, identity)."""
    if path is None:
        policy = _validated({"schema_version": SCHEMA, "version": "builtin-default"}, "builtin")
        return policy, {"version": policy["version"], "sha256": "", "source": "builtin-default"}
    try:
        data = Path(path).read_bytes()
        raw = tomllib.loads(data.decode("utf-8"))
    except OSError as exc:
        raise ConfigError("policy_unreadable", f"cannot read policy {path}: {exc.strerror or exc}") from exc
    except (tomllib.TOMLDecodeError, UnicodeDecodeError) as exc:
        raise ConfigError("policy_invalid", f"{path}: {exc}") from exc
    return _validated(raw, str(path)), {"version": raw["version"], "sha256": sha256_bytes(data), "source": Path(path).name}


def _in_scope(finding, scope):
    shipped = finding["presence"]["shipped"]
    if scope == "all":
        return True
    return shipped == "yes" if scope == "shipped" else shipped in ("yes", "unknown")


def _age_hours(value, now):
    if not isinstance(value, str):
        return None
    try:
        moment = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=dt.timezone.utc)
    return (now - moment).total_seconds() / 3600


def incompleteness(inventory, scan, kev_identity, kev_problem, vex_problems, policy, now):
    """Reasons a result cannot be treated as a completed scan. Applies to every gate mode."""
    reasons = [dict(item, origin="coverage") for item in inventory["coverage"]["incomplete_reasons"]]
    for item in scan["diagnostics"]:
        if item.get("severity") == "error":
            reasons.append({"code": item["code"], "subject": item.get("subject", ""), "message": item["message"], "origin": "tool"})
    fresh = policy["freshness"]
    if kev_problem and fresh["kev_required"]:
        reasons.append({"code": "kev_unavailable", "subject": "kev", "message": f"The known-exploited check did not run: {kev_problem}", "origin": "input"})
    if kev_identity:
        age = _age_hours(kev_identity.get("date_released"), now)
        if age is None and fresh["kev_required"]:
            reasons.append({"code": "kev_age_unknown", "subject": "kev", "message": "The KEV catalogue does not state a usable release date.", "origin": "input"})
        elif age is not None and age < -5 / 60:
            reasons.append({"code": "kev_in_future", "subject": "kev", "message": "The KEV catalogue release time is in the future.", "origin": "input"})
        elif age is not None and age > fresh["max_kev_age_hours"]:
            reasons.append({"code": "kev_stale", "subject": "kev", "message": f"The KEV catalogue is {age:.0f} hours old; the limit is {fresh['max_kev_age_hours']}.", "origin": "input"})
    database = (scan.get("scanner") or {}).get("database") or {}
    built = database.get("built")
    age = _age_hours(built, now)
    if age is None:
        reasons.append({"code": "vulnerability_data_age_unknown", "subject": "grype-db", "message": "The vulnerability database did not state a build time.", "origin": "tool"})
    elif age < -5 / 60:
        reasons.append({"code": "vulnerability_data_in_future", "subject": "grype-db", "message": "The vulnerability database build time is in the future.", "origin": "tool"})
    elif age > fresh["max_vulnerability_data_age_hours"]:
        reasons.append({"code": "vulnerability_data_stale", "subject": "grype-db", "message": f"Vulnerability data is {age:.0f} hours old; the limit is {fresh['max_vulnerability_data_age_hours']}.", "origin": "tool"})
    reasons += [dict(item, origin="input") for item in vex_problems]
    return reasons


def evaluate(findings, inventory, policy, incomplete, readiness, now):
    """Evaluate both gate modes. Findings are never removed; only their effect is decided."""
    return {mode: _evaluate_mode(mode, findings, inventory, policy, incomplete, readiness, now) for mode in ("build", "release")}


def _evaluate_mode(mode, findings, inventory, policy, incomplete, readiness, now):
    rules = policy[mode]
    violations = []

    def block(code, message, finding=None):
        record = {"code": code, "message": message}
        if finding:
            record.update(finding=finding["id"], vulnerability=finding["vulnerability"]["id"], component=finding["component"]["purl"])
        violations.append(record)

    open_states = ("needs_triage", "under_investigation", "affected")
    minimum = CONFIDENCE[rules["minimum_confidence"]]
    for finding in findings:
        label = f"{finding['vulnerability']['id']} on {finding['component']['name']} {finding['component']['version']}"
        status = finding["triage"]["status"]
        if rules["block_vex_problems"] and finding["triage"]["problem"] and status == "needs_triage":
            block("vex_rejected", f"A VEX statement for {label} was not applied: {finding['triage']['problem']}.", finding)
        if finding["kev"]["listed"] and status == "needs_triage" and rules["block_kev_untriaged"]:
            block("kev_untriaged", f"{label} is in the KEV catalogue and has no triage decision. Investigate whether it is exploitable in this product.", finding)
        if status == "under_investigation":
            age = _age_hours(finding["triage"].get("since"), now)
            limit = policy["triage"]["max_investigation_days"]
            if age is None or age < 0 or age / 24 > limit:
                block("investigation_overdue", f"The investigation of {label} is older than the {limit}-day limit or has no usable start date.", finding)
        decision = (finding.get("register") or {}).get("release_decision") or {}
        if status in open_states and finding["severity"] in rules["block_severities"] and _in_scope(finding, rules["block_scope"]):
            if status == "affected" or CONFIDENCE.get(finding["matching"]["confidence"], 0) >= minimum:
                block("severity_blocked", f"{label}: {finding['severity']} severity, status {status}, shipped {finding['presence']['shipped']}.", finding)
        if mode == "release":
            if rules["require_all_triaged"] and status == "needs_triage" and _in_scope(finding, rules["block_scope"]):
                block("untriaged", f"{label} has no triage decision.", finding)
            if decision.get("decision") == "fix_before_release" and status in open_states:
                block("fix_before_release", f"The recorded release decision requires {label} to be fixed first.", finding)
    if rules["block_conflicts"]:
        for conflict in inventory["conflicts"]:
            if conflict["kind"] not in ("version_varies",):
                block("inventory_conflict", f"Unresolved {conflict['kind']} for {conflict['subject']}: {', '.join(map(str, conflict['values']))}.")
    if mode == "release" and rules["require_readiness"]:
        if readiness is None:
            block("readiness_missing", "This policy requires CRA readiness records, and none were supplied.")
        else:
            for failure in readiness["release_failures"]:
                block("readiness", failure)
    outcome = "incomplete" if incomplete else "policy_blocked" if violations else "passed"
    return {"mode": mode, "outcome": outcome, "incomplete_reasons": incomplete, "policy_violations": violations}
