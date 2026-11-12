"""Shared policy semantics for collector preflight and the analysis engine."""
import math
from .errors import ConfigError

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

