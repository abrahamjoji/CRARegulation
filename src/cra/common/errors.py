"""Documented exit outcomes and structured diagnostics.

An exit code answers one question: what may CI conclude? Causes stay in
diagnostics so a failure in our software is never mistaken for a product finding.
"""
from dataclasses import dataclass, field

EXIT_PASSED = 0
EXIT_POLICY = 10
EXIT_INCOMPLETE = 20
EXIT_CONFIG = 30
EXIT_AUTH = 31
EXIT_OPERATIONAL = 32

OUTCOME_EXIT = {"passed": EXIT_PASSED, "policy_blocked": EXIT_POLICY, "incomplete": EXIT_INCOMPLETE}


def diagnostic(code, message, *, subject="", origin="tool", severity="error", **details):
    """origin: 'tool' for our software, 'input' for supplied data, 'external' for scanners and services."""
    record = {"code": code, "severity": severity, "origin": origin, "subject": subject, "message": message}
    if details:
        record["details"] = details
    return record


@dataclass
class CraError(Exception):
    """A failure that stops a command. Carries its documented exit code and cause."""
    code: str
    message: str
    exit_code: int = EXIT_OPERATIONAL
    details: dict = field(default_factory=dict)

    def __str__(self):
        return f"{self.code}: {self.message}"

    def as_diagnostic(self):
        return diagnostic(self.code, self.message, **self.details)


class ConfigError(CraError):
    def __init__(self, code, message, **details):
        super().__init__(code, message, EXIT_CONFIG, details)


class AuthError(CraError):
    def __init__(self, code, message, **details):
        super().__init__(code, message, EXIT_AUTH, details)


class OperationalError(CraError):
    def __init__(self, code, message, **details):
        super().__init__(code, message, EXIT_OPERATIONAL, details)


class UntrustedInputError(ValueError):
    """Supplied metadata, archive or scanner output failed validation or a limit."""

    def __init__(self, code, message):
        super().__init__(message)
        self.code = code
