"""JEV command classifier: classify shell commands for Codex approvals.

This package is the reference implementation that ships with the
`jev-command-classifier` skill. It is dependency-free (Python 3.9+) so it can
run from a skill folder, a repo checkout, or an installed console script.

The model verdict is advisory. `classifier.decide` is the deterministic,
fail-closed layer that produces the decision a caller enforces, and
`classifier.hard_deny` implements local hard-deny rules that always win.
"""

from .classifier import (
    ALLOW,
    COMMAND_QUESTION,
    DECISION_RANK,
    FORBIDDEN,
    PROBABILITY_SUM_TOLERANCE,
    PROMPT,
    REDACTION_MASK,
    build_state,
    decide,
    hard_deny,
    matched_rule_floor,
    most_restrictive,
    redact,
    redact_argv,
    split_simple,
)
from .client import (
    API_KEY_ENV,
    DEFAULT_ENDPOINT,
    DEFAULT_MODEL,
    ENDPOINT_ENV,
    GENERIC_KEY_ENV,
    JEV_MODEL_PREFIX,
    MODEL_ENV,
    PROVIDER_ENV,
    PROVIDERS,
    TypeSafeAuthError,
    TypeSafeError,
    evaluate,
    resolve_provider,
    validate_jev_model,
)

__all__ = [
    "ALLOW",
    "API_KEY_ENV",
    "COMMAND_QUESTION",
    "DECISION_RANK",
    "DEFAULT_ENDPOINT",
    "DEFAULT_MODEL",
    "ENDPOINT_ENV",
    "FORBIDDEN",
    "GENERIC_KEY_ENV",
    "JEV_MODEL_PREFIX",
    "MODEL_ENV",
    "PROBABILITY_SUM_TOLERANCE",
    "PROVIDER_ENV",
    "PROVIDERS",
    "PROMPT",
    "REDACTION_MASK",
    "TypeSafeAuthError",
    "TypeSafeError",
    "build_state",
    "decide",
    "evaluate",
    "hard_deny",
    "matched_rule_floor",
    "most_restrictive",
    "redact",
    "redact_argv",
    "resolve_provider",
    "split_simple",
    "validate_jev_model",
]

__version__ = "0.1.0"
