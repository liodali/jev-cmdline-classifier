"""Command-line entry point for the JEV command classifier.

Examples::

    python3 scripts/classify_command.py --cwd "$PWD" -- git status --short
    python3 scripts/classify_command.py --command "git push origin main"
    python3 scripts/classify_command.py --offline -- rm -rf /
    python3 scripts/classify_command.py --self-test

Exit codes: 0 allow, 1 prompt, 2 forbidden, 3 classifier failure (the printed
decision is still fail-closed to prompt).
"""

from __future__ import annotations

import argparse
import json
import math
import os
import shlex
import sys
from pathlib import Path
from typing import Optional, Sequence

from .classifier import (
    ALLOW,
    CONFIDENCE_FLOOR,
    FORBIDDEN,
    FORBIDDEN_MASS_CEILING,
    PROMPT,
    hard_deny,
    matched_rule_floor,
    most_restrictive,
    redact,
    redact_argv,
    split_simple,
)
from .client import DEFAULT_ENDPOINT, DEFAULT_MODEL, DEFAULT_TIMEOUT

EXIT_CODES = {ALLOW: 0, PROMPT: 1, FORBIDDEN: 2}

_READ_ONLY = frozenset(
    {
        "ls",
        "pwd",
        "cat",
        "head",
        "tail",
        "wc",
        "file",
        "stat",
        "whoami",
        "id",
        "date",
        "uname",
        "echo",
        "printf",
        "which",
        "type",
        "true",
        "false",
        "rg",
        "grep",
    }
)
_READ_ONLY_GIT = frozenset(
    {
        "status",
        "log",
        "diff",
        "show",
        "rev-parse",
        "ls-files",
        "blame",
        "describe",
        "shortlog",
    }
)


def _heuristic_segment(segment: Sequence[str]) -> dict:
    """Deterministic stand-in for JEV, used only with --offline.

    This is a wiring aid for tests and demos, not a security control. It is
    intentionally conservative: anything it does not recognize becomes prompt.
    """
    reason = hard_deny(segment)
    if reason:
        return {"decision": FORBIDDEN, "reasons": [f"hard-deny: {reason}"]}
    if not segment:
        return {"decision": PROMPT, "reasons": ["empty command"]}

    exe = os.path.basename(segment[0])
    args = list(segment[1:])
    if exe == "git" and args and args[0] in _READ_ONLY_GIT:
        return {"decision": ALLOW, "reasons": ["offline heuristic: read-only git"]}
    if exe in _READ_ONLY:
        if exe == "date" and any(arg.startswith("-s") for arg in args):
            return {"decision": PROMPT, "reasons": ["offline heuristic: date -s"]}
        if any(arg.startswith("-o") for arg in args) and exe in {"sort", "uniq"}:
            return {"decision": PROMPT, "reasons": ["offline heuristic: writes output"]}
        return {"decision": ALLOW, "reasons": ["offline heuristic: read-only"]}
    if exe == "sed" and "-n" in args and not any(a.startswith("-i") for a in args):
        return {"decision": ALLOW, "reasons": ["offline heuristic: sed -n"]}
    if exe == "find" and not any(
        a in {"-delete", "-exec", "-execdir", "-ok", "-fprint", "-fls"} for a in args
    ):
        return {"decision": ALLOW, "reasons": ["offline heuristic: find without writes"]}
    return {"decision": PROMPT, "reasons": ["offline heuristic: not recognized"]}


def _offline_classify(
    command: Optional[str],
    argv: Sequence[str],
    matched_rules: Optional[Sequence[dict]] = None,
) -> dict:
    global_reason = hard_deny(argv, raw=command or "")
    if global_reason:
        record = {
            "argv": list(argv),
            "decision": FORBIDDEN,
            "reasons": [f"hard-deny: {global_reason}"],
        }
        return {
            "decision": FORBIDDEN,
            "reasons": record["reasons"],
            "segments": [record],
            "source": "offline-heuristic",
        }

    rule_floor = matched_rule_floor(matched_rules)
    if rule_floor == FORBIDDEN:
        record = {
            "argv": list(argv),
            "decision": FORBIDDEN,
            "reasons": ["matched execpolicy rule: forbidden"],
        }
        return {
            "decision": FORBIDDEN,
            "reasons": record["reasons"],
            "segments": [record],
            "source": "offline-heuristic",
        }

    segments = split_simple(command) if command else None
    unparsed = command is not None and segments is None
    if segments is None:
        segments = [list(argv)]
    records = []
    for segment in segments:
        if unparsed:
            reason = hard_deny(segment, raw=command or "")
            if reason:
                record = {"decision": FORBIDDEN, "reasons": [f"hard-deny: {reason}"]}
            else:
                record = {
                    "decision": PROMPT,
                    "reasons": ["offline heuristic: unsplittable shell features"],
                }
        else:
            record = _heuristic_segment(segment)
        record["argv"] = list(segment)
        records.append(record)
    overall = most_restrictive(
        [rule_floor] + [record["decision"] for record in records]
    )
    reasons = [
        reason
        for record in records
        if record["decision"] == overall
        for reason in record.get("reasons", [])
    ]
    if rule_floor != ALLOW and rule_floor == overall:
        reasons.insert(0, f"matched execpolicy rule: {rule_floor}")
    return {
        "decision": overall,
        "reasons": reasons,
        "segments": records,
        "source": "offline-heuristic",
    }


def load_fixtures() -> dict:
    """Load the shared language-parity fixtures shipped next to the scripts."""
    path = Path(__file__).resolve().parent.parent / "fixtures" / "cases.json"
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def _self_test() -> int:
    """Check the deterministic decision layer, splitter, and hard denies."""
    from .classifier import decide

    fixtures = load_fixtures()
    failures = []

    for case in fixtures["decide"]:
        options = {}
        if "confidence_floor" in case:
            options["confidence_floor"] = case["confidence_floor"]
        got = decide(
            case["choice"],
            case["confidence"],
            case["probabilities"],
            hard_deny_reason=case.get("hard_deny_reason"),
            **options,
        )["decision"]
        if got != case["expected"]:
            failures.append(f"decide[{case['name']}] -> {got}, expected {case['expected']}")

    for case in fixtures["split"]:
        got = split_simple(case["command"])
        if got != case["expected"]:
            failures.append(
                f"split_simple({case['command']!r}) -> {got!r}, expected {case['expected']!r}"
            )

    for case in fixtures["hard_deny"]:
        got = hard_deny(case["argv"], raw=case["raw"])
        if (got is not None) != case["expected"]:
            failures.append(
                f"hard_deny[{case['name']}] -> {got!r}, expected match={case['expected']}"
            )

    for case in fixtures["rule_floor"]:
        got = matched_rule_floor(case["rules"])
        if got != case["expected"]:
            failures.append(
                f"matched_rule_floor[{case['name']}] -> {got}, expected {case['expected']}"
            )

    for case in fixtures["redact"]:
        got = redact(case["input"])
        if got != case["expected"]:
            failures.append(
                f"redact[{case['name']}] -> {got!r}, expected {case['expected']!r}"
            )

    for case in fixtures["redact_argv"]:
        got = redact_argv(case["argv"])
        if got != case["expected"]:
            failures.append(
                f"redact_argv[{case['name']}] -> {got!r}, expected {case['expected']!r}"
            )

    if failures:
        for failure in failures:
            print(f"FAIL: {failure}", file=sys.stderr)
        return 1
    print("self-test: ok")
    return 0


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="jev-classify",
        description=(
            "Classify a shell command as allow, prompt, or forbidden with JEV "
            "(TypeSafe Choice) and a fail-closed decision layer."
        ),
    )
    parser.add_argument("argv", nargs="*", help="command and arguments after --")
    parser.add_argument("--command", help="raw shell command string to classify")
    parser.add_argument("--cwd", help="working directory for context")
    parser.add_argument(
        "--sandbox",
        default=os.environ.get("CODEX_SANDBOX_MODE", "unknown"),
        help="Codex sandbox mode for context (default: $CODEX_SANDBOX_MODE or unknown)",
    )
    parser.add_argument(
        "--network",
        choices=("on", "off", "unknown"),
        default="unknown",
        help="whether commands have network access",
    )
    parser.add_argument(
        "--matched-rule",
        action="append",
        default=[],
        metavar="DECISION:PATTERN",
        help="matched execpolicy rule, repeatable (for example allow:git status)",
    )
    parser.add_argument("--model", default=DEFAULT_MODEL)
    parser.add_argument("--endpoint", default=DEFAULT_ENDPOINT)
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    parser.add_argument("--no-retry", action="store_true")
    parser.add_argument(
        "--confidence-floor", type=float, default=CONFIDENCE_FLOOR
    )
    parser.add_argument(
        "--forbidden-ceiling", type=float, default=FORBIDDEN_MASS_CEILING
    )
    parser.add_argument(
        "--offline",
        action="store_true",
        help="use the deterministic heuristic instead of calling JEV (testing only)",
    )
    parser.add_argument(
        "--text", action="store_true", help="human-readable output instead of JSON"
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="run deterministic self-tests and exit",
    )
    return parser


def _threshold_error(args: argparse.Namespace) -> Optional[str]:
    """Reject threshold overrides that could make an unsafe answer ``allow``.

    Values must be finite and within ``[0, 1]``, and the CLI only accepts
    tightening: a lower ``--confidence-floor`` or a higher
    ``--forbidden-ceiling`` than the production defaults is refused. Looser
    thresholds belong in a labeled evaluation, not in a live invocation.
    """
    for name, value in (
        ("--confidence-floor", args.confidence_floor),
        ("--forbidden-ceiling", args.forbidden_ceiling),
    ):
        if not math.isfinite(value) or not 0.0 <= value <= 1.0:
            return f"{name} must be a finite number in [0, 1], got {value!r}"
    if args.confidence_floor < CONFIDENCE_FLOOR:
        return (
            f"--confidence-floor may only tighten the default "
            f"{CONFIDENCE_FLOOR}, got {args.confidence_floor!r}"
        )
    if args.forbidden_ceiling > FORBIDDEN_MASS_CEILING:
        return (
            f"--forbidden-ceiling may only tighten the default "
            f"{FORBIDDEN_MASS_CEILING}, got {args.forbidden_ceiling!r}"
        )
    return None


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.self_test:
        return _self_test()

    threshold_error = _threshold_error(args)
    if threshold_error:
        parser.error(threshold_error)

    if args.command and args.argv:
        parser.error("pass either --command or trailing argv, not both")
    if not args.command and not args.argv:
        parser.error("provide a command: --command '<script>' or -- <argv...>")

    raw = args.command
    command_argv = list(args.argv)
    if raw and not command_argv:
        try:
            command_argv = shlex.split(raw)
        except ValueError:
            command_argv = []

    matched_rules = []
    for rule in args.matched_rule:
        decision, _, pattern = rule.partition(":")
        matched_rules.append({"decision": decision or "unknown", "pattern": pattern})

    if args.offline:
        result = _offline_classify(raw, command_argv, matched_rules)
        result["model"] = "offline-heuristic"
    else:
        from .classifier import classify_command

        result = classify_command(
            command_argv,
            raw=raw,
            cwd=args.cwd,
            sandbox_mode=args.sandbox,
            network=None if args.network == "unknown" else args.network,
            matched_rules=matched_rules,
            confidence_floor=args.confidence_floor,
            forbidden_mass_ceiling=args.forbidden_ceiling,
            client_evaluate=lambda state, questions: _evaluate(
                state, questions, args
            ),
        )
        result["source"] = "jev"

    # Audit-facing output only ever contains redacted command data.
    result["command"] = redact(raw or " ".join(command_argv))
    for segment in result.get("segments", []):
        if isinstance(segment.get("argv"), list):
            segment["argv"] = redact_argv(segment["argv"])
    decision = result["decision"]

    if args.text:
        print(f"decision: {decision}")
        for reason in result.get("reasons", []):
            print(f"  - {reason}")
        for segment in result.get("segments", []):
            print(f"  segment {segment['argv']}: {segment['decision']}")
    else:
        print(json.dumps(result, indent=2, sort_keys=True))

    if result.get("segments") and any(
        "classifier failure" in reason for reason in result.get("reasons", [])
    ):
        return 3
    return EXIT_CODES.get(decision, 3)


def _evaluate(state, questions, args):
    from .client import evaluate

    return evaluate(
        state,
        questions,
        model=args.model,
        endpoint=args.endpoint,
        timeout=args.timeout,
        retries=0 if args.no_retry else 2,
    )


if __name__ == "__main__":
    sys.exit(main())
