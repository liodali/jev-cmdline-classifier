"""Parity tests: the Python and JavaScript implementations share these fixtures.

If a fixture fails here, the JavaScript self-test fails too; keep both in sync.
"""

from __future__ import annotations

import json
import unittest

from . import _paths

from jev_classifier.classifier import decide, hard_deny, redact_argv, split_simple

FIXTURES_PATH = _paths.SCRIPTS_DIR / "fixtures" / "cases.json"


class FixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixtures = json.loads(FIXTURES_PATH.read_text(encoding="utf-8"))

    def test_fixtures_cover_all_layers(self):
        for section in ("decide", "split", "hard_deny", "redact_argv"):
            with self.subTest(section=section):
                self.assertGreater(len(self.fixtures[section]), 0)

    def test_decide_fixtures(self):
        for case in self.fixtures["decide"]:
            with self.subTest(case=case["name"]):
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
                self.assertEqual(got, case["expected"])

    def test_split_fixtures(self):
        for case in self.fixtures["split"]:
            with self.subTest(command=case["command"]):
                self.assertEqual(split_simple(case["command"]), case["expected"])

    def test_hard_deny_fixtures(self):
        for case in self.fixtures["hard_deny"]:
            with self.subTest(case=case["name"]):
                got = hard_deny(case["argv"], raw=case["raw"])
                self.assertEqual(got is not None, case["expected"])

    def test_redact_argv_fixtures(self):
        for case in self.fixtures["redact_argv"]:
            with self.subTest(case=case["name"]):
                self.assertEqual(redact_argv(case["argv"]), case["expected"])


if __name__ == "__main__":
    unittest.main()
