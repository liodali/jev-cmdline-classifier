"""Client tests against a local fake TypeSafe server (no API key needed)."""

from __future__ import annotations

import unittest

from . import _paths  # noqa: F401

from jev_classifier.client import (
    TypeSafeAuthError,
    TypeSafeError,
    api_key_from_env,
    evaluate,
)

from .fake_typesafe import FakeTypeSafe

QUESTION = {"risk": {"type": "choice", "instructions": "?", "criteria": {"a": None, "b": None}}}
ANSWER = {
    "model": "jev-1.13.0",
    "answers": {"risk": {"type": "choice", "choice": "a", "confidence": 1.0, "probabilities": {"a": 1.0, "b": 0.0}}},
    "usage": {"input_tokens": 10, "output_tokens": 5},
}


class EvaluateTests(unittest.TestCase):
    def test_successful_request(self):
        with FakeTypeSafe() as server:
            server.enqueue_json(200, ANSWER)
            response = evaluate(
                {"command": {"argv": ["ls"]}},
                QUESTION,
                api_key="test-key",
                endpoint=server.endpoint,
                sleep=lambda _: None,
            )
            self.assertEqual(response["answers"]["risk"]["choice"], "a")

            request = server.requests[0]
            self.assertEqual(request["headers"]["Authorization"], "Bearer test-key")
            self.assertEqual(request["body"]["model"], "jev-latest")
            self.assertIn("risk", request["body"]["questions"])

    def test_401_raises_auth_error_without_retry(self):
        with FakeTypeSafe() as server:
            server.enqueue_json(401, {"error": "unauthorized"})
            with self.assertRaises(TypeSafeAuthError):
                evaluate({}, QUESTION, api_key="bad", endpoint=server.endpoint, sleep=lambda _: None)
            self.assertEqual(len(server.requests), 1)

    def test_422_raises_without_retry(self):
        with FakeTypeSafe() as server:
            server.enqueue_json(422, {"error": "invalid"})
            with self.assertRaises(TypeSafeError):
                evaluate({}, QUESTION, api_key="k", endpoint=server.endpoint, sleep=lambda _: None)
            self.assertEqual(len(server.requests), 1)

    def test_transient_failure_is_retried_then_succeeds(self):
        with FakeTypeSafe() as server:
            server.enqueue_json(529, {"error": "overloaded"})
            server.enqueue_json(200, ANSWER)
            response = evaluate(
                {},
                QUESTION,
                api_key="k",
                endpoint=server.endpoint,
                sleep=lambda _: None,
            )
            self.assertEqual(response["model"], "jev-1.13.0")
            self.assertEqual(len(server.requests), 2)

    def test_exhausted_retries_raise(self):
        with FakeTypeSafe() as server:
            server.enqueue_json(500, {"error": "boom"})
            server.enqueue_json(500, {"error": "boom"})
            with self.assertRaises(TypeSafeError):
                evaluate(
                    {},
                    QUESTION,
                    api_key="k",
                    endpoint=server.endpoint,
                    retries=1,
                    sleep=lambda _: None,
                )
            self.assertEqual(len(server.requests), 2)


class ApiKeyTests(unittest.TestCase):
    def test_missing_key_raises(self):
        with self.assertRaises(TypeSafeAuthError):
            api_key_from_env({})

    def test_key_is_read_from_env_mapping(self):
        self.assertEqual(api_key_from_env({"TYPESAFE_API_KEY": " abc "}), "abc")


if __name__ == "__main__":
    unittest.main()
