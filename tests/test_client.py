"""Client tests against a local fake TypeSafe server (no API key needed)."""

from __future__ import annotations

import json
import unittest
from unittest import mock

from . import _paths  # noqa: F401

from jev_classifier.client import (
    TypeSafeAuthError,
    TypeSafeError,
    api_key_from_env,
    evaluate,
    JEV_MODEL_PREFIX,
    resolve_provider,
    validate_jev_model,
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


class GatewayTests(unittest.TestCase):
    def test_gateway_contract_without_network(self):
        response = mock.MagicMock()
        response.read.return_value = json.dumps(ANSWER).encode()
        response.__enter__.return_value = response
        with mock.patch("jev_classifier.client.urllib.request.urlopen", return_value=response) as opener:
            result = evaluate(
                {"command": {"argv": ["git", "status"]}}, QUESTION,
                provider="systemone-compatible",
                endpoint="https://gateway.example/v1/systemone",
                api_key="gateway-key",
            )
        self.assertEqual(result["answers"]["risk"]["choice"], "a")
        request = opener.call_args.args[0]
        payload = json.loads(request.data)
        self.assertEqual(set(payload), {"state", "model", "questions"})
        self.assertEqual(request.get_header("Authorization"), "Bearer gateway-key")

    def test_gateway_uses_systemone_contract(self):
        with FakeTypeSafe() as server:
            server.enqueue_json(200, ANSWER)
            response = evaluate(
                {"command": {"argv": ["git", "status"]}},
                QUESTION,
                provider="systemone-compatible",
                endpoint=server.endpoint,
                api_key="gateway-key",
                sleep=lambda _: None,
            )
            self.assertEqual(response["answers"]["risk"]["choice"], "a")
            request = server.requests[0]
            self.assertEqual(request["headers"]["Authorization"], "Bearer gateway-key")
            self.assertEqual(request["body"]["model"], "jev-latest")
            self.assertIn("state", request["body"])
            self.assertIn("questions", request["body"])
            self.assertNotIn("messages", request["body"])

    def test_chat_response_is_not_translated(self):
        with FakeTypeSafe() as server:
            server.enqueue_json(200, {
                "model": "jev-latest",
                "choices": [{"message": {"content": '{"choice":"allow"}'}}],
            })
            with self.assertRaises(TypeSafeError):
                evaluate(
                    {}, QUESTION, provider="systemone-compatible",
                    endpoint=server.endpoint, api_key="k", sleep=lambda _: None,
                )

    def test_gateway_requires_endpoint_and_its_own_key(self):
        with self.assertRaises(TypeSafeError):
            resolve_provider(provider="systemone-compatible", env={})
        config = resolve_provider(
            provider="systemone-compatible",
            endpoint="https://gateway.example/v1/systemone",
            env={},
        )
        self.assertEqual(config["key_env"], "JEV_API_KEY")
        with self.assertRaises(TypeSafeAuthError):
            evaluate(
                {}, QUESTION, provider="systemone-compatible",
                endpoint="https://gateway.example/v1/systemone", env={}, sleep=lambda _: None,
            )

    def test_non_jev_response_model_is_rejected(self):
        with FakeTypeSafe() as server:
            server.enqueue_json(200, {**ANSWER, "model": "gpt-4o"})
            with self.assertRaises(TypeSafeError):
                evaluate(
                    {}, QUESTION, provider="systemone-compatible",
                    endpoint=server.endpoint, api_key="k", sleep=lambda _: None,
                )


class ResolveProviderTests(unittest.TestCase):
    def test_typesafe_key_not_sent_to_override_endpoint_implicitly(self):
        with self.assertRaisesRegex(TypeSafeError, "refusing to send TYPESAFE_API_KEY"):
            evaluate(
                {}, QUESTION,
                endpoint="https://gateway.example/v1/systemone",
                env={"TYPESAFE_API_KEY": "secret"},
            )

    def test_defaults_and_overrides(self):
        config = resolve_provider(env={})
        self.assertEqual(config["provider"], "typesafe")
        self.assertEqual(config["model"], "jev-latest")
        self.assertEqual(config["key_env"], "TYPESAFE_API_KEY")
        config = resolve_provider(
            env={"JEV_PROVIDER": "systemone-compatible", "JEV_ENDPOINT": "https://gateway.example/v1/systemone"}
        )
        self.assertEqual(config["provider"], "systemone-compatible")
        self.assertEqual(config["key_env"], "JEV_API_KEY")
        self.assertEqual(config["endpoint"], "https://gateway.example/v1/systemone")
        self.assertEqual(validate_jev_model("jev-1.13.0"), "jev-1.13.0")
        self.assertEqual(JEV_MODEL_PREFIX, "jev-")

    def test_chat_provider_and_non_jev_model_are_rejected(self):
        for provider in ("openai", "openrouter", "openai-compatible"):
            with self.subTest(provider=provider), self.assertRaises(TypeSafeError):
                resolve_provider(provider=provider, env={})
        with self.assertRaises(TypeSafeError):
            resolve_provider(model="gpt-4o", env={})

    def test_gateway_explicit_key_env(self):
        config = resolve_provider(
            provider="systemone-compatible",
            model="jev-1.13.0",
            endpoint="https://gateway.example/v1/systemone",
            api_key_env="MY_GATEWAY_KEY",
            env={},
        )
        self.assertEqual(config["key_env"], "MY_GATEWAY_KEY")
        self.assertEqual(config["model"], "jev-1.13.0")
if __name__ == "__main__":
    unittest.main()
