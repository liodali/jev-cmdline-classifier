"""Stdlib client for TypeSafe's JEV System One Choice API, directly or via a
trusted provider that forwards the same protocol without substituting a model.
No chat-completions translation is permitted. API: https://docs.typesafe.ai/api
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from typing import Any, Mapping, Optional

DEFAULT_ENDPOINT = "https://api.typesafe.ai/v1/systemone"
DEFAULT_MODEL = "jev-latest"
DEFAULT_TIMEOUT = 10.0
DEFAULT_RETRIES = 2
API_KEY_ENV = "TYPESAFE_API_KEY"
JEV_MODEL_PREFIX = "jev-"

# Provider selection and overrides. Flags win over these environment values.
PROVIDER_ENV = "JEV_PROVIDER"
ENDPOINT_ENV = "JEV_ENDPOINT"
MODEL_ENV = "JEV_MODEL"
GENERIC_KEY_ENV = "JEV_API_KEY"

# A custom provider is a trusted System One gateway, not another model host.
PROVIDERS: Mapping[str, Mapping[str, Any]] = {
    "typesafe": {
        "endpoint": DEFAULT_ENDPOINT,
        "key_env": API_KEY_ENV,
        "model": DEFAULT_MODEL,
    },
    "systemone-compatible": {
        "endpoint": None,
        "key_env": GENERIC_KEY_ENV,
        "model": DEFAULT_MODEL,
    },
}

# Transient failures worth retrying with backoff.
RETRY_STATUS = frozenset({429, 500, 502, 503, 529})


class TypeSafeError(RuntimeError):
    """A classifier-provider request failed in a way the caller must handle."""


class TypeSafeAuthError(TypeSafeError):
    """The API key is missing or was rejected."""


def validate_jev_model(model: Any) -> str:
    """Return a model id only when it names a JEV model.

    This is an input check, not proof of model provenance. A custom endpoint
    must be trusted to forward the request to TypeSafe's actual JEV model.
    """
    if not isinstance(model, str):
        raise TypeSafeError("model must be a JEV model id beginning with 'jev-'")
    value = model.strip()
    if not value.startswith(JEV_MODEL_PREFIX) or len(value) == len(JEV_MODEL_PREFIX):
        raise TypeSafeError(
            f"model {model!r} is not a JEV model id; expected a name beginning with 'jev-'"
        )
    if any(character.isspace() for character in value):
        raise TypeSafeError(f"model {model!r} must not contain whitespace")
    return value


def api_key_from_env(env: Optional[Mapping[str, str]] = None, env_var: str = API_KEY_ENV) -> str:
    """Return the API key stored in ``env_var``, or raise when unset."""
    source = os.environ if env is None else env
    key = (source.get(env_var) or "").strip()
    if not key:
        hint = (
            "create a key at https://console.typesafe.ai/keys"
            if env_var == API_KEY_ENV
            else "put the provider's API key in this variable"
        )
        raise TypeSafeAuthError(f"{env_var} is not set; {hint}")
    return key


# Keyless trusted gateways ignore
# Authorization; the sentinel variable name ``none`` opts out of the header.
KEYLESS_SENTINELS = frozenset({"none", "off", "no", ""})


def _resolve_key(config: Mapping[str, Any], env: Optional[Mapping[str, str]]) -> Optional[str]:
    """Return the API key, or None when the provider runs without one."""
    if config["key_env"].strip().lower() in KEYLESS_SENTINELS:
        return None
    return api_key_from_env(env, config["key_env"])


def resolve_provider(
    provider: Optional[str] = None,
    model: Optional[str] = None,
    endpoint: Optional[str] = None,
    api_key_env: Optional[str] = None,
    env: Optional[Mapping[str, str]] = None,
) -> dict:
    """Resolve provider, endpoint, model, and key-variable name.

    Precedence for every field: explicit argument, then its environment
    variable, then the provider's built-in default. Raises TypeSafeError for
    an unknown provider or an under-specified one.
    """
    source = os.environ if env is None else env
    name = str(provider or source.get(PROVIDER_ENV) or "typesafe").strip().lower()
    spec = PROVIDERS.get(name)
    if spec is None:
        raise TypeSafeError(
            f"unknown provider {name!r}; expected one of {', '.join(sorted(PROVIDERS))}"
        )

    resolved_endpoint = endpoint or source.get(ENDPOINT_ENV) or spec["endpoint"]
    resolved_model = validate_jev_model(model or source.get(MODEL_ENV) or spec["model"])
    if not resolved_endpoint:
        raise TypeSafeError(
            f"provider {name!r} needs an endpoint (pass --endpoint or set ${ENDPOINT_ENV})"
        )

    generic_key = (source.get(GENERIC_KEY_ENV) or "").strip()
    key_env = api_key_env or (GENERIC_KEY_ENV if generic_key else spec["key_env"])
    return {
        "provider": name,
        "endpoint": resolved_endpoint,
        "model": resolved_model,
        "key_env": key_env,
    }


def evaluate(
    state: Any,
    questions: Mapping[str, Any],
    *,
    api_key: Optional[str] = None,
    model: Optional[str] = None,
    endpoint: Optional[str] = None,
    provider: Optional[str] = None,
    api_key_env: Optional[str] = None,
    timeout: float = DEFAULT_TIMEOUT,
    retries: int = DEFAULT_RETRIES,
    sleep=time.sleep,
    env: Optional[Mapping[str, str]] = None,
) -> dict:
    """Ask the configured provider to answer ``questions`` for ``state``.

    Retries transient failures (429, 5xx, network errors) with exponential
    backoff. Authentication and validation failures are never retried.

    Returns the native System One response from the chosen endpoint.
    Raises TypeSafeAuthError for a missing or rejected
    key, TypeSafeError for everything else. Callers must fail closed on both.
    """
    config = resolve_provider(
        provider=provider,
        model=model,
        endpoint=endpoint,
        api_key_env=api_key_env,
        env=env,
    )
    if (
        config["provider"] == "typesafe"
        and config["endpoint"] != DEFAULT_ENDPOINT
        and config["key_env"] == API_KEY_ENV
        and api_key is None
    ):
        raise TypeSafeError(
            "refusing to send TYPESAFE_API_KEY to a custom endpoint; select "
            "systemone-compatible and a gateway key, or explicitly choose --api-key-env"
        )
    key = api_key if api_key is not None else _resolve_key(config, env)
    return _evaluate_typesafe(
        state,
        questions,
        key=key,
        model=config["model"],
        endpoint=config["endpoint"],
        provider=config["provider"],
        timeout=timeout,
        retries=retries,
        sleep=sleep,
    )


def _post_with_retries(
    *,
    endpoint: str,
    payload: bytes,
    headers: Mapping[str, str],
    provider: str,
    timeout: float,
    retries: int,
    sleep=time.sleep,
) -> str:
    """POST the payload and return the response body text, retrying transient
    failures with exponential backoff. 401 and non-retryable 4xx raise."""
    last_error: Optional[Exception] = None
    for attempt in range(retries + 1):
        request = urllib.request.Request(
            endpoint, data=payload, headers=dict(headers), method="POST"
        )
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                return response.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            try:
                body = exc.read().decode("utf-8", "replace")
            finally:
                exc.close()
            if exc.code == 401:
                raise TypeSafeAuthError(
                    f"{provider} rejected the API key (401): {body[:200]}"
                ) from exc
            if exc.code not in RETRY_STATUS:
                raise TypeSafeError(
                    f"{provider} request failed with HTTP {exc.code}: {body[:200]}"
                ) from exc
            last_error = TypeSafeError(f"HTTP {exc.code}: {body[:200]}")
        except urllib.error.URLError as exc:
            last_error = TypeSafeError(f"{provider} request failed: {exc.reason}")
        except (TimeoutError, json.JSONDecodeError) as exc:
            last_error = TypeSafeError(f"{provider} request failed: {exc}")

        if attempt < retries:
            sleep(min(0.5 * (2**attempt), 4.0))

    raise TypeSafeError(
        f"{provider} request failed after {retries + 1} attempts: {last_error}"
    )


def _auth_headers(key: Optional[str], user_agent: str) -> dict:
    headers = {
        "Content-Type": "application/json",
        "User-Agent": user_agent,
    }
    if key:
        headers["Authorization"] = f"Bearer {key}"
    return headers


def _evaluate_typesafe(
    state: Any,
    questions: Mapping[str, Any],
    *,
    key: Optional[str],
    model: str,
    endpoint: str,
    provider: str,
    timeout: float,
    retries: int,
    sleep,
) -> dict:
    """System One contract: POST state + questions, return the raw response."""
    payload = json.dumps(
        {"state": state, "model": model, "questions": dict(questions)}
    ).encode("utf-8")
    body = _post_with_retries(
        endpoint=endpoint,
        payload=payload,
        headers=_auth_headers(key, "jev-command-classifier/0.1"),
        provider=provider,
        timeout=timeout,
        retries=retries,
        sleep=sleep,
    )
    try:
        response = json.loads(body)
    except json.JSONDecodeError as exc:
        raise TypeSafeError(f"{provider} returned invalid JSON: {exc}") from exc
    if not isinstance(response, Mapping):
        raise TypeSafeError(f"{provider} returned a non-object response")
    validate_jev_model(response.get("model"))
    if not isinstance(response.get("answers"), Mapping):
        raise TypeSafeError(f"{provider} returned no System One answers object")
    return dict(response)
