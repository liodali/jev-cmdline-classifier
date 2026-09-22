"""Minimal stdlib client for the TypeSafe System One API.

No third-party dependencies, so the skill script works anywhere Python 3.9+
is available. API reference: https://docs.typesafe.ai/api
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

# Transient failures worth retrying with backoff.
RETRY_STATUS = frozenset({429, 500, 502, 503, 529})


class TypeSafeError(RuntimeError):
    """A TypeSafe request failed in a way the caller must handle."""


class TypeSafeAuthError(TypeSafeError):
    """The API key is missing or was rejected."""


def api_key_from_env(env: Optional[Mapping[str, str]] = None) -> str:
    """Return TYPESAFE_API_KEY, or raise TypeSafeAuthError when unset."""
    source = os.environ if env is None else env
    key = (source.get(API_KEY_ENV) or "").strip()
    if not key:
        raise TypeSafeAuthError(
            f"{API_KEY_ENV} is not set; create a key at https://console.typesafe.ai/keys"
        )
    return key


def evaluate(
    state: Any,
    questions: Mapping[str, Any],
    *,
    api_key: Optional[str] = None,
    model: str = DEFAULT_MODEL,
    endpoint: str = DEFAULT_ENDPOINT,
    timeout: float = DEFAULT_TIMEOUT,
    retries: int = DEFAULT_RETRIES,
    sleep=time.sleep,
) -> dict:
    """POST ``state`` and ``questions`` to TypeSafe and return the response.

    Retries transient failures (429, 5xx, network errors) with exponential
    backoff. Authentication and validation failures are never retried.

    Raises TypeSafeAuthError for a missing or rejected key, TypeSafeError for
    everything else. Callers must fail closed on either.
    """
    key = api_key or api_key_from_env()
    payload = json.dumps(
        {"state": state, "model": model, "questions": dict(questions)}
    ).encode("utf-8")
    headers = {
        "Authorization": f"Bearer {key}",
        "Content-Type": "application/json",
        "User-Agent": "jev-command-classifier/0.1",
    }

    last_error: Optional[Exception] = None
    for attempt in range(retries + 1):
        request = urllib.request.Request(
            endpoint, data=payload, headers=headers, method="POST"
        )
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                return json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            try:
                body = exc.read().decode("utf-8", "replace")
            finally:
                exc.close()
            if exc.code == 401:
                raise TypeSafeAuthError(
                    f"TypeSafe rejected the API key (401): {body[:200]}"
                ) from exc
            if exc.code not in RETRY_STATUS:
                raise TypeSafeError(
                    f"TypeSafe request failed with HTTP {exc.code}: {body[:200]}"
                ) from exc
            last_error = TypeSafeError(f"HTTP {exc.code}: {body[:200]}")
        except urllib.error.URLError as exc:
            last_error = TypeSafeError(f"TypeSafe request failed: {exc.reason}")
        except (TimeoutError, json.JSONDecodeError) as exc:
            last_error = TypeSafeError(f"TypeSafe request failed: {exc}")

        if attempt < retries:
            sleep(min(0.5 * (2**attempt), 4.0))

    raise TypeSafeError(
        f"TypeSafe request failed after {retries + 1} attempts: {last_error}"
    )
