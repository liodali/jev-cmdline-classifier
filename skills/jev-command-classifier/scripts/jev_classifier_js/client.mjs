/**
 * Minimal client for the TypeSafe System One API (no dependencies).
 *
 * Uses the global fetch available in Node 18+ and Bun. API reference:
 * https://docs.typesafe.ai/api
 */

export const DEFAULT_ENDPOINT = "https://api.typesafe.ai/v1/systemone";
export const DEFAULT_MODEL = "jev-latest";
export const DEFAULT_TIMEOUT_MS = 10_000;
export const DEFAULT_RETRIES = 2;
export const API_KEY_ENV = "TYPESAFE_API_KEY";

/** Transient failures worth retrying with backoff. */
const RETRY_STATUS = new Set([429, 500, 502, 503, 529]);

export class TypeSafeError extends Error {
  constructor(message, options) {
    super(message, options);
    this.name = "TypeSafeError";
  }
}

export class TypeSafeAuthError extends TypeSafeError {
  constructor(message, options) {
    super(message, options);
    this.name = "TypeSafeAuthError";
  }
}

/** Return TYPESAFE_API_KEY, or throw TypeSafeAuthError when unset. */
export function apiKeyFromEnv(env = process.env) {
  const key = (env[API_KEY_ENV] ?? "").trim();
  if (!key) {
    throw new TypeSafeAuthError(
      `${API_KEY_ENV} is not set; create a key at https://console.typesafe.ai/keys`,
    );
  }
  return key;
}

const defaultSleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/**
 * POST `state` and `questions` to TypeSafe and return the parsed response.
 *
 * Retries transient failures (429, 5xx, network errors, timeouts) with
 * exponential backoff. Authentication and validation failures are never
 * retried. Callers must fail closed on any error.
 */
export async function evaluate(
  state,
  questions,
  {
    apiKey,
    model = DEFAULT_MODEL,
    endpoint = DEFAULT_ENDPOINT,
    timeoutMs = DEFAULT_TIMEOUT_MS,
    retries = DEFAULT_RETRIES,
    sleep = defaultSleep,
    fetchImpl = fetch,
  } = {},
) {
  const key = apiKey || apiKeyFromEnv();
  const payload = JSON.stringify({ state, model, questions });
  const headers = {
    Authorization: `Bearer ${key}`,
    "Content-Type": "application/json",
    "User-Agent": "jev-command-classifier-js/0.1",
  };

  let lastError = null;
  for (let attempt = 0; attempt <= retries; attempt += 1) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    let response = null;
    try {
      response = await fetchImpl(endpoint, {
        method: "POST",
        headers,
        body: payload,
        signal: controller.signal,
      });
    } catch (error) {
      lastError = new TypeSafeError(
        `TypeSafe request failed: ${error?.message ?? error}`,
      );
    } finally {
      clearTimeout(timer);
    }

    if (response) {
      let body = "";
      try {
        body = await response.text();
      } catch {
        // A body read failure is treated like an empty body below.
      }
      if (response.status === 401) {
        throw new TypeSafeAuthError(
          `TypeSafe rejected the API key (401): ${body.slice(0, 200)}`,
        );
      }
      if (response.ok) {
        try {
          return JSON.parse(body);
        } catch (error) {
          lastError = new TypeSafeError(
            `TypeSafe returned invalid JSON: ${error.message}`,
          );
        }
      } else if (!RETRY_STATUS.has(response.status)) {
        throw new TypeSafeError(
          `TypeSafe request failed with HTTP ${response.status}: ${body.slice(0, 200)}`,
        );
      } else {
        lastError = new TypeSafeError(
          `HTTP ${response.status}: ${body.slice(0, 200)}`,
        );
      }
    }

    if (attempt < retries) {
      await sleep(Math.min(500 * 2 ** attempt, 4000));
    }
  }

  throw new TypeSafeError(
    `TypeSafe request failed after ${retries + 1} attempts: ${lastError?.message ?? "unknown error"}`,
  );
}
