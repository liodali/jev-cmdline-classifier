/**
 * Client for TypeSafe's JEV System One Choice API, directly or through a
 * trusted provider forwarding the same protocol without model substitution.
 *
 * Uses the global fetch available in Node 18+ and Bun. TypeSafe API reference:
 * https://docs.typesafe.ai/api
 *
 * Providers are selected with `--provider` / $JEV_PROVIDER. Every provider
 * must forward to TypeSafe's JEV model; a `jev-` name is not provenance proof.
 */

export const DEFAULT_ENDPOINT = "https://api.typesafe.ai/v1/systemone";
export const DEFAULT_MODEL = "jev-latest";
export const DEFAULT_TIMEOUT_MS = 10_000;
export const DEFAULT_RETRIES = 2;
export const API_KEY_ENV = "TYPESAFE_API_KEY";
export const JEV_MODEL_PREFIX = "jev-";

// Provider selection and overrides. Flags win over these environment values.
export const PROVIDER_ENV = "JEV_PROVIDER";
export const ENDPOINT_ENV = "JEV_ENDPOINT";
export const MODEL_ENV = "JEV_MODEL";
export const GENERIC_KEY_ENV = "JEV_API_KEY";

// A custom provider is a trusted System One gateway, not another model host.
export const PROVIDERS = {
  typesafe: { endpoint: DEFAULT_ENDPOINT, keyEnv: API_KEY_ENV, model: DEFAULT_MODEL },
  "systemone-compatible": {
    endpoint: null,
    keyEnv: GENERIC_KEY_ENV,
    model: DEFAULT_MODEL,
  },
};

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

/** Return a model id only when it names a JEV model. */
export function validateJevModel(model) {
  if (typeof model !== "string") {
    throw new TypeSafeError("model must be a JEV model id beginning with 'jev-'");
  }
  const value = model.trim();
  if (!value.startsWith(JEV_MODEL_PREFIX) || value.length === JEV_MODEL_PREFIX.length) {
    throw new TypeSafeError(
      `model '${model}' is not a JEV model id; expected a name beginning with 'jev-'`,
    );
  }
  if (/\s/.test(value)) {
    throw new TypeSafeError(`model '${model}' must not contain whitespace`);
  }
  return value;
}

/** Return the API key stored in `envVar`, or throw when unset. */
export function apiKeyFromEnv(env = process.env, envVar = API_KEY_ENV) {
  const key = (env[envVar] ?? "").trim();
  if (!key) {
    const hint =
      envVar === API_KEY_ENV
        ? "create a key at https://console.typesafe.ai/keys"
        : "put the provider's API key in this variable";
    throw new TypeSafeAuthError(`${envVar} is not set; ${hint}`);
  }
  return key;
}

// Keyless trusted gateways ignore
// Authorization; the sentinel variable name `none` opts out of the header.
const KEYLESS_SENTINELS = new Set(["none", "off", "no", ""]);

/** Return the API key, or null when the provider runs without one. */
export function resolveKey(config, env = process.env) {
  if (KEYLESS_SENTINELS.has(String(config.keyEnv).trim().toLowerCase())) return null;
  return apiKeyFromEnv(env, config.keyEnv);
}

function authHeaders(key, userAgent) {
  const headers = {
    "Content-Type": "application/json",
    "User-Agent": userAgent,
  };
  if (key) headers.Authorization = `Bearer ${key}`;
  return headers;
}

/**
 * Resolve provider, endpoint, model, and key-variable name.
 *
 * Precedence for every field: explicit argument, then its environment
 * variable, then the provider's built-in default. Throws for an unknown
 * provider or an under-specified one.
 */
export function resolveProvider({
  provider,
  model,
  endpoint,
  apiKeyEnv,
  env = process.env,
} = {}) {
  const name = String(provider || env[PROVIDER_ENV] || "typesafe").trim().toLowerCase();
  const spec = PROVIDERS[name];
  if (!spec) {
    throw new TypeSafeError(
      `unknown provider '${name}'; expected one of ${Object.keys(PROVIDERS).join(", ")}`,
    );
  }

  const resolvedEndpoint = endpoint || env[ENDPOINT_ENV] || spec.endpoint;
  const resolvedModel = validateJevModel(model || env[MODEL_ENV] || spec.model);
  if (!resolvedEndpoint) {
    throw new TypeSafeError(
      `provider '${name}' needs an endpoint (pass --endpoint or set $${ENDPOINT_ENV})`,
    );
  }

  const genericKey = (env[GENERIC_KEY_ENV] ?? "").trim();
  const keyEnv = apiKeyEnv || (genericKey ? GENERIC_KEY_ENV : spec.keyEnv);
  return { provider: name, endpoint: resolvedEndpoint, model: resolvedModel, keyEnv };
}

const defaultSleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/**
 * POST the payload and return the response body text, retrying transient
 * failures with exponential backoff. 401 and non-retryable 4xx throw.
 */
async function postWithRetries({
  endpoint,
  payload,
  headers,
  provider,
  timeoutMs,
  retries,
  sleep = defaultSleep,
  fetchImpl = fetch,
}) {
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
      lastError = new TypeSafeError(`${provider} request failed: ${error?.message ?? error}`);
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
          `${provider} rejected the API key (401): ${body.slice(0, 200)}`,
        );
      }
      if (response.ok) return body;
      if (!RETRY_STATUS.has(response.status)) {
        throw new TypeSafeError(
          `${provider} request failed with HTTP ${response.status}: ${body.slice(0, 200)}`,
        );
      }
      lastError = new TypeSafeError(`HTTP ${response.status}: ${body.slice(0, 200)}`);
    }

    if (attempt < retries) {
      await sleep(Math.min(500 * 2 ** attempt, 4000));
    }
  }

  throw new TypeSafeError(
    `${provider} request failed after ${retries + 1} attempts: ${lastError?.message ?? "unknown error"}`,
  );
}

/**
 * Ask the configured provider to answer `questions` for `state`.
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
    model,
    endpoint,
    provider,
    apiKeyEnv,
    timeoutMs = DEFAULT_TIMEOUT_MS,
    retries = DEFAULT_RETRIES,
    sleep = defaultSleep,
    fetchImpl = fetch,
    env = process.env,
  } = {},
) {
  const config = resolveProvider({ provider, model, endpoint, apiKeyEnv, env });
  if (
    config.provider === "typesafe" &&
    config.endpoint !== DEFAULT_ENDPOINT &&
    config.keyEnv === API_KEY_ENV &&
    apiKey == null
  ) {
    throw new TypeSafeError(
      "refusing to send TYPESAFE_API_KEY to a custom endpoint; select systemone-compatible and a gateway key, or explicitly choose --api-key-env",
    );
  }
  const key = apiKey ?? resolveKey(config, env);
  const headers = authHeaders(key, "jev-command-classifier-js/0.1");

  const body = await postWithRetries({
    endpoint: config.endpoint,
    payload: JSON.stringify({ state, model: config.model, questions }),
    headers,
    provider: config.provider,
    timeoutMs,
    retries,
    sleep,
    fetchImpl,
  });
  let parsed;
  try {
    parsed = JSON.parse(body);
  } catch (error) {
    throw new TypeSafeError(`${config.provider} returned invalid JSON: ${error.message}`);
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new TypeSafeError(`${config.provider} returned a non-object response`);
  }
  validateJevModel(parsed.model);
  if (parsed.answers === null || typeof parsed.answers !== "object" || Array.isArray(parsed.answers)) {
    throw new TypeSafeError(`${config.provider} returned no System One answers object`);
  }
  return parsed;
}
