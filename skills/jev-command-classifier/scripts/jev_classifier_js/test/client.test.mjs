/**
 * Client tests against a local fake TypeSafe server (no API key needed).
 */

import assert from "node:assert/strict";
import { createServer } from "node:http";
import test from "node:test";

import {
  TypeSafeAuthError,
  TypeSafeError,
  apiKeyFromEnv,
  evaluate,
  resolveKey,
  resolveProvider,
} from "../client.mjs";

const QUESTION = {
  risk: { type: "choice", instructions: "?", criteria: { a: null, b: null } },
};
const ANSWER = {
  model: "jev-1.13.0",
  answers: {
    risk: {
      type: "choice",
      choice: "a",
      confidence: 1.0,
      probabilities: { a: 1.0, b: 0.0 },
    },
  },
  usage: { input_tokens: 10, output_tokens: 5 },
};

/** Start a fake server and return its endpoint, queued responses, and requests. */
function startFakeServer() {
  const state = { requests: [], responses: [] };
  const server = createServer((request, response) => {
    let body = "";
    request.on("data", (chunk) => {
      body += chunk;
    });
    request.on("end", () => {
      let parsed = body;
      try {
        parsed = JSON.parse(body);
      } catch {
        // keep the raw body
      }
      state.requests.push({ path: request.url, headers: request.headers, body: parsed });
      const next = state.responses.shift() ?? {
        status: 500,
        payload: { error: "no queued response" },
      };
      const encoded = JSON.stringify(next.payload);
      response.writeHead(next.status, {
        "Content-Type": "application/json",
        "Content-Length": Buffer.byteLength(encoded),
      });
      response.end(encoded);
    });
  });

  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address();
      resolve({
        state,
        endpoint: `http://127.0.0.1:${port}/v1/systemone`,
        close: () => new Promise((done) => server.close(done)),
      });
    });
  });
}

const noSleep = async () => {};

test("successful request", async () => {
  const server = await startFakeServer();
  try {
    server.state.responses.push({ status: 200, payload: ANSWER });
    const response = await evaluate(
      { command: { argv: ["ls"] } },
      QUESTION,
      { apiKey: "test-key", endpoint: server.endpoint, sleep: noSleep },
    );
    assert.equal(response.answers.risk.choice, "a");

    const request = server.state.requests[0];
    assert.equal(request.headers.authorization, "Bearer test-key");
    assert.equal(request.body.model, "jev-latest");
    assert.ok(request.body.questions.risk);
  } finally {
    await server.close();
  }
});

test("401 raises an auth error without retrying", async () => {
  const server = await startFakeServer();
  try {
    server.state.responses.push({ status: 401, payload: { error: "unauthorized" } });
    await assert.rejects(
      evaluate({}, QUESTION, {
        apiKey: "bad",
        endpoint: server.endpoint,
        sleep: noSleep,
      }),
      TypeSafeAuthError,
    );
    assert.equal(server.state.requests.length, 1);
  } finally {
    await server.close();
  }
});

test("422 raises without retrying", async () => {
  const server = await startFakeServer();
  try {
    server.state.responses.push({ status: 422, payload: { error: "invalid" } });
    await assert.rejects(
      evaluate({}, QUESTION, {
        apiKey: "k",
        endpoint: server.endpoint,
        sleep: noSleep,
      }),
      TypeSafeError,
    );
    assert.equal(server.state.requests.length, 1);
  } finally {
    await server.close();
  }
});

test("transient failure is retried then succeeds", async () => {
  const server = await startFakeServer();
  try {
    server.state.responses.push({ status: 529, payload: { error: "overloaded" } });
    server.state.responses.push({ status: 200, payload: ANSWER });
    const response = await evaluate({}, QUESTION, {
      apiKey: "k",
      endpoint: server.endpoint,
      sleep: noSleep,
    });
    assert.equal(response.model, "jev-1.13.0");
    assert.equal(server.state.requests.length, 2);
  } finally {
    await server.close();
  }
});

test("exhausted retries raise", async () => {
  const server = await startFakeServer();
  try {
    server.state.responses.push({ status: 500, payload: { error: "boom" } });
    server.state.responses.push({ status: 500, payload: { error: "boom" } });
    await assert.rejects(
      evaluate({}, QUESTION, {
        apiKey: "k",
        endpoint: server.endpoint,
        retries: 1,
        sleep: noSleep,
      }),
      TypeSafeError,
    );
    assert.equal(server.state.requests.length, 2);
  } finally {
    await server.close();
  }
});

test("missing key raises", () => {
  assert.throws(() => apiKeyFromEnv({}), TypeSafeAuthError);
  assert.equal(apiKeyFromEnv({ TYPESAFE_API_KEY: " abc " }), "abc");
});

test("gateway uses System One contract", async () => {
  const server = await startFakeServer();
  try {
    server.state.responses.push({ status: 200, payload: ANSWER });
    const response = await evaluate(
      { command: { argv: ["git", "status"] } },
      QUESTION,
      {
        provider: "systemone-compatible",
        endpoint: server.endpoint,
        apiKey: "gateway-key",
        sleep: noSleep,
      },
    );
    assert.equal(response.answers.risk.choice, "a");
    const request = server.state.requests[0];
    assert.equal(request.headers.authorization, "Bearer gateway-key");
    assert.equal(request.body.model, "jev-latest");
    assert.ok(request.body.state);
    assert.ok(request.body.questions);
    assert.equal(request.body.messages, undefined);
  } finally {
    await server.close();
  }
});

test("gateway contract without network", async () => {
  let sent;
  const result = await evaluate({}, QUESTION, {
    provider: "systemone-compatible",
    endpoint: "https://gateway.example/v1/systemone",
    apiKey: "gateway-key",
    fetchImpl: async (_url, options) => {
      sent = options;
      return new Response(JSON.stringify(ANSWER), { status: 200 });
    },
  });
  assert.equal(result.answers.risk.choice, "a");
  assert.deepEqual(Object.keys(JSON.parse(sent.body)).sort(), ["model", "questions", "state"]);
  assert.equal(sent.headers.Authorization, "Bearer gateway-key");
});

test("chat response is not translated into Choice answers", async () => {
  const server = await startFakeServer();
  try {
    server.state.responses.push({
      status: 200,
      payload: { model: "jev-latest", choices: [{ message: { content: '{"choice":"allow"}' } }] },
    });
    await assert.rejects(
      evaluate({}, QUESTION, {
        provider: "systemone-compatible",
        endpoint: server.endpoint,
        apiKey: "k",
        sleep: noSleep,
      }),
      TypeSafeError,
    );
  } finally {
    await server.close();
  }
});

test("non-JEV response model is rejected", async () => {
  const server = await startFakeServer();
  try {
    server.state.responses.push({ status: 200, payload: { ...ANSWER, model: "gpt-4o" } });
    await assert.rejects(
      evaluate({}, QUESTION, {
        provider: "systemone-compatible",
        endpoint: server.endpoint,
        apiKey: "k",
        sleep: noSleep,
      }),
      TypeSafeError,
    );
  } finally {
    await server.close();
  }
});

test("resolveProvider restricts providers and requires gateway endpoint", () => {
  const defaults = resolveProvider({ env: {} });
  assert.equal(defaults.provider, "typesafe");
  assert.equal(defaults.model, "jev-latest");
  assert.equal(defaults.keyEnv, "TYPESAFE_API_KEY");
  for (const provider of ["openai", "openrouter", "openai-compatible"]) {
    assert.throws(() => resolveProvider({ provider, env: {} }), TypeSafeError);
  }
  assert.throws(
    () => resolveProvider({ provider: "systemone-compatible", env: {} }),
    TypeSafeError,
  );
  const gateway = resolveProvider({
    provider: "systemone-compatible",
    endpoint: "https://gateway.example/v1/systemone",
    env: {},
  });
  assert.equal(gateway.keyEnv, "JEV_API_KEY");
  const keyless = resolveProvider({
    provider: "systemone-compatible",
    endpoint: "https://gateway.example/v1/systemone",
    apiKeyEnv: "none",
    env: {},
  });
  assert.equal(resolveKey(keyless, {}), null);
  assert.throws(() => resolveProvider({ model: "gpt-4o", env: {} }), TypeSafeError);
});

test("TypeSafe key is not sent to an override endpoint implicitly", async () => {
  await assert.rejects(
    evaluate({}, QUESTION, {
      endpoint: "https://gateway.example/v1/systemone",
      env: { TYPESAFE_API_KEY: "secret" },
      fetchImpl: async () => { throw new Error("must not send request"); },
    }),
    /refusing to send TYPESAFE_API_KEY/,
  );
});
