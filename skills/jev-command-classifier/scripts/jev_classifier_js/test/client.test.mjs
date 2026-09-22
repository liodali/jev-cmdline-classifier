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
