/**
 * Classifier tests, driven by the shared language-parity fixtures.
 */

import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  ALLOW,
  FORBIDDEN,
  PROMPT,
  buildState,
  classifyCommand,
  decide,
  hardDeny,
  matchedRuleFloor,
  mostRestrictive,
  redact,
  redactArgv,
  splitSimple,
} from "../classifier.mjs";

const fixtures = JSON.parse(
  await readFile(new URL("../../fixtures/cases.json", import.meta.url), "utf8"),
);

test("decide fixtures", () => {
  for (const testCase of fixtures.decide) {
    const options = {};
    if ("confidence_floor" in testCase) options.confidenceFloor = testCase.confidence_floor;
    const got = decide(testCase.choice, testCase.confidence, testCase.probabilities, {
      hardDenyReason: testCase.hard_deny_reason ?? null,
      ...options,
    }).decision;
    assert.equal(got, testCase.expected, `decide[${testCase.name}]`);
  }
});

test("split fixtures", () => {
  for (const testCase of fixtures.split) {
    assert.deepEqual(
      splitSimple(testCase.command),
      testCase.expected,
      `splitSimple(${JSON.stringify(testCase.command)})`,
    );
  }
});

test("hard-deny fixtures", () => {
  for (const testCase of fixtures.hard_deny) {
    const got = hardDeny(testCase.argv, testCase.raw);
    assert.equal(got !== null, testCase.expected, `hardDeny[${testCase.name}] -> ${got}`);
  }
});

test("mostRestrictive orders decisions", () => {
  assert.equal(mostRestrictive([ALLOW, PROMPT]), PROMPT);
  assert.equal(mostRestrictive([PROMPT, FORBIDDEN, ALLOW]), FORBIDDEN);
  assert.equal(mostRestrictive([]), ALLOW);
});

test("buildState includes context and omits raw by default", () => {
  const state = buildState(["git", "status"], {
    cwd: "/repo",
    sandboxMode: "workspace-write",
    network: "off",
    matchedRules: [{ decision: "prompt", pattern: "git push" }],
  });
  assert.deepEqual(state.command.argv, ["git", "status"]);
  assert.equal("raw" in state.command, false);
  assert.equal(state.context.sandbox_mode, "workspace-write");
  assert.equal(state.context.matched_rules[0].decision, "prompt");
});

test("classifyCommand fails closed when evaluate rejects", async () => {
  const record = await classifyCommand(["ls"], {
    evaluate: async () => {
      throw new Error("service down");
    },
  });
  assert.equal(record.decision, PROMPT);
  assert.match(record.reasons[0], /classifier failure/);
});

test("malformed probabilities fail closed", () => {
  const cases = [
    { allow: 1.0, forbidden: Number.NaN },
    { allow: 1.0, forbidden: Number.POSITIVE_INFINITY },
    { allow: 1.2, forbidden: 0.0 },
    { allow: 1.0, forbidden: -0.1 },
    { allow: 0.5, prompt: 0.2, forbidden: 0.0 },
  ];
  for (const probabilities of cases) {
    assert.equal(
      decide(ALLOW, 1.0, probabilities).decision,
      PROMPT,
      JSON.stringify(probabilities),
    );
  }
  assert.equal(decide(ALLOW, Number.NaN, { allow: 1.0, forbidden: 0.0 }).decision, PROMPT);
});

test("incomplete or inconsistent probability maps fail closed", () => {
  const cases = [
    { name: "missing label", probabilities: { allow: 1.0, prompt: 0.0 } },
    {
      name: "unknown label",
      probabilities: { allow: 0.99, prompt: 0.01, forbidden: 0.0, confused: 0.0 },
    },
    {
      name: "choice below the top probability",
      probabilities: { allow: 0.4, prompt: 0.6, forbidden: 0.0 },
    },
    {
      name: "tied top probabilities",
      probabilities: { allow: 0.5, prompt: 0.5, forbidden: 0.0 },
    },
  ];
  for (const { name, probabilities } of cases) {
    const result = decide(ALLOW, 1.0, probabilities);
    assert.equal(result.decision, PROMPT, `${name}: ${JSON.stringify(probabilities)}`);
  }
});

test("redactArgv masks a secret value in the next argument", () => {
  assert.deepEqual(redactArgv(["deploy", "--password", "hunter2"]), [
    "deploy",
    "--password",
    "<redacted>",
  ]);
  assert.deepEqual(
    redactArgv(["deploy", "--token", "sk-abcdefghijklmnopqrstuvwxyz"]),
    ["deploy", "--token", "<redacted>"],
  );
  assert.deepEqual(redactArgv(["deploy", "--password=hunter2"]), [
    "deploy",
    "--password=<redacted>",
  ]);
  assert.deepEqual(redactArgv(["deploy", "--password", "--verbose", "build"]), [
    "deploy",
    "--password",
    "--verbose",
    "build",
  ]);
  assert.deepEqual(redactArgv(["git", "status", "--short"]), [
    "git",
    "status",
    "--short",
  ]);
});

test("redact masks secrets and leaves ordinary commands alone", () => {
  const cases = {
    "GITHUB_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz1234": "GITHUB_TOKEN=<redacted>",
    "deploy --password=hunter2": "deploy --password=<redacted>",
    "deploy --api-key sk-abcdefghijklmnopqrstuvwxyz": "deploy --api-key <redacted>",
    "psql postgres://user:hunter2@db/app": "psql postgres://user:<redacted>@db/app",
    "git status --short": "git status --short",
    [`git show ${"a".repeat(40)}`]: `git show ${"a".repeat(40)}`,
  };
  for (const [input, expected] of Object.entries(cases)) {
    assert.equal(redact(input), expected, input);
  }
});

test("buildState redacts every field", () => {
  const state = buildState(["deploy", "--token", "sk-abcdefghijklmnopqrstuvwxyz"], {
    shellCommand: "deploy --token sk-abcdefghijklmnopqrstuvwxyz",
    matchedRules: [{ decision: "prompt", pattern: "deploy --password=hunter2" }],
    recentDecisions: [{ command: "curl -H 'Authorization: Bearer abc123'" }],
  });
  const serialized = JSON.stringify(state);
  assert.match(state.command.argv[2], /<redacted>/);
  assert.match(state.command.raw, /<redacted>/);
  assert.match(state.context.matched_rules[0].pattern, /<redacted>/);
  assert.match(state.context.recent_decisions[0].command, /<redacted>/);
  assert.doesNotMatch(serialized, /hunter2/);
  assert.doesNotMatch(serialized, /sk-abcdefghijklmnopqrstuvwxyz/);
});

test("matchedRuleFloor resolves rules fail closed", () => {
  assert.equal(
    matchedRuleFloor([
      { decision: "allow" },
      { decision: "forbidden" },
      { decision: "prompt" },
    ]),
    FORBIDDEN,
  );
  assert.equal(matchedRuleFloor([{ decision: "bogus" }]), PROMPT);
  assert.equal(matchedRuleFloor([{}]), PROMPT);
  assert.equal(matchedRuleFloor(["not-an-object"]), PROMPT);
  assert.equal(matchedRuleFloor([]), ALLOW);
  assert.equal(matchedRuleFloor(null), ALLOW);
});

test("a matched forbidden rule wins without calling the model", async () => {
  const calls = [];
  const record = await classifyCommand(["git", "push"], {
    matchedRules: [{ decision: "forbidden", pattern: "git push" }],
    evaluate: async (state) => {
      calls.push(state);
      return { answers: {} };
    },
  });
  assert.equal(record.decision, FORBIDDEN);
  assert.equal(calls.length, 0);
  assert.match(record.reasons[0], /matched execpolicy rule/);
});

test("a matched prompt rule cannot be lowered by the model", async () => {
  const record = await classifyCommand(["git", "push"], {
    matchedRules: [{ decision: "prompt", pattern: "git push" }],
    evaluate: async () => ({
      answers: {
        command_permission: {
          choice: "allow",
          confidence: 1.0,
          probabilities: { allow: 1.0, prompt: 0.0, forbidden: 0.0 },
        },
      },
    }),
  });
  assert.equal(record.decision, PROMPT);
});

test("matched rules do not leak secrets to the model", async () => {
  let seen = null;
  await classifyCommand(["deploy", "--token", "sk-abcdefghijklmnopqrstuvwxyz"], {
    raw: "deploy --token sk-abcdefghijklmnopqrstuvwxyz",
    matchedRules: [{ decision: "prompt", pattern: "deploy --password=hunter2" }],
    evaluate: async (state) => {
      seen = JSON.stringify(state);
      return {
        answers: {
          command_permission: {
            choice: "allow",
            confidence: 1.0,
            probabilities: { allow: 1.0, prompt: 0.0, forbidden: 0.0 },
          },
        },
      };
    },
  });
  assert.ok(seen);
  assert.doesNotMatch(seen, /hunter2/);
  assert.doesNotMatch(seen, /sk-abcdefghijklmnopqrstuvwxyz/);
});
