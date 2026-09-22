#!/usr/bin/env node
/**
 * Command-line entry point for the JEV command classifier (Node 18+ / Bun).
 *
 * Mirrors scripts/jev_classifier/cli.py.
 *
 * Examples:
 *   node scripts/classify_command.mjs --cwd "$PWD" -- git status --short
 *   node scripts/classify_command.mjs --command "git push origin main"
 *   node scripts/classify_command.mjs --offline -- rm -rf /
 *   node scripts/classify_command.mjs --self-test
 *
 * Exit codes: 0 allow, 1 prompt, 2 forbidden, 3 classifier failure (the
 * printed decision is still fail-closed to prompt).
 */

import { readFile } from "node:fs/promises";
import { pathToFileURL } from "node:url";

import {
  ALLOW,
  CONFIDENCE_FLOOR,
  FORBIDDEN,
  FORBIDDEN_MASS_CEILING,
  PROMPT,
  hardDeny,
  matchedRuleFloor,
  mostRestrictive,
  redact,
  redactArgv,
  splitSimple,
} from "./classifier.mjs";
import { DEFAULT_ENDPOINT, DEFAULT_MODEL, DEFAULT_TIMEOUT_MS } from "./client.mjs";

const EXIT_CODES = { [ALLOW]: 0, [PROMPT]: 1, [FORBIDDEN]: 2 };

const READ_ONLY = new Set([
  "ls", "pwd", "cat", "head", "tail", "wc", "file", "stat", "whoami", "id",
  "date", "uname", "echo", "printf", "which", "type", "true", "false", "rg",
  "grep",
]);
const READ_ONLY_GIT = new Set([
  "status", "log", "diff", "show", "rev-parse", "ls-files", "blame",
  "describe", "shortlog",
]);

const USAGE = `Usage: classify_command.mjs [options] -- <argv...>

Classify a shell command as allow, prompt, or forbidden with JEV (TypeSafe
Choice) and a fail-closed decision layer.

Options:
  --command <script>        raw shell command string to classify
  --cwd <dir>               working directory for context
  --sandbox <mode>          Codex sandbox mode (default: $CODEX_SANDBOX_MODE)
  --network <on|off|unknown>
  --matched-rule <d:pattern>  matched execpolicy rule, repeatable
  --model <name>            TypeSafe model (default: ${DEFAULT_MODEL})
  --endpoint <url>          TypeSafe endpoint (default: ${DEFAULT_ENDPOINT})
  --timeout <seconds>       request timeout (default: ${DEFAULT_TIMEOUT_MS / 1000})
  --no-retry                disable transient-failure retries
  --confidence-floor <n>    default: 0.98 (tighten only)
  --forbidden-ceiling <n>   default: 0.01 (tighten only)
  --offline                 deterministic heuristic instead of JEV (testing only)
  --text                    human-readable output instead of JSON
  --self-test               run deterministic self-tests and exit
  -h, --help                show this help

Exit codes: 0 allow, 1 prompt, 2 forbidden, 3 classifier failure.
`;

/** Deterministic stand-in for JEV, used only with --offline. */
function heuristicSegment(segment) {
  const reason = hardDeny(segment);
  if (reason) return { decision: FORBIDDEN, reasons: [`hard-deny: ${reason}`] };
  if (segment.length === 0) return { decision: PROMPT, reasons: ["empty command"] };

  const exe = segment[0].split("/").pop();
  const args = segment.slice(1);
  if (exe === "git" && args.length > 0 && READ_ONLY_GIT.has(args[0])) {
    return { decision: ALLOW, reasons: ["offline heuristic: read-only git"] };
  }
  if (READ_ONLY.has(exe)) {
    if (exe === "date" && args.some((arg) => arg.startsWith("-s"))) {
      return { decision: PROMPT, reasons: ["offline heuristic: date -s"] };
    }
    if (["sort", "uniq"].includes(exe) && args.some((arg) => arg.startsWith("-o"))) {
      return { decision: PROMPT, reasons: ["offline heuristic: writes output"] };
    }
    return { decision: ALLOW, reasons: ["offline heuristic: read-only"] };
  }
  if (exe === "sed" && args.includes("-n") && !args.some((a) => a.startsWith("-i"))) {
    return { decision: ALLOW, reasons: ["offline heuristic: sed -n"] };
  }
  if (
    exe === "find" &&
    !args.some((a) => ["-delete", "-exec", "-execdir", "-ok", "-fprint", "-fls"].includes(a))
  ) {
    return { decision: ALLOW, reasons: ["offline heuristic: find without writes"] };
  }
  return { decision: PROMPT, reasons: ["offline heuristic: not recognized"] };
}

function offlineClassify(command, argv, matchedRules = []) {
  const globalReason = hardDeny(argv, command ?? "");
  if (globalReason) {
    const record = {
      argv: [...argv],
      decision: FORBIDDEN,
      reasons: [`hard-deny: ${globalReason}`],
    };
    return {
      decision: FORBIDDEN,
      reasons: record.reasons,
      segments: [record],
      source: "offline-heuristic",
    };
  }

  const ruleFloor = matchedRuleFloor(matchedRules);
  if (ruleFloor === FORBIDDEN) {
    const record = {
      argv: [...argv],
      decision: FORBIDDEN,
      reasons: ["matched execpolicy rule: forbidden"],
    };
    return {
      decision: FORBIDDEN,
      reasons: record.reasons,
      segments: [record],
      source: "offline-heuristic",
    };
  }

  let segments = command ? splitSimple(command) : null;
  const unparsed = command != null && segments === null;
  if (segments === null) segments = [[...argv]];

  const records = [];
  for (const segment of segments) {
    let record;
    if (unparsed) {
      const reason = hardDeny(segment, command ?? "");
      record = reason
        ? { decision: FORBIDDEN, reasons: [`hard-deny: ${reason}`] }
        : { decision: PROMPT, reasons: ["offline heuristic: unsplittable shell features"] };
    } else {
      record = heuristicSegment(segment);
    }
    record.argv = [...segment];
    records.push(record);
  }

  const overall = mostRestrictive([ruleFloor, ...records.map((record) => record.decision)]);
  const reasons = records
    .filter((record) => record.decision === overall)
    .flatMap((record) => record.reasons ?? []);
  if (ruleFloor !== ALLOW && ruleFloor === overall) {
    reasons.unshift(`matched execpolicy rule: ${ruleFloor}`);
  }
  return { decision: overall, reasons, segments: records, source: "offline-heuristic" };
}

async function loadFixtures() {
  const url = new URL("../fixtures/cases.json", import.meta.url);
  return JSON.parse(await readFile(url, "utf8"));
}

async function selfTest() {
  const { decide } = await import("./classifier.mjs");
  const fixtures = await loadFixtures();
  const failures = [];

  for (const testCase of fixtures.decide) {
    const options = {};
    if ("confidence_floor" in testCase) options.confidenceFloor = testCase.confidence_floor;
    const got = decide(
      testCase.choice,
      testCase.confidence,
      testCase.probabilities,
      { hardDenyReason: testCase.hard_deny_reason ?? null, ...options },
    ).decision;
    if (got !== testCase.expected) {
      failures.push(`decide[${testCase.name}] -> ${got}, expected ${testCase.expected}`);
    }
  }

  for (const testCase of fixtures.split) {
    const got = splitSimple(testCase.command);
    if (JSON.stringify(got) !== JSON.stringify(testCase.expected)) {
      failures.push(
        `splitSimple(${JSON.stringify(testCase.command)}) -> ${JSON.stringify(got)}, ` +
          `expected ${JSON.stringify(testCase.expected)}`,
      );
    }
  }

  for (const testCase of fixtures.hard_deny) {
    const got = hardDeny(testCase.argv, testCase.raw);
    if ((got !== null) !== testCase.expected) {
      failures.push(
        `hardDeny[${testCase.name}] -> ${JSON.stringify(got)}, expected match=${testCase.expected}`,
      );
    }
  }

  for (const testCase of fixtures.rule_floor) {
    const got = matchedRuleFloor(testCase.rules);
    if (got !== testCase.expected) {
      failures.push(
        `matchedRuleFloor[${testCase.name}] -> ${got}, expected ${testCase.expected}`,
      );
    }
  }

  for (const testCase of fixtures.redact) {
    const got = redact(testCase.input);
    if (got !== testCase.expected) {
      failures.push(
        `redact[${testCase.name}] -> ${JSON.stringify(got)}, ` +
          `expected ${JSON.stringify(testCase.expected)}`,
      );
    }
  }

  for (const testCase of fixtures.redact_argv) {
    const got = redactArgv(testCase.argv);
    if (JSON.stringify(got) !== JSON.stringify(testCase.expected)) {
      failures.push(
        `redactArgv[${testCase.name}] -> ${JSON.stringify(got)}, ` +
          `expected ${JSON.stringify(testCase.expected)}`,
      );
    }
  }

  if (failures.length > 0) {
    for (const failure of failures) console.error(`FAIL: ${failure}`);
    return 1;
  }
  console.log("self-test: ok");
  return 0;
}

function parseArgs(args) {
  const options = {
    argv: [],
    command: null,
    cwd: null,
    sandbox: process.env.CODEX_SANDBOX_MODE ?? "unknown",
    network: "unknown",
    matchedRules: [],
    model: DEFAULT_MODEL,
    endpoint: DEFAULT_ENDPOINT,
    timeoutSeconds: DEFAULT_TIMEOUT_MS / 1000,
    retries: 2,
    confidenceFloor: 0.98,
    forbiddenCeiling: 0.01,
    offline: false,
    text: false,
    selfTest: false,
  };

  const need = (index, name) => {
    if (index + 1 >= args.length) throw new Error(`${name} needs a value`);
    return args[index + 1];
  };

  let index = 0;
  while (index < args.length) {
    const arg = args[index];
    if (arg === "--") {
      options.argv = args.slice(index + 1);
      break;
    }
    switch (arg) {
      case "--command": options.command = need(index, arg); index += 1; break;
      case "--cwd": options.cwd = need(index, arg); index += 1; break;
      case "--sandbox": options.sandbox = need(index, arg); index += 1; break;
      case "--network": options.network = need(index, arg); index += 1; break;
      case "--matched-rule": options.matchedRules.push(need(index, arg)); index += 1; break;
      case "--model": options.model = need(index, arg); index += 1; break;
      case "--endpoint": options.endpoint = need(index, arg); index += 1; break;
      case "--timeout": options.timeoutSeconds = Number(need(index, arg)); index += 1; break;
      case "--confidence-floor": options.confidenceFloor = Number(need(index, arg)); index += 1; break;
      case "--forbidden-ceiling": options.forbiddenCeiling = Number(need(index, arg)); index += 1; break;
      case "--no-retry": options.retries = 0; break;
      case "--offline": options.offline = true; break;
      case "--text": options.text = true; break;
      case "--self-test": options.selfTest = true; break;
      case "-h":
      case "--help": options.help = true; break;
      default:
        if (arg.startsWith("-")) throw new Error(`unknown option: ${arg}`);
        options.argv.push(arg);
    }
    index += 1;
  }
  return options;
}

/** Shell-like split used only to derive argv from --command. */
function splitArgv(command) {
  const tokens = [];
  let current = "";
  let hasCurrent = false;
  let quote = null;
  for (const char of command) {
    if (quote) {
      if (char === quote) quote = null;
      else current += char;
      continue;
    }
    if (char === '"' || char === "'") {
      quote = char;
      hasCurrent = true;
      continue;
    }
    if (char === " " || char === "\t") {
      if (hasCurrent) {
        tokens.push(current);
        current = "";
        hasCurrent = false;
      }
      continue;
    }
    current += char;
    hasCurrent = true;
  }
  if (hasCurrent) tokens.push(current);
  return tokens;
}

/**
 * Reject threshold overrides that could make an unsafe answer `allow`.
 *
 * Values must be finite and within [0, 1], and the CLI only accepts
 * tightening: a lower `--confidence-floor` or a higher `--forbidden-ceiling`
 * than the production defaults is refused. Looser thresholds belong in a
 * labeled evaluation, not in a live invocation.
 */
function validateThresholds(options) {
  for (const [name, value] of [
    ["--confidence-floor", options.confidenceFloor],
    ["--forbidden-ceiling", options.forbiddenCeiling],
  ]) {
    if (!Number.isFinite(value) || value < 0 || value > 1) {
      throw new Error(`${name} must be a finite number in [0, 1], got ${value}`);
    }
  }
  if (options.confidenceFloor < CONFIDENCE_FLOOR) {
    throw new Error(
      `--confidence-floor may only tighten the default ${CONFIDENCE_FLOOR}, got ${options.confidenceFloor}`,
    );
  }
  if (options.forbiddenCeiling > FORBIDDEN_MASS_CEILING) {
    throw new Error(
      `--forbidden-ceiling may only tighten the default ${FORBIDDEN_MASS_CEILING}, got ${options.forbiddenCeiling}`,
    );
  }
}

export async function main(argv = process.argv.slice(2)) {
  let options;
  try {
    options = parseArgs(argv);
  } catch (error) {
    console.error(`classify_command.mjs: ${error.message}`);
    console.error(USAGE);
    return 2;
  }

  if (options.help) {
    console.log(USAGE);
    return 0;
  }
  if (options.selfTest) return selfTest();

  try {
    validateThresholds(options);
  } catch (error) {
    console.error(`classify_command.mjs: ${error.message}`);
    return 2;
  }

  if (options.command && options.argv.length > 0) {
    console.error("classify_command.mjs: pass either --command or trailing argv, not both");
    return 2;
  }
  if (!options.command && options.argv.length === 0) {
    console.error("classify_command.mjs: provide a command: --command '<script>' or -- <argv...>");
    return 2;
  }

  const raw = options.command;
  const commandArgv = options.argv.length > 0 ? options.argv : splitArgv(raw ?? "");
  const matchedRules = options.matchedRules.map((rule) => {
    const separator = rule.indexOf(":");
    return separator === -1
      ? { decision: "unknown", pattern: rule }
      : { decision: rule.slice(0, separator) || "unknown", pattern: rule.slice(separator + 1) };
  });

  let result;
  if (options.offline) {
    result = offlineClassify(raw, commandArgv, matchedRules);
    result.model = "offline-heuristic";
  } else {
    const { classifyCommand } = await import("./classifier.mjs");
    const { evaluate } = await import("./client.mjs");
    result = await classifyCommand(commandArgv, {
      raw,
      cwd: options.cwd,
      sandboxMode: options.sandbox,
      network: options.network === "unknown" ? null : options.network,
      matchedRules,
      confidenceFloor: options.confidenceFloor,
      forbiddenMassCeiling: options.forbiddenCeiling,
      evaluate: (state, questions) =>
        evaluate(state, questions, {
          model: options.model,
          endpoint: options.endpoint,
          timeoutMs: options.timeoutSeconds * 1000,
          retries: options.retries,
        }),
    });
    result.source = "jev";
  }

  // Audit-facing output only ever contains redacted command data.
  result.command = redact(raw ?? commandArgv.join(" "));
  for (const segment of result.segments ?? []) {
    if (Array.isArray(segment.argv)) segment.argv = redactArgv(segment.argv);
  }

  if (options.text) {
    console.log(`decision: ${result.decision}`);
    for (const reason of result.reasons ?? []) console.log(`  - ${reason}`);
    for (const segment of result.segments ?? []) {
      console.log(`  segment ${JSON.stringify(segment.argv)}: ${segment.decision}`);
    }
  } else {
    console.log(JSON.stringify(result, null, 2));
  }

  const failed = (result.reasons ?? []).some((reason) => reason.includes("classifier failure"));
  if (failed) return 3;
  return EXIT_CODES[result.decision] ?? 3;
}

const invokedDirectly =
  Boolean(process.argv[1]) && import.meta.url === pathToFileURL(process.argv[1]).href;
if (invokedDirectly) {
  process.exitCode = await main();
}
