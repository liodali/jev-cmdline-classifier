/**
 * JEV command classifier for Codex approvals (Node 18+ / Bun).
 *
 * Mirrors the Python package in ../jev_classifier. The model verdict is
 * advisory: `decide` fails closed and `hardDeny` always wins.
 */

export {
  ALLOW,
  COMMAND_QUESTION,
  CONFIDENCE_FLOOR,
  DECISION_RANK,
  FORBIDDEN,
  FORBIDDEN_MASS_CEILING,
  PROBABILITY_SUM_TOLERANCE,
  PROMPT,
  QUESTION_ID,
  REDACTION_MASK,
  buildState,
  classifyCommand,
  decide,
  hardDeny,
  matchedRuleFloor,
  mostRestrictive,
  redact,
  redactArgv,
  splitSimple,
} from "./classifier.mjs";

export {
  API_KEY_ENV,
  DEFAULT_ENDPOINT,
  DEFAULT_MODEL,
  DEFAULT_RETRIES,
  DEFAULT_TIMEOUT_MS,
  TypeSafeAuthError,
  TypeSafeError,
  apiKeyFromEnv,
  evaluate,
} from "./client.mjs";

export { main } from "./cli.mjs";
