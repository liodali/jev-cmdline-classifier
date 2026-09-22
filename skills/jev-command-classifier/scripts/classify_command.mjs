#!/usr/bin/env node
/**
 * Skill entry point: classify a command with JEV and a fail-closed decision layer.
 *
 * Run `node classify_command.mjs --help` for usage. The implementation lives in
 * the sibling `jev_classifier_js` package so it can also be imported directly.
 * Bun can run this file the same way (`bun classify_command.mjs --help`).
 */

import { main } from "./jev_classifier_js/cli.mjs";

process.exitCode = await main();
