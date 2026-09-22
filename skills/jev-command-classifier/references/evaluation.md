# Evaluation and rollout

Read this before trusting a threshold, changing the question, or promoting
JEV verdicts into auto-allow behavior.

## Build a labeled set first

Collect at least 200-500 real commands from the environment where the
classifier will run, redact secrets, and label each with the decision a careful
reviewer would give. Add synthetic cases for the categories below so rare
dangers are represented.

| Category | Examples |
| --- | --- |
| Read-only | `git status`, `rg`, `ls`, `cat README.md` |
| Local writes | `npm install`, `cargo build`, formatters, test runs |
| Network | `curl`, `pip download`, `gh pr view` |
| Remote state | `git push`, `gh pr merge`, `npm publish` |
| Destructive | `rm -rf build`, `git reset --hard`, `docker system prune` |
| Credential access | reads or writes under `~/.ssh`, `~/.aws`, `.env` |
| Escalation | `sudo`, `chmod 777`, `launchctl`, `systemctl` |
| Obfuscated or compound | `bash -c "..."`, pipelines, command substitution, base64 payloads |
| Injection attempts | commands whose arguments contain instructions to the classifier |

Keep the set in version control and grow it with every production surprise.

## Metrics that matter

- **False-allow rate** (a harmful command classified `allow`): the primary
  metric. Target zero. Any nonzero rate blocks auto-allow rollout.
- **False-forbid rate**: `forbidden` on something harmless. Low cost to safety,
  high cost to trust; keep it low enough that users do not disable the layer.
- **Prompt rate**: how often a human is still asked. Track by category to see
  whether the classifier is buying anything.
- **Latency and cost**: p50/p95 added latency per approval and token spend.
  A cached, per-command budget is often necessary for chatty agents.
- **Disagreement rate** with user decisions: where users routinely accept a
  `prompt`, consider a narrow rule; where they routinely decline an `allow`,
  treat it as a false-allow near-miss and investigate.

## Tune thresholds

1. Run the classifier over the labeled set and store choice, probabilities,
   and confidence for every case.
2. Sweep `confidence_floor` and `forbidden_mass_ceiling` offline. Plot
   false-allow rate against prompt rate.
3. Pick the strictest operating point whose prompt rate is tolerable, and
   re-check the false-forbid rate for the categories users care about.
4. Re-run the whole procedure whenever the model version, question text, or
   criteria change. A threshold tuned for one model does not transfer.
5. New defaults only land after the sweep and a reviewed rollout. The CLI
   flags accept tightening only: `--confidence-floor` may not go below the
   shipped default and `--forbidden-ceiling` may not go above it, so a
   live invocation cannot weaken the production thresholds.

## Audit record

Write one JSON object per decision to a JSONL file or log pipeline:

```json
{
  "timestamp": "2026-09-21T12:00:00Z",
  "command": "git push origin main",
  "cwd": "/repo",
  "sandbox_mode": "workspace-write",
  "matched_rules": [{ "decision": "prompt", "pattern": "git push" }],
  "model": "jev-1.13.0",
  "choice": "prompt",
  "confidence": 0.93,
  "probabilities": { "allow": 0.05, "prompt": 0.93, "forbidden": 0.02 },
  "decision": "prompt",
  "reasons": ["confidence 0.930 below floor 0.980"],
  "hard_deny": null,
  "user_response": "acceptForSession"
}
```

Run the command through `redact()` before writing. Keep enough of the command
to reproduce the decision, and join records to user responses so false-allow
and false-forbid reviews are possible. Add a case to the evaluation set for
every redaction miss you find.

## Rollout

1. **Shadow**: classify every approval request, log the verdict, but let Codex
   prompt normally. Compare verdicts with user responses.
2. **Prompt-only**: use the classifier to annotate prompts, never to auto
   accept. Watch for false allows the user caught.
3. **Narrow auto-allow**: enable `allow` verdicts only for categories with a
   clean false-allow record, for example read-only Git and search commands.
4. **Broaden**: extend category by category with the same evidence bar.

Every stage needs a rollback: an environment flag that restores normal Codex
approval behavior without redeploying.

## Regression checks

- Re-run the labeled set on every classifier change and in CI if possible.
- Assert the decision layer invariants directly: hard deny wins, malformed
  answers fail closed, compound commands keep the most restrictive verdict.
  The shared fixtures in `scripts/fixtures/cases.json` drive the self-tests of
  both implementations, so a divergence between them fails immediately.
- Verify that allowed commands still run inside the sandbox and that no code
  path grants network access or extra permissions from a model verdict.
