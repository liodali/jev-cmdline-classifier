# Codex integration surfaces

Read this when wiring a JEV verdict into Codex approvals or authoring
execpolicy rules.

## Why rules cannot call JEV

`.rules` files are Starlark evaluated by a deterministic engine with no side
effects (no filesystem, no network). There is no hook for a model call. Treat
rules as the durable, reviewable layer and JEV as an advisory layer that runs
in a client or service that already sees approval requests.

## App Server approval flow

App Server is Codex's JSON-RPC interface for rich clients. It is experimental;
generate version-matched schemas with:

```bash
codex app-server generate-json-schema --out ./schemas
```

### Command execution approvals

Message order:

1. `item/started` with the pending `commandExecution` item (`command`, `cwd`).
2. Server request `item/commandExecution/requestApproval` with `itemId`,
   `threadId`, `turnId`, and optionally `reason`, `command`, `cwd`,
   `commandActions`, `proposedExecpolicyAmendment`, `networkApprovalContext`,
   `availableDecisions`, and (experimental) `additionalPermissions`.
3. The client answers with one of:
   - `accept`
   - `acceptForSession`
   - `decline`
   - `cancel`
   - `{ "acceptWithExecpolicyAmendment": { "execpolicy_amendment": ["cmd", "..."] } }`
4. `serverRequest/resolved` confirms the answer.
5. `item/completed` reports the final `commandExecution` item with
   `status: completed | failed | declined`.

Map the JEV decision to the response:

| JEV decision | Client response |
| --- | --- |
| `allow` | `accept` |
| `prompt` | Surface the prompt to the user; `decline` in non-interactive runs |
| `forbidden` | `decline` (or `cancel` to abort the turn) |
| matched `forbidden` rule | `decline`; deterministic, evaluated before the model |
| classifier failure | `decline`; never `accept` |

Resolve the most restrictive matched rule first. A matched `forbidden` rule
must produce `decline` even when the model returns a confident `allow`, and a
matched `prompt` rule must keep the prompt in front of the user. Codex applies
the same precedence (`forbidden` > `prompt` > `allow`) when it evaluates the
rules itself, so the client must not disagree with it.

When the user accepts a command permanently, answer with
`acceptWithExecpolicyAmendment` and a narrow prefix instead of writing rules
yourself. Codex turns the amendment into an execpolicy proposal the user can
review.

### Related approval requests

- `item/fileChange/requestApproval` covers file writes (`accept`,
  `acceptForSession`, `decline`, `cancel`). The command classifier does not
  judge file edits; keep those approvals separate or add a dedicated question.
- `networkApprovalContext` marks a managed network approval, not a general
  shell approval. Decide it from the destination `host` and protocol, and
  expect Codex to group prompts by host, protocol, and port.
- `additionalPermissions` (experimental) requests extra sandbox access for one
  command. Treat any escalation as `prompt` or `decline`; the JEV allow
  verdict does not cover it.
- `item/permissions/requestApproval` handles the `request_permissions` tool.
  Grant only the requested subset and scope it to the turn unless the user
  explicitly chooses session scope.

### Approval configuration that keeps the boundary

```toml
# ~/.codex/config.toml
approval_policy = "on-request"
sandbox_mode    = "workspace-write"
# Optional: let Codex's own reviewer handle eligible escalations.
# approvals_reviewer = "auto_review"
```

- `approvals_reviewer = "auto_review"` is Codex's built-in reviewer. It is a
  separate mechanism from a JEV client and can coexist with it.
- The retired `untrusted` approval policy must not be reintroduced. For
  stricter command approval, omit an explicit policy and set a project
  `trust_level = "untrusted"`, or use `sandbox_mode = "read-only"` with
  `approval_policy = "on-request"`.
- Granular approval policies can auto-reject categories such as
  `sandbox_approval`, `rules`, `mcp_elicitations`, `request_permissions`, or
  `skill_approval`. Returning `decline` is the fail-closed choice.

## Execpolicy rules

Rules live in `.rules` files under a `rules/` folder next to an active config
layer: `~/.codex/rules/default.rules`, `<repo>/.codex/rules/` when the project
layer is trusted, and other layers. Codex rescans them at startup.

```python
prefix_rule(
    pattern = ["git", "status"],
    decision = "allow",
    justification = "Read-only status inspection",
    match = ["git status", "git status --short"],
    not_match = ["git status && rm -rf /"],
)

prefix_rule(
    pattern = ["git", "push"],
    decision = "prompt",
    justification = "Remote-changing command",
)
```

Facts that shape rule proposals:

- `pattern` is a non-empty list of literal strings or unions of literals at a
  position, for example `["git", ["push", "fetch"]]`.
- The most restrictive decision wins across matching rules:
  `forbidden` > `prompt` > `allow`.
- Codex splits a linear chain of plain words joined by `&&`, `||`, `;`, or `|`
  into separate commands before applying rules. Redirects, substitutions,
  variables, wildcards, control flow, and assignments make the whole script a
  single `["bash", "-lc", "..."]` invocation.
- The TUI writes accepted allowlist entries to `~/.codex/rules/default.rules`.
- Validate before adopting: `codex execpolicy check --pretty --rules <file> -- <command>`.

### Proposal quality

- Derive the narrowest prefix that covers the accepted invocation; do not
  promote a one-off acceptance into a family-wide rule.
- Never end a prefix in a value that varies, and never use a wildcard as a
  shortcut around review.
- Prefer `prompt` for anything that changes remote state (`git push`,
  `gh pr merge`, `npm publish`) even when the local command looks routine.
- Include `match` and `not_match` examples so a bad rule fails at load time
  instead of at approval time.
- Keep `forbidden` rules for destructive or credential-touching commands, and
  put a recommended alternative in `justification`.

## Audit and failure behavior

- Record the redacted request payload, the model name and version, choice,
  probabilities, confidence, final decision, matched rules, and the user's
  response. Run commands and rule patterns through `redact()` before writing
  them anywhere durable.
- Retry 429/529 with backoff; never retry 401. Fail closed on every error
  path, including malformed JSON and timeouts.
- If the classifier is unavailable, keep Codex's normal approval prompt
  instead of substituting a heuristic.
