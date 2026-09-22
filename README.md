# codex-jev-classifier-skills

A portable [Agent Skill](skills/jev-command-classifier/SKILL.md) and reference
implementation that classifies shell commands with TypeSafe's JEV `Choice`.
It emits a verdict for an approval wrapper or App Server client to consume;
that integration is documented but not implemented in this repository.

The classifier returns one of three decisions:

| Decision | Meaning |
| --- | --- |
| `allow` | Read-only, local, narrowly scoped; cannot change files, processes, credentials, network state, or remote state |
| `prompt` | May write, reach the network, install software, affect processes, change Git state, or is ambiguous |
| `forbidden` | Destructive, privilege-escalating, credential-stealing, sandbox-escaping, or dangerously broad |

**JEV is advisory.** Codex sandboxing, approval policy, and execpolicy `.rules`
remain the security boundary. The deterministic decision layer fails closed,
local hard-deny rules and matched `forbidden` rules win before the model runs,
secrets are redacted before any state is sent, and an `allow` verdict never
widens the sandbox or grants network access.

## Install the skill

Works with Codex, OpenCode, Pi, and Command Code. Any harness that reads
`SKILL.md` folders can use it.

```bash
./install.sh                 # copy into every detected harness
./install.sh --link          # symlink so this repo stays the source of truth
./install.sh --codex --pi    # only the named harnesses
```

Targets: `${CODEX_HOME:-~/.codex}/skills`, `~/.config/opencode/skills`,
`~/.pi/agent/skills`, `~/.commandcode/skills`. Copy manually if you prefer:

```bash
cp -R skills/jev-command-classifier ~/.codex/skills/
```

Once published, the skills.sh CLI can install it too:

```bash
npx skills add <owner>/codex-jev-classifier-skills --skill jev-command-classifier
```

## Use the implementation

Dependency-free in both languages, talking to the model provider's HTTP API
directly. Python 3.9+ (stdlib only) or Node 18+ / Bun (ESM, no packages). The
two implementations share `scripts/fixtures/cases.json` and produce identical
decisions.

A **TypeSafe JEV connection is required for real classification** (direct by
default — create a key at https://console.typesafe.ai/keys). The
`--self-test` and `--offline` modes need no key at all.

```bash
export TYPESAFE_API_KEY=...   # https://console.typesafe.ai/keys

python3 skills/jev-command-classifier/scripts/classify_command.py \
  --cwd "$PWD" -- git status --short

node skills/jev-command-classifier/scripts/classify_command.mjs \
  --cwd "$PWD" -- git status --short
# Bun runs the same file: bun skills/jev-command-classifier/scripts/classify_command.mjs -- ...
```

```json
{
  "command": "git status --short",
  "decision": "allow",
  "reasons": [],
  "segments": [{ "argv": ["git", "status", "--short"], "decision": "allow" }],
  "source": "jev"
}
```

Exit codes: `0` allow, `1` prompt, `2` forbidden, `3` classifier failure (the
printed decision is still fail-closed to `prompt`). Output is JSON so a wrapper
can consume it directly.

Testing and offline modes, no API key needed:

```bash
python3 skills/jev-command-classifier/scripts/classify_command.py --self-test
node skills/jev-command-classifier/scripts/classify_command.mjs --self-test
python3 skills/jev-command-classifier/scripts/classify_command.py \
  --offline --command "git add . && rm -rf /"
```

`--offline` is a wiring aid for tests, never a security control.

## Configuration

The classifier uses TypeSafe's JEV `Choice` model only. The default provider
calls TypeSafe directly. Other providers are supported as trusted gateways
that forward the System One API to TypeSafe JEV without substituting another
model. Flags override environment variables.

| Variable | Meaning |
| --- | --- |
| `JEV_PROVIDER` | `typesafe` (default) or `systemone-compatible` (trusted gateway) |
| `JEV_ENDPOINT` | Override the provider endpoint URL |
| `JEV_MODEL` | JEV model id beginning with `jev-` (default: `jev-latest`) |
| `TYPESAFE_API_KEY` | Key for direct TypeSafe calls |
| `JEV_API_KEY` | Key for a gateway; overrides the default key variable if set |

The implementation rejects non-`jev-*` model IDs before making a request and
rejects a response that names a different model family. A model-name check
is not proof of provenance. You must trust the selected gateway to route to
TypeSafe's real JEV model. The classifier never sends chat-completions
messages or synthesizes probabilities from generated text.

### Direct TypeSafe access

```bash
export TYPESAFE_API_KEY=...   # https://console.typesafe.ai/keys
python3 skills/jev-command-classifier/scripts/classify_command.py -- git status --short
```

### Trusted gateway

A gateway must accept the System One `POST` payload
`{state, model, questions}` and return native typed `answers` with
probabilities and confidence. OpenAI/OpenRouter chat-completions APIs and
general-purpose LLM runtimes are not supported; asking them to emit JSON
does not turn them into JEV.

```bash
export MY_GATEWAY_KEY=...
python3 skills/jev-command-classifier/scripts/classify_command.py \
  --provider systemone-compatible \
  --endpoint https://gateway.internal.example/v1/systemone \
  --api-key-env MY_GATEWAY_KEY \
  -- git status --short
```

The JavaScript/Bun CLI accepts the same flags. For a trusted gateway that
does not use bearer authentication, `--api-key-env none` omits the header.
The clients refuse to send `TYPESAFE_API_KEY` to an override endpoint by
default. Do not deliberately send it to an untrusted gateway.

Before relying on a gateway, verify its actual upstream model and API
contract. Then evaluate thresholds against a labeled command set per
[skill references/evaluation.md](skills/jev-command-classifier/references/evaluation.md).
A `jev-*` response name alone cannot establish the upstream model's identity.

## Development

```bash
python3 -m unittest discover -s tests -t .      # Python tests
npm test --prefix skills/jev-command-classifier/scripts/jev_classifier_js
bun test --cwd skills/jev-command-classifier/scripts/jev_classifier_js
pip install -e .    # optional: installs the `jev-classify` console script
```

The implementations live inside the skill
(`skills/jev-command-classifier/scripts/jev_classifier/` for Python,
`.../jev_classifier_js/` for JavaScript) so an installed skill stays
self-contained; `pyproject.toml` and the package's `package.json` package them
for testing and console use.

## Layout

```text
skills/jev-command-classifier/
├── SKILL.md                 Skill entrypoint and constraints
├── agents/openai.yaml       Codex UI metadata
├── references/
│   ├── codex-integration.md App Server approvals, execpolicy rules, audit
│   ├── classification.md    Question, state schema, hard denies, injection
│   └── evaluation.md        Labeled sets, thresholds, rollout, regression
└── scripts/
    ├── classify_command.py  Python CLI entrypoint
    ├── classify_command.mjs JavaScript/Bun CLI entrypoint
    ├── fixtures/cases.json  Shared parity fixtures for both implementations
    ├── jev_classifier/      Python implementation (stdlib only)
    └── jev_classifier_js/   JavaScript implementation (ESM, no packages)
tests/                       Python unit and client tests (no network required)
install.sh                   Installs the skill into local harnesses
```

## License

MIT. See [LICENSE](LICENSE).
