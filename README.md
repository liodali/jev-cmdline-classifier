# codex-jev-classifier-skills

A portable [Agent Skill](skills/jev-command-classifier/SKILL.md) that classifies
shell commands with JEV (TypeSafe `Choice`) and wires the verdict into Codex
command approvals, plus the reference implementation and tests for it.

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

Dependency-free in both languages, talking to the TypeSafe HTTP API directly.
Python 3.9+ (stdlib only) or Node 18+ / Bun (ESM, no packages). The two
implementations share `scripts/fixtures/cases.json` and produce identical
decisions.

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
