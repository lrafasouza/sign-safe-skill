# sign-safe -- Solana Signing-Time Safety Gate

A Claude Code skill (and a runnable TypeScript library) that decodes an opaque
Solana transaction **before you sign it**, classifies it against a danger-primitive
catalog, computes the signer-perspective outflow, and emits a **SIGN / HOLD /
REJECT** verdict plus a machine-readable `verdict.json` for autonomous-agent gating.

> **Extends**: [solana-dev-skill](https://github.com/solana-foundation/solana-dev-skill)
> -- core Solana development (programs, frontend, testing, security). sign-safe
> layers a signing-time gate on top; it does not duplicate the core skill.

## The problem (Drift, April 2026)

In April 2026, roughly **$285M** was drained after signers approved an opaque
transaction whose framing relied on **durable nonces** and **blind signing**: the
signed transaction had no blockhash expiry, so it could be held and replayed
under conditions the signers never intended. The signers saw an inscrutable
base64 blob and a wallet "Approve" button -- and no decode, no danger
classification, no outflow accounting between the blob and their signature.

sign-safe is the missing layer: a deterministic, offline gate that sits between
the bytes and the signature.

## What it does

Given a base64 message (legacy or v0), the deterministic core:

1. **decodes** the wire format with our own parser (no web3.js dependency in the
   core),
2. **derives roles** (signer / writable / readonly) from the header, marking any
   Address-Lookup-Table reference as `unverified`,
3. **classifies** each instruction against a 10-entry danger catalog
   (authority handoffs, program upgrades, durable nonces, delegate grants,
   account closes, large transfers),
4. **computes** the statically-declared signer outflow,
5. **emits** a `SIGN / HOLD / REJECT` verdict + `verdict.json`.

**Fail-closed by construction:** malformed input -> REJECT; unresolved ALT
references can never produce SIGN; unknown programs can never produce SIGN, and
if they write to a value-bearing account they force REJECT.

### The SIGN / HOLD / REJECT contract

The verdict is a three-way, severity-ordered decision. The decision is always
the **worst** outcome triggered by any instruction (REJECT dominates HOLD
dominates SIGN), and the exit code mirrors it so agents and scripts can gate on
it directly.

| Verdict | Exit | Meaning | Triggered by |
|---------|------|---------|--------------|
| **SIGN** | `0` | Every instruction is recognized and within thresholds. Still *not* a guarantee of intent — verify recipients and amounts yourself. | No danger primitives, no unknown programs, no unverified ALT references, outflow under threshold. |
| **HOLD** | `10` | Needs a human. Plausibly legitimate but capable of loss; do not auto-sign. | Delegate grants, account closes, durable-nonce setup, permanent-delegate, large transfers, or any unverified ALT reference. |
| **REJECT** | `20` | Do not sign. Either a catastrophic primitive or the bytes could not be trusted. | Authority handoffs, program upgrades, the Drift-style durable-nonce advance, an unknown program writing to a value-bearing account, or malformed/undecodable input. |

A SIGN verdict is deliberately the weakest claim in the system: it says "nothing
in this blob is recognized as dangerous," never "this is safe."

## Scope

**In scope (what sign-safe decides):**

- Decoding legacy and v0 serialized messages from opaque base64, with our own
  dependency-free wire parser.
- Deriving signer / writable / readonly roles and flagging every
  Address-Lookup-Table reference as `unverified`.
- Classifying instructions against a 10-entry danger-primitive catalog
  (authority handoffs, program upgrades, durable nonces, delegate grants,
  account closes, large transfers).
- Computing the statically-declared signer outflow (lamports + SPL transfers).
- Emitting a `SIGN / HOLD / REJECT` verdict and a machine-readable
  `verdict.json` with a verdict-mirroring exit code.

**Out of scope (and what to use instead):**

| Not this | Use instead |
|----------|-------------|
| A program source-code audit | `/audit-solana` |
| A debugger for a landed/failed transaction | `/debug-user-tx` |
| A replacement for core Solana dev knowledge | `solana-dev-skill` |
| Simulating runtime balance changes against live cluster state | a simulation/`simulateTransaction` tool |
| Signing, broadcasting, or touching a private key | your wallet — sign-safe never asks for a key |
| A guarantee that a SIGN'd transaction matches your *intent* | your own check of recipients and amounts |

sign-safe is a **static, offline, fail-closed pre-signing gate**, not a runtime
simulator and not a signer. It tells you what a blob *is*; you still confirm it
is what you *meant*.

## Why this skill is different: it actually runs, and it is tested

Most skills are prose. This one ships a small, **pure-function** TypeScript core
with a deterministic, fully **offline** test suite:

- **10 golden fixtures** -- real serialized messages built with `@solana/web3.js`,
  decoded by *our own* parser, verdicts deep-equal-checked against committed
  `verdict.json` goldens.
- **Cross-validation** -- the same bytes are deserialized with `@solana/web3.js`
  and we assert our decoded program ids, static keys, version, and ALT count
  match. Two independent implementations agree, so the parser is *correct*, not
  merely self-consistent.
- **Determinism** -- every fixture is decoded twice and the JSON must be identical.
- **Fail-closed** -- truncated / garbage / tampered input must yield REJECT and
  never throw uncaught.

## Install

The repo is **self-contained** — the core has no runtime dependency on any
sibling skill, and there is **no postinstall and no curl** anywhere in it. It
installs two ways: as a submodule inside a skills kit, or standalone.

### As a submodule inside `solana-ai-kit` (kit integration)

Add `sign-safe` to an existing kit (e.g. `solanabr/solana-ai-kit`) as a git
submodule, then commit the pointer:

```bash
# from the root of your fork of solanabr/solana-ai-kit
git submodule add https://github.com/<you>/sign-safe-skill skills/sign-safe
git commit -m "feat: add sign-safe signing-time safety gate as a submodule"

# anyone cloning the kit then pulls the skill in with:
git clone --recurse-submodules https://github.com/solanabr/solana-ai-kit
# or, in an existing checkout:
git submodule update --init --recursive
```

The kit picks up `skills/sign-safe/skill/SKILL.md`, the `/sign-review` command,
and the signing-output rule automatically. The skill references the core
`solana-dev-skill` **by name** only (never by a relative path or a nested
submodule), so it composes with the rest of the kit without creating a second,
conflicting dependency graph.

### Standalone (clone and run the gate locally)

```bash
git clone https://github.com/<you>/sign-safe-skill sign-safe
cd sign-safe
npm install
npm run gen-fixtures   # (re)generate the 10 .b64 fixtures from @solana/web3.js
npm test               # golden + cross-validation + determinism + fail-closed
```

You can also drop the `skill/`, `commands/`, and `rules/` directories directly
under a Claude Code skills root (e.g. `~/.claude/skills/sign-safe/`) if you are
wiring it into Claude Code by hand rather than through a kit.

## Usage

```bash
# Review a base64 message file:
node --import tsx skill/src/cli.ts skill/fixtures/07_large_transfer_hold.b64

# Pipe base64 on stdin:
cat msg.b64 | node --import tsx skill/src/cli.ts

# Override the large-transfer threshold (lamports):
node --import tsx skill/src/cli.ts msg.b64 --threshold 5000000000

# JSON only (for agents):
node --import tsx skill/src/cli.ts msg.b64 --json
```

### Real CLI output: a REJECT (fixture 02) vs a SIGN (fixture 01)

The contrast below is the whole point of the skill. Same command, two opaque
base64 blobs, two opposite verdicts — decided offline, before any signature.

**A dangerous transaction is caught (fixture 02 — an SPL `SetAuthority`):**

```console
$ node --import tsx skill/src/cli.ts skill/fixtures/02_setauthority_reject.b64

================================================================
[ REJECT ]  Contains a REJECT-class danger primitive: SPL Token SetAuthority.
================================================================
message version : legacy
worst severity  : REJECT
static outflow  : 0 lamports
flags           : unknownProgram=false alt=false unverifiedRoles=false decodeFailed=false

findings (1):
  - [REJECT] ix#0 SPL Token SetAuthority
      Matched SetAuthority on spl-token.
      maps to loss: Hands mint/freeze/owner authority to an attacker, who can then mint, freeze, or seize at will.

verdict.json:
{
  "schema": "sign-safe/verdict@1",
  "decision": "REJECT",
  "reason": "Contains a REJECT-class danger primitive: SPL Token SetAuthority.",
  "messageVersion": "legacy",
  "worstSeverity": "REJECT",
  "findings": [
    {
      "id": "spl-set-authority",
      "label": "SPL Token SetAuthority",
      "severity": "REJECT",
      "instructionIndex": 0,
      "programId": "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
      "detail": "Matched SetAuthority on spl-token.",
      "mapsToLoss": "Hands mint/freeze/owner authority to an attacker, who can then mint, freeze, or seize at will."
    }
  ],
  "outflow": { "lamports": "0", "splTransfers": [], "exceedsLamportThreshold": false },
  "flags": { "unknownProgramPresent": false, "altLookupsPresent": false, "rolesUnverified": false, "decodeFailed": false },
  "unknownPrograms": []
}
$ echo $?
20
```

**A benign transaction passes (fixture 01 — a 0.01 SOL System transfer):**

```console
$ node --import tsx skill/src/cli.ts skill/fixtures/01_safe_sol_transfer.b64

================================================================
[ SIGN ]  Recognized instructions within thresholds; no danger primitives, unknown programs, or unverified ALT references. Not a guarantee of intent -- verify the recipients and amounts yourself.
================================================================
message version : legacy
worst severity  : INFO
static outflow  : 10000000 lamports
flags           : unknownProgram=false alt=false unverifiedRoles=false decodeFailed=false

findings (0):
  (none)

verdict.json:
{
  "schema": "sign-safe/verdict@1",
  "decision": "SIGN",
  "reason": "Recognized instructions within thresholds; no danger primitives, unknown programs, or unverified ALT references. Not a guarantee of intent -- verify the recipients and amounts yourself.",
  "messageVersion": "legacy",
  "worstSeverity": "INFO",
  "findings": [],
  "outflow": { "lamports": "10000000", "splTransfers": [], "exceedsLamportThreshold": false },
  "flags": { "unknownProgramPresent": false, "altLookupsPresent": false, "rolesUnverified": false, "decodeFailed": false },
  "unknownPrograms": []
}
$ echo $?
0
```

Even a SIGN verdict refuses to call the transaction "safe": it states what was
checked and hands intent verification back to the human. CLI exit codes mirror
the verdict so scripts and agents can gate on them: **`0 = SIGN`, `10 = HOLD`,
`20 = REJECT`**.

## The danger catalog (10 primitives)

| id | program | detection | severity | maps to loss |
|----|---------|-----------|----------|--------------|
| `spl-set-authority` | SPL Token | SetAuthority (6) | REJECT | mint/freeze/owner authority handoff |
| `token2022-set-authority` | Token-2022 | SetAuthority (6) | REJECT | + extension authorities |
| `token2022-permanent-delegate` | Token-2022 | PermanentDelegate (35) | HOLD | irrevocable seizure of any holder's tokens |
| `bpf-upgrade` | BPF Loader Upgradeable | Upgrade (3) | REJECT | bytecode replacement -> instant rug |
| `bpf-set-upgrade-authority` | BPF Loader Upgradeable | SetAuthority (4) | REJECT | upgrade-authority handoff -> later rug |
| `durable-nonce-advance` | System | AdvanceNonceAccount (4) | HOLD | replay/hold vector (Drift 2026) |
| `durable-nonce-initialize` | System | Initialize/Authorize Nonce (6/7) | HOLD | sets/redirects nonce authority |
| `spl-approve-delegate` | SPL Token | Approve/ApproveChecked (4/13) | HOLD | delegate spend -> silent drain |
| `spl-close-account` | SPL Token | CloseAccount (9) | HOLD | sweeps lamports to a destination |
| `system-large-transfer` | System | Transfer (2) over threshold | HOLD | direct SOL outflow above threshold |

See [skill/references/danger-catalog.md](skill/references/danger-catalog.md) for
full rationale and [skill/catalog/danger-primitives.json](skill/catalog/danger-primitives.json)
for the machine-readable source.

## How it is tested

```
$ npm test
sign-safe test suite -- 10 fixtures

[1]  Golden verdicts (our core vs committed verdict.json)  -- 10 PASS
[2]  Cross-validation (our parser vs @solana/web3.js)       -- 10 PASS  (all fixtures)
[2b] Cross-validation (our parser vs @solana/kit, modern)   -- 10 PASS  (all fixtures)
[3]  Determinism (same bytes -> identical JSON, twice)      -- 10 PASS
[4]  Fail-closed (malformed input -> REJECT, never throws)  --  6 PASS
[5]  Banned-phrase enforcement (no reassurance in verdicts) -- 11 PASS
[6]  Behavioral guards (decoder & verdict fail-closed)      --  8 PASS

PASS 65   FAIL 0
RESULT: ALL GREEN
```

Run in CI on every push/PR via `.github/workflows/ci.yml` (`npm ci` +
type-check + `npm test`), across Node 20 and 22, with a determinism gate (two
runs must be byte-identical) and a fixture-drift guard (`npm run gen-fixtures`
must not change any committed `.b64`).

Solana libraries are used **only** for fixture generation and cross-validation,
never by the core. The cross-check now covers **all 10 fixtures** against **two
independent, current implementations** — `@solana/web3.js` (v1) and
`@solana/kit` (v2, the modern stack) — using kit's
`getCompiledTransactionMessageDecoder` on the same serialized bytes. The core
decoder is our own dependency-free wire parser, so agreeing with both proves it
is correct, not merely self-consistent or pinned to a single legacy library. A
regression cannot quietly co-rewrite a fixture and its golden, because both
oracles would disagree. (The kit section degrades to SKIP if kit is not
installed, so a minimal offline checkout still runs green; CI installs it.)

The banned-reassurance-phrase contract is **executable**, not just prose:
`src/banned.ts` is run over every verdict's narrative fields inside
`buildVerdict`/`rejectVerdict`, so any reason or finding string that reintroduces
"safe" / "no risk" / etc. fails loud (and the gate fails closed to REJECT).

## Repository structure

```
sign-safe-skill/
├── package.json            # build / test / gen-fixtures (no postinstall, no curl)
├── tsconfig.json           # strict, NodeNext, ES2022
├── LICENSE                 # MIT
├── README.md               # this file
├── CLAUDE.md               # how an agent should use this skill
├── commands/
│   └── sign-review.md      # the /sign-review command (frontmatter description)
├── rules/
│   └── signing-output.md   # verdict contract + banned reassurance phrases
└── skill/
    ├── SKILL.md            # thin router hub (frontmatter: name, description)
    ├── references/
    │   ├── verdict-contract.md
    │   ├── danger-catalog.md
    │   └── decode-notes.md
    ├── catalog/
    │   └── danger-primitives.json
    ├── src/
    │   ├── types.ts        # the shared contract
    │   ├── decode.ts       # PURE base64 -> DecodedMessage (legacy + v0)
    │   ├── roles.ts        # PURE header math -> roles, ALT -> unverified
    │   ├── classify.ts     # PURE instruction x catalog -> Finding[]
    │   ├── outflow.ts      # PURE statically-declared signer outflow
    │   ├── banned.ts       # PURE banned-reassurance-phrase enforcement
    │   ├── verdict.ts      # PURE Finding[] -> Verdict + verdict.json
    │   ├── enrich.ts       # IMPURE runtime hooks (NEVER imported by core/tests)
    │   └── cli.ts          # thin CLI wrapper
    ├── fixtures/
    │   ├── generate.ts     # builds the .b64 fixtures with @solana/web3.js
    │   ├── NN_*.b64        # 10 serialized messages
    │   └── NN_*.verdict.json   # 10 golden verdicts
    └── test/
        └── run.ts          # golden + cross-validation + determinism + fail-closed
```

## License

MIT -- see [LICENSE](LICENSE).
