# sign-safe -- Solana Signing-Time Safety Gate

A Claude Code skill (and a runnable TypeScript library) that decodes an opaque
Solana transaction **before you sign it**, classifies it against a danger-primitive
catalog, computes the signer-perspective outflow, and emits a **SIGN / HOLD /
REJECT** verdict plus a machine-readable `verdict.json` for autonomous-agent gating.

> **Extends**: [solana-dev-skill](https://github.com/solana-foundation/solana-dev-skill)
> -- core Solana development (programs, frontend, testing, security). sign-safe
> layers a signing-time gate on top; it does not duplicate the core skill.

## The problem (Drift, 2026)

In late March 2026, signers on Drift's security multisig **blind-signed**
**durable-nonce** transactions that looked routine but transferred administrative
control. A durable-nonce message has no blockhash expiry, so the signed payloads
stayed valid until they were executed on **April 1, 2026** to drain roughly
**$285M** -- a governance/signing compromise, not a smart-contract bug. The
signers saw an inscrutable base64 blob and an "Approve" button: no decode, no
danger classification, no outflow accounting between the blob and their signature.

sign-safe is the missing layer: a deterministic, offline gate that sits between
the bytes and the signature. It is **complementary to** transaction simulation
(Blowfish / Phantom-style) -- static decoding flags authority/ownership and
danger-primitive shapes (which simulation has been shown to miss), while
simulation catches economic/oracle outcomes that static decoding cannot. Use both.

## What it does

Given a base64 message (legacy or v0), the deterministic core:

1. **decodes** the wire format with our own parser (no web3.js dependency in the
   core), enforcing the runtime sanitization invariants (D19),
2. **derives roles** with a **two-layer writability model** — the positional
   partition (`is_writable_index`) AND the runtime demotion layer
   (reserved-account-keys + program-id demotion, SIMD-0105) — exposing both
   modes; Address-Lookup-Table accounts keep their real writable/readonly role
   but are marked `addressVerified: false` (their concrete address is unknown
   offline),
3. **classifies** each instruction against a 22-entry danger catalog covering
   **both SPL Token and Token-2022** (authority/ownership handoffs, program
   upgrade/close, durable nonces incl. nonce withdrawals, delegate/approve
   grants, account closes & freezes, mint/supply changes, large transfers) plus
   a pure Token-2022 TLV extension walker,
4. **computes** the statically-declared signer outflow,
5. **emits** a `SIGN / HOLD / REJECT` verdict + `verdict.json`, escalating the
   Drift composite (durable-nonce marker at ix0 + authority change) to REJECT.

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
- Classifying instructions against a 22-entry danger-primitive catalog
  (authority handoffs, program upgrades, durable nonces, delegate grants,
  account closes, large transfers) plus a pure Token-2022 TLV extension walker.
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
with a deterministic, fully **offline** test suite (`vitest` + `fast-check`),
**164 checks across 10 files** (`npm test`, see exact counts below):

- **10 synthetic golden fixtures** -- serialized messages built with
  `@solana/web3.js`, decoded by *our own* parser, verdicts deep-equal-checked
  against committed `verdict.json` goldens (regenerable, reviewed, with
  `npm run gen-goldens`).
- **5 REAL mainnet fixtures** (`skill/fixtures/real/`) -- captured once from
  `api.mainnet-beta.solana.com` (located via `getSignaturesForAddress`, fetched
  via `getTransaction`), frozen as base64 of the signed **message** bytes with
  full provenance (signature, slot, cluster, capture date — see each
  `*.meta.json`) and decoded **offline** at run time: a legacy System transfer,
  an SPL-Token transfer, a Token-2022 transfer, a v0 tx WITHOUT ALTs, and a v0 tx
  **WITH** ALTs (the most-broken path). No test makes a network call.
- **Differential cross-validation** on EVERY fixture against **two** independent
  references — `@solana/web3.js` (v1) and `@solana/kit` (v2) — on version, header,
  static keys, blockhash, per-instruction program ids / account indexes / data,
  and ALT count; plus a disagreement ⇒ fail-closed (V10) guard.
- **Property-based** (fast-check, seed 42): round-trip identity
  (`encode(decode(b)) === b`), fail-closed on arbitrary `uint8Array`, no
  trailing-byte tolerance, and compact-u16 invariants over `[0, 65535]`.
- **Role-derivation goldens** (SDK `test_is_writable_index` / `test_is_maybe_writable`,
  program-id demotion flip, multi-lookup ordering, reserved-key vs Incinerator).
- **Determinism**, **fail-closed** adversarial inputs (truncation, trailing
  garbage, out-of-range index, unsupported version `0x81`, empty/single-byte),
  **prompt-injection** (decoded data never interpolated, V8), and a
  **no-network** assertion (core modules import no http/https/net/fetch).

## Install

The repo is **self-contained** — the core has no runtime dependency on any
sibling skill, and there is **no postinstall and no curl** anywhere in it. It
installs two ways: as a submodule inside a skills kit, or standalone.

### As a submodule inside `solana-ai-kit` (kit integration)

Add `sign-safe` to an existing kit (e.g. `solanabr/solana-ai-kit`) as a git
submodule, then commit the pointer:

```bash
# from the root of your fork of solanabr/solana-ai-kit
git submodule add https://github.com/lrafasouza/sign-safe-skill .claude/skills/ext/sign-safe
git commit -m "feat: add sign-safe signing-time safety gate as a submodule"

# anyone cloning the kit then pulls the skill in with:
git clone --recurse-submodules https://github.com/solanabr/solana-ai-kit
# or, in an existing checkout:
git submodule update --init --recursive
```

The kit picks up `.claude/skills/ext/sign-safe/skill/SKILL.md` (add a routing row
to the hub `.claude/skills/SKILL.md`), the `/sign-review` command, and the
signing-output rule. The skill references the core `solana-dev-skill` **by name**
only (never by a relative path or a nested submodule), so it composes with the
rest of the kit without creating a second, conflicting dependency graph. (This is
exactly what PR solanabr/solana-ai-kit#34 does.)

### Standalone (clone and run the gate locally)

```bash
git clone https://github.com/lrafasouza/sign-safe-skill sign-safe
cd sign-safe
npm install
npm run gen-fixtures   # (re)generate the 10 synthetic .b64 fixtures from @solana/web3.js
npm test               # vitest: golden + differential (web3.js + kit) + PBT + real fixtures + fail-closed
```

The real mainnet fixtures under `skill/fixtures/real/` are committed (frozen
bytes + provenance) and read offline; `gen-fixtures` does NOT touch them and no
test makes a network call.

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
      SetAuthority on spl-token: authority_type=0 (MintTokens), new_authority=<base58>.
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
      "detail": "SetAuthority on spl-token: authority_type=0 (MintTokens), new_authority=<base58>.",
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

## The danger catalog (22 primitives)

| id | program | detection | severity | maps to loss |
|----|---------|-----------|----------|--------------|
| `spl-set-authority` | SPL Token | SetAuthority (6) | REJECT | mint/freeze/owner authority handoff |
| `token2022-set-authority` | Token-2022 | SetAuthority (6) | REJECT | + extension authorities |
| `token2022-permanent-delegate` | Token-2022 | PermanentDelegate (35) | HOLD | irrevocable seizure of any holder's tokens |
| `bpf-upgrade` | BPF Loader Upgradeable | Upgrade (3) | REJECT | bytecode replacement -> instant rug |
| `bpf-set-upgrade-authority` | BPF Loader Upgradeable | SetAuthority (4) | REJECT | upgrade-authority handoff -> later rug |
| `bpf-set-upgrade-authority-checked` | BPF Loader Upgradeable | SetAuthorityChecked (7) | REJECT | upgrade-authority handoff (checked) |
| `bpf-close` | BPF Loader Upgradeable | Close (5) | REJECT | destroys/drains buffer/programdata account |
| `system-assign` | System | Assign (1) | REJECT | reassigns account owner to arbitrary program |
| `system-assign-with-seed` | System | AssignWithSeed (10) | REJECT | seed-account ownership change |
| `system-transfer-with-seed` | System | TransferWithSeed (11) | HOLD | SOL outflow from a seed-derived account |
| `durable-nonce-advance` | System | AdvanceNonceAccount (4) **at ix0 only** | HOLD | replay/hold vector (Drift 2026); + authority change ⇒ REJECT |
| `durable-nonce-initialize` | System | Initialize/Authorize Nonce (6/7) | HOLD | sets/redirects nonce authority |
| `spl-approve-delegate` | SPL Token | Approve/ApproveChecked (4/13) | HOLD | delegate spend -> silent drain |
| `spl-close-account` | SPL Token | CloseAccount (9) | HOLD | sweeps lamports to a destination |
| `token2022-approve-delegate` | Token-2022 | Approve/ApproveChecked (4/13) | HOLD | delegate spend -> silent drain |
| `token2022-close-account` | Token-2022 | CloseAccount (9) | HOLD | sweeps lamports to a destination |
| `spl-freeze-account` | SPL Token | FreezeAccount (10) | HOLD | freezes a holder -> honeypot / denial |
| `token2022-freeze-account` | Token-2022 | FreezeAccount (10) | HOLD | freezes a holder -> honeypot / denial |
| `spl-mint-to` | SPL Token | MintTo/MintToChecked (7/14) | HOLD | supply inflation -> dilute / dump |
| `token2022-mint-to` | Token-2022 | MintTo/MintToChecked (7/14) | HOLD | supply inflation -> dilute / dump |
| `system-withdraw-nonce` | System | WithdrawNonceAccount (5) | HOLD | SOL drain from a nonce account |
| `system-large-transfer` | System | Transfer (2) over threshold | HOLD | direct SOL outflow above threshold |

See [skill/references/danger-catalog.md](skill/references/danger-catalog.md) for
full rationale and [skill/catalog/danger-primitives.json](skill/catalog/danger-primitives.json)
for the machine-readable source.

## How it is tested

```
$ npm test            # vitest run -- the full suite (exits nonzero on any fail)

 ✓ skill/test/decode.test.ts        (25 tests)   compact-u16 vectors/rejection, D19, versions, fail-closed
 ✓ skill/test/roles.test.ts         (13 tests)   is_writable_index + demotion goldens, multi-lookup, reserved
 ✓ skill/test/classify.test.ts        (21 tests)   Transfer/TransferChecked, SetAuthority, TLV, loader, routing
 ✓ skill/test/catalog-coverage.test.ts (10 tests)   dangerous shapes never SIGN (Token-2022 Approve/Close/Freeze/MintTo, WithdrawNonce, CreateAccount)
 ✓ skill/test/verdict.test.ts         (12 tests)   durable nonce ix0 gate, Drift composite, prompt-injection, V2
 ✓ skill/test/pbt.test.ts             ( 7 tests)   round-trip, fail-closed, no-trailing, compact-u16 (fast-check)
 ✓ skill/test/fixtures.test.ts        (52 tests)   golden + web3.js + kit differential + disagreement + no-network
 ✓ skill/test/real-fixtures.test.ts   (14 tests)   REAL mainnet txs decoded offline + cross-validated
 ✓ skill/test/fulltx.test.ts          ( 9 tests)   full signed-tx input stripped + fail-closed (W011 §7)
 ✓ skill/test/legacy-runner.test.ts   ( 1 test )   runs the standalone node smoke runner

 Test Files  10 passed (10)
      Tests  164 passed (164)
```

There are two entry points: `npm test` (vitest, the full suite) and
`npm run test:fixtures` (the dependency-light standalone node runner, usable in a
minimal checkout and used as the CI determinism oracle). `npm run gen-goldens`
regenerates the committed golden `verdict.json` from the current core (only after
reviewing each decision — the goldens are a security contract).

Run in CI on every push/PR via `.github/workflows/ci.yml` (`npm ci` +
type-check + `npm test`), across Node 20 and 22, with a determinism gate (two
runs of the node runner must be byte-identical) and a fixture-drift guard
(`npm run gen-fixtures` must not change any committed `.b64`).

The real fixtures are captured ONCE and committed; the suite reads the frozen
bytes and makes **no network calls at run time**. Re-capturing is a manual,
out-of-band step (see `skill/fixtures/real/*.meta.json` for provenance).

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

## Validation

A reviewer can reproduce the entire result from a clean clone with three
commands and no network access at test time:

```bash
npm install            # deps for generation + cross-validation only (no postinstall, no curl)
npm run gen-fixtures   # rebuild the 10 synthetic .b64 from @solana/web3.js (deterministic, byte-identical)
npm test               # 164 checks, 10 files, fully offline; exits nonzero on any failure
```

Expected: `Tests  164 passed (164)`, and `git status` clean afterward (the
deterministic generator reproduces the committed `.b64` byte-for-byte). To also
confirm the type contract: `npx tsc --noEmit` (exit 0).

What those 164 checks actually validate:

| Coverage area | Where | What it proves |
|---|---|---|
| **Golden verdicts** | `fixtures.test.ts` | All 10 synthetic fixtures' verdicts deep-equal committed `verdict.json` goldens (the SIGN/HOLD/REJECT contract is frozen). |
| **Dual-reference cross-validation** | `fixtures.test.ts`, `real-fixtures.test.ts` | Our dependency-free decoder agrees with **both** `@solana/web3.js` (v1) and `@solana/kit` (v2) on version, header, static keys, blockhash, per-ix program id/accounts/data, and ALT count — on every fixture. |
| **Property-based** | `pbt.test.ts` | fast-check (seed 42): `encode(decode(b)) === b` round-trip, fail-closed on arbitrary `Uint8Array`, no trailing-byte tolerance, compact-u16 invariants over `[0, 65535]`. |
| **Real mainnet fixtures** | `real-fixtures.test.ts` | 5 frozen mainnet txs (legacy System, SPL-Token, Token-2022, v0 no-ALT, v0 with-ALT) decoded **offline** and cross-validated; each carries a `*.meta.json` with signature, slot, cluster, and capture date for provenance. |
| **SDK role / demotion goldens** | `roles.test.ts` | Two-layer writability against SDK semantics: `is_writable_index` partition, runtime program-id demotion flip (SIMD-0105), multi-lookup ordering, reserved-key set vs Incinerator, ALT accounts marked `addressVerified: false`. |
| **Full-tx input + untrusted data (W011)** | `fulltx.test.ts` | A full signed transaction (signatures + message) is detected, its signatures stripped (never verified), and the inner message reaches the same verdict as the bare message; a mismatched signature count or non-canonical garbage fails closed; decoded on-chain strings are surfaced as data, never obeyed. |
| **Catalog coverage (never false-SIGN)** | `catalog-coverage.test.ts` | The dangerous shapes most easily missed — Token-2022 `Approve`/`CloseAccount`/`Freeze`/`MintTo`, System `WithdrawNonceAccount`, and a large `CreateAccount` funding — must **never** return SIGN; small/benign equivalents still SIGN (no over-flagging). Closes the SPL-vs-Token-2022 asymmetry. |
| **Fail-closed / adversarial** | `decode.test.ts`, `verdict.test.ts` | Truncation, trailing garbage, out-of-range index, unsupported version `0x81`, empty/single-byte → REJECT; unresolved ALT can never SIGN; unknown program writing a value-bearing account → REJECT; cross-oracle disagreement ⇒ fail-closed (V10); prompt-injection (decoded data never interpolated, V8); banned reassurance phrases fail loud. |
| **Determinism** | `run.ts` + CI | The standalone node runner's output is byte-identical across two runs (no timing/nondeterminism in the core). |
| **No-network** | `fixtures.test.ts` | Core modules import no `http`/`https`/`net`/`fetch`; the suite makes zero network calls at run time. |

> **On `npm audit`:** any advisories come exclusively from **dev** dependencies
> (the `vitest`/`vite`/`esbuild` toolchain and `@solana/web3.js`'s transitive
> deps used only for fixture generation + cross-validation). The shipped runtime
> core has **zero** dependencies (`"dependencies": {}`), so none of these reach a
> consumer of the skill.

CI (`.github/workflows/ci.yml`) runs exactly this on every push and PR across
Node 20 and 22, plus a determinism gate (two byte-identical runner runs) and a
fixture-drift guard (`gen-fixtures` must not change any committed `.b64`). The
real fixtures are committed, so CI never depends on the network — it just decodes
the frozen bytes.

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
    │   ├── types.ts        # the shared contract (two-layer role model)
    │   ├── decode.ts       # PURE base64 -> DecodedMessage (legacy + v0) + re-encoder
    │   ├── roles.ts        # PURE two-layer writability (partition + demotion) + reserved set
    │   ├── classify.ts     # PURE instruction x catalog -> Finding[]
    │   ├── outflow.ts      # PURE statically-declared signer outflow
    │   ├── tlv.ts          # PURE Token-2022 mint/account TLV extension walker
    │   ├── banned.ts       # PURE banned-reassurance-phrase enforcement
    │   ├── verdict.ts      # PURE Finding[] -> Verdict + verdict.json (Drift composite)
    │   ├── enrich.ts       # IMPURE runtime hooks (NEVER imported by core/tests)
    │   └── cli.ts          # thin CLI wrapper
    ├── fixtures/
    │   ├── generate.ts     # builds the synthetic .b64 fixtures with @solana/web3.js
    │   ├── gen-goldens.ts  # regenerates the golden verdict.json from the core
    │   ├── NN_*.b64        # 10 synthetic serialized messages
    │   ├── NN_*.verdict.json   # 10 golden verdicts
    │   └── real/           # REAL mainnet fixtures (frozen .b64 + .meta.json provenance)
    └── test/
        ├── helpers.ts          # offline message-byte builders + fixture loaders
        ├── decode.test.ts      # wire-format / compact-u16 / sanitization / fail-closed
        ├── roles.test.ts       # role-derivation goldens (partition + demotion)
        ├── classify.test.ts    # instruction classification + TLV
        ├── verdict.test.ts     # durable nonce / Drift composite / prompt-injection
        ├── pbt.test.ts         # fast-check property-based tests (seed 42)
        ├── fixtures.test.ts    # golden + web3.js/kit differential + no-network
        ├── real-fixtures.test.ts # real mainnet txs decoded offline + cross-validated
        ├── legacy-runner.test.ts  # wraps run.ts so it is part of `npm test`
        └── run.ts              # standalone node smoke runner (npm run test:fixtures)
```

## License

MIT -- see [LICENSE](LICENSE).
