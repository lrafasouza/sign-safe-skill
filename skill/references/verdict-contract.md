# Verdict Contract

The single source of truth for the `verdict.json` shape and the decision rules.
This is what autonomous agents gate on. It is produced by `src/verdict.ts`,
which is a **pure function** of the decoded message and a tunable context.

## `verdict.json` schema (`sign-safe/verdict@1`)

```jsonc
{
  "schema": "sign-safe/verdict@1",
  "decision": "SIGN" | "HOLD" | "REJECT",
  "requiresHumanReview": false,       // true for HOLD/REJECT; false for SIGN
  "reason": "string",                 // qualified, factual; never reassuring
  "messageVersion": "legacy" | 0,
  "worstSeverity": "INFO" | "HOLD" | "REJECT",
  "findings": [
    {
      "id": "string",                 // catalog id, or synthetic id
      "label": "string",
      "severity": "INFO" | "HOLD" | "REJECT",
      "category": "string",           // closed FindingCategory taxonomy
      "instructionIndex": 0,
      "programId": "base58",
      "detail": "string",
      "mapsToLoss": "string"          // concrete real-world loss enabled
    }
  ],
  "outflow": {
    "lamports": "0",                  // statically-declared signer SOL outflow,
                                      // base-10 DECIMAL STRING (exact past 2^53)
    "splTransfers": [
      { "instructionIndex": 0, "programId": "base58", "amount": "string" }
    ],
    "exceedsLamportThreshold": false
  },
  "flags": {
    "unknownProgramPresent": false,
    "altLookupsPresent": false,
    "rolesUnverified": false,
    "decodeFailed": false             // true => input could not be parsed
  },
  "unknownPrograms": ["base58", ...]
}
```

`requiresHumanReview` is the single agent-gating boolean: it is `false` only
when `decision === "SIGN"`, and `true` when the decision is `HOLD` or `REJECT`.

`Finding.category` is one of:

`authority-change`, `ownership-transfer`, `value-outflow`,
`delegate-approval`, `token-operation`, `token-2022-extension`,
`program-upgrade`, `durable-nonce`, `unknown-program`, `screening`,
`simulation`, `structural`, `squads`, `program-interaction`, or `policy`.

### Forward compatibility

The schema is additive within `sign-safe/verdict@1`. Consumers must ignore
unknown object fields and tolerate unknown future `category` values rather than
rejecting or mis-parsing the entire verdict. Security gates should continue to
use `decision` or `requiresHumanReview` as the authoritative action signal.

## Decision rules (deterministic, worst-severity wins)

v0.4 operates in a **two-tier posture by default** (calibrated against 100 real
benign mainnet transactions, 0 false-REJECTs). Pass `--strict` / `ctx.strict`
to restore the aggressive single-tier behavior.

Evaluated in this exact order:

1. **REJECT** if **any** of:
   - any `Finding.severity === "REJECT"`, or
   - decode failed (malformed / truncated / trailing bytes / unsupported version), or
   - a blocklist-matched recipient, delegate, or new-authority (`"blocklisted-recipient"`), or
   - an explicit Anchor authority-mutation discriminator matched on an inner instruction
     (e.g. `update_admin`, `set_admin`, `transfer_ownership` — REJECT-class entries in
     `catalog/anchor-danger.json`), or
   - a **real authority/ownership change** alongside a durable-nonce advance at ix0
     (the "Drift composite": `driftComposite = true`), or
   - `governanceContext` is true and a durable-nonce advance is present (bare nonce →
     REJECT in governance mode regardless of other findings), or
   - **`--strict` mode** and an **unknown program is writable on a value-bearing account**.

2. else **HOLD** if **any** of:
   - any `Finding.severity === "HOLD"`, or
   - any unknown program is present (default mode: unknown writable → HOLD, not REJECT), or
   - (`altLookupsPresent` **and** `rolesUnverified`), or
   - `outflow.lamports` exceeds the configured threshold (default 1 SOL = `1_000_000_000` lamports), or
   - a durable-nonce advance at ix0 with no REJECT-class companion (bare nonce in default mode).

3. else **SIGN** -- only when there are **zero** non-INFO findings, **zero**
   unknown programs, and **no** unverified ALT roles.

`worstSeverity` is the maximum severity across all findings (`INFO < HOLD < REJECT`).

### Default vs `--strict` summary

| Condition | Default | `--strict` |
|-----------|---------|-----------|
| Unknown program, writable, value-bearing | HOLD | REJECT |
| Durable nonce + any non-INFO finding | REJECT only if REJECT-class companion | REJECT on any non-INFO finding |
| Bare durable nonce, no other findings | HOLD | HOLD |
| `governanceContext` + bare nonce | REJECT | REJECT |

### SIGN is always qualified

A `SIGN` verdict means *"recognized instructions within thresholds; no danger
primitives, unknown programs, or unverified ALT references."* It is explicitly
**not** a guarantee of intent. The `reason` field for SIGN always carries this
qualification and instructs the operator to verify recipients and amounts.

### Fail-closed invariants

- ALT lookups present and roles unverified => the verdict can **never** be SIGN.
- Any unknown (uncatalogued) program present => the verdict can **never** be SIGN.
- Any decode failure => REJECT with `flags.decodeFailed = true`. The core never
  throws on bad input; it returns a REJECT verdict.

## Exit codes (CLI)

The `/sign-review` CLI maps the verdict to a process exit code so scripts and
agents can gate on it directly:

| Decision | Exit code |
|----------|-----------|
| SIGN | 0 |
| HOLD | 10 |
| REJECT | 20 |

## Banned reassurance phrases

Any output describing a verdict -- human-readable or otherwise -- is forbidden
from using reassurance language. This is **unconditional**: even a SIGN verdict
must not claim safety. Forbidden substrings (case-insensitive):

- "safe"
- "totally safe"
- "no risk"
- "looks fine"
- "you can sign this"
- "nothing dangerous"
- "trust me"

The verdict reason strings and findings emitted by `src/verdict.ts` are written
to comply. See [../../rules/signing-output.md](../../rules/signing-output.md) for
the enforcement rule that applies to any agent narrating a verdict.

**This is enforced in code, not just documented.** `src/banned.ts` exposes a
pure `assertNoBannedPhrase` / `findBannedPhrase` pair, and `buildVerdict` /
`rejectVerdict` run every narrative field (`reason`, and each finding's
`label` / `detail` / `mapsToLoss`) through it before returning. Matching is
case-insensitive and **word-boundary anchored**, so the standalone word "safe"
is banned while the skill's own name "sign-safe", the schema id
"sign-safe/verdict@1", and compounds like "fail-closed" / "value-bearing" are
allowed. A violation throws; the verdict layer converts that into a fail-closed
REJECT, so a reassuring SIGN can never be emitted. The test suite asserts this
over every fixture verdict and over the matcher itself
(positive + negative cases).
