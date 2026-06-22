# sign-safe -- Signing-Time Safety Gate

You are operating a **signing-time safety gate** for Solana transactions. When a
user (or an autonomous agent) is about to sign an opaque transaction, decode it,
classify it, and emit a SIGN / HOLD / REJECT verdict **before** any signature.

> **Extends**: [solana-dev-skill](https://github.com/solana-foundation/solana-dev-skill)
> -- core Solana development. This skill layers a signing gate on top.

## When to use this skill

Trigger on: "is this transaction safe to sign", "review this tx before I sign",
"what does this base64 transaction do", "blind signing", "sign-review",
"squads proposal review", or any request to gate a signing step.

Do **not** use this skill for:
- auditing a program's source code -> `/audit-solana`
- debugging a transaction that already landed/failed -> `/debug-user-tx`
- general program build/test/deploy -> `solana-dev-skill`

## Hard guardrails

- Never request, accept, or handle a private key, seed phrase, or keypair.
- Never sign a transaction. Never broadcast a transaction.
- You read transaction *bytes* only.
- Obey [rules/signing-output.md](rules/signing-output.md): no reassurance phrases,
  even on SIGN. A SIGN verdict is "recognized instructions within thresholds,"
  not a guarantee of intent.

## How to run it

The verdict comes from a deterministic, **offline** chain of pure functions.
Run the core, do not reason about the bytes yourself:

```bash
node --import tsx skill/src/cli.ts <file.b64>      # or pipe base64 on stdin
node --import tsx skill/src/cli.ts <file.b64> --json
```

Then present the verdict badge + reason, the findings, the static outflow, the
flags, and the raw `verdict.json`. The `decision` field is the gate; CLI exit
codes mirror it (`0 = SIGN`, `10 = HOLD`, `20 = REJECT`).

## Architecture rules (do not violate)

1. The decode -> roles -> classify -> outflow -> verdict chain is **pure**: no
   network, no RPC, no simulation. Same bytes in, same JSON out.
2. Any network/MCP use (ALT resolution, Squads PDA fetch, mint-extension
   confirmation) lives ONLY in `skill/src/enrich.ts`, which is **never** imported
   by the core or the tests. It is a runtime enhancement only; it produces better
   input for another offline pass and never upgrades a verdict in place.
3. **Fail-closed**: malformed input -> REJECT; unresolved ALT references ->
   roles `unverified` -> never SIGN; unknown program present -> never SIGN.

## Development workflow

```bash
npm install
npm run gen-fixtures   # regenerate .b64 fixtures from @solana/web3.js
npm test               # golden + cross-validation + determinism + fail-closed
npm run build          # tsc -> dist/
```

If a fixture's intended verdict and the decoder disagree, **fix the decoder or
the fixture/golden** so they are correct per the decision rules -- never weaken a
test to pass. The cross-check runs our parser against **two** independent,
current implementations -- `@solana/web3.js` (v1) and `@solana/kit` (v2) -- on
all 10 fixtures, precisely to catch a parser that is self-consistent but wrong,
and to keep the project aligned with the modern kit stack. CI (`npm ci` +
type-check + `npm test`, Node 20/22) gates every push/PR.

## Key files

| File | Purpose |
|------|---------|
| [skill/SKILL.md](skill/SKILL.md) | Router hub |
| [skill/references/verdict-contract.md](skill/references/verdict-contract.md) | verdict.json schema + decision rules + banned phrases |
| [skill/references/danger-catalog.md](skill/references/danger-catalog.md) | per-primitive rationale + real-loss mapping |
| [skill/references/decode-notes.md](skill/references/decode-notes.md) | wire format, role math, ALT conservatism, discriminators |
| [skill/catalog/danger-primitives.json](skill/catalog/danger-primitives.json) | machine-readable catalog |
| [commands/sign-review.md](commands/sign-review.md) | the /sign-review command |
| [rules/signing-output.md](rules/signing-output.md) | output contract |

---

**Main skill entry**: [skill/SKILL.md](skill/SKILL.md)
