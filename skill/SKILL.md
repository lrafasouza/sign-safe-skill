---
name: sign-safe
description: Signing-time safety gate for Solana transactions. Decodes an opaque base64 transaction/message, classifies its instructions against a danger-primitive catalog, computes the signer-perspective statically-declared outflow, downgrades unknown programs and unresolved Address-Lookup-Table references, and emits a SIGN / HOLD / REJECT verdict plus a machine-readable verdict.json for autonomous-agent gating. Trigger phrases include "is this transaction safe to sign", "review this tx before I sign", "what does this base64 transaction do", "blind signing", "sign-review", "squads proposal review". Offline, deterministic, and tested. Motivated by the April-2026 Drift blind-signing / durable-nonce incident.
user-invocable: true
---

# sign-safe -- Solana Signing-Time Safety Gate

> **Extends**: solana-dev-skill -- Core Solana development (programs, frontend, testing, security). This skill LAYERS ON the core skill; it does not duplicate it. Install solana-dev-skill alongside for program-level context.

## What This Skill Is For

Use this skill when a user (or an autonomous agent) is about to **sign** a Solana
transaction and wants to know what it actually does *before* approving it.

- "Is this transaction safe to sign?" / "Review this tx before I sign."
- "What does this base64 transaction do?"
- "I'm being asked to blind-sign this -- decode it."
- "Review this Squads proposal / multisig transaction."
- Gating an autonomous agent's signing step on a machine-readable verdict.

It decodes the message, flags **danger primitives** (authority handoffs, program
upgrades, durable nonces, delegate grants, large outflows), and returns a
**SIGN / HOLD / REJECT** verdict with a `verdict.json`.

### What this skill is NOT

| Not this | Use instead |
|----------|-------------|
| A program source-code security audit | `/audit-solana` (program-level audit) |
| A debugger for a transaction that already landed/failed | `/debug-user-tx` (landed-tx reproduction) |
| A replacement for core Solana development knowledge | `solana-dev-skill` (core) |

This skill is purely a **pre-signature gate** over transaction *bytes*.

## Deterministic core (offline)

The entire verdict is produced by a chain of **pure functions** -- no network,
no RPC, no simulation. Same bytes in, same JSON out:

1. **decode** (`src/decode.ts`) -- base64 -> `DecodedMessage`. Our own wire-format
   parser for legacy and v0 messages (compact-u16 lengths, 32-byte pubkeys,
   header bytes, blockhash, compiled instructions, v0 addressTableLookups).
2. **roles** (`src/roles.ts`) -- two-layer writability: the positional partition
   (`is_writable_index`) AND the runtime demotion layer (reserved-account-keys +
   program-id demotion, SIMD-0105), both exposed. ALT-referenced accounts keep
   their real writable/readonly role but are marked `addressVerified: false`
   (their concrete identity cannot be known without an on-chain lookup).
3. **classify** (`src/classify.ts`) -- each instruction x the danger catalog
   (`catalog/danger-primitives.json`) -> `Finding[]`, matched by programId +
   discriminator. Plus `src/tlv.ts`, a pure Token-2022 mint/account TLV extension
   walker (PermanentDelegate / TransferHook / fee / pausable, surfaced on a
   byte-identical plain Transfer).
4. **outflow** (`src/outflow.ts`) -- statically-declared signer outflow: System
   Transfer lamports (when the signer funds it) + SPL transfer/transferChecked
   amounts.
5. **verdict** (`src/verdict.ts`) -- `Finding[]` + context -> `Verdict` + `verdict.json`.

**Fail-closed by construction:** malformed/truncated input -> `REJECT`; any
unresolved ALT reference forces roles `unverified` so the verdict can never be
`SIGN`; any unknown program present forbids `SIGN`.

Any MCP/network use (ALT resolution, Squads PDA fetch, live mint-extension
confirmation) lives ONLY in `src/enrich.ts`, which is **never** imported by the
core or the tests. It is a documented runtime enhancement only.

## Verdict contract

See [references/verdict-contract.md](references/verdict-contract.md) for the exact
`verdict.json` schema, the deterministic decision rules, and the **banned
reassurance phrases**. The output contract is also enforced by
[../rules/signing-output.md](../rules/signing-output.md).

The banned-phrase contract is **executable**: `src/banned.ts` scans every
narrative field of a verdict (`reason`, and each finding's `label` / `detail` /
`mapsToLoss`) with word-boundary matching, and `buildVerdict` / `rejectVerdict`
run it before returning. A reassuring phrase therefore cannot ship — it fails
loud and the gate falls back to a fail-closed REJECT. The skill's own name
("sign-safe") and the schema id are intentionally not narration and are not
scanned. `outflow.lamports` is a base-10 **decimal string** (not a JS number),
so SOL sums above 2^53 lamports stay exact.

## Progressive Disclosure (Read When Needed)

- [references/verdict-contract.md](references/verdict-contract.md) -- verdict.json schema + decision rules + banned phrases
- [references/danger-catalog.md](references/danger-catalog.md) -- rationale for each catalog entry, with real-loss mapping
- [references/decode-notes.md](references/decode-notes.md) -- message parse details, header role math, ALT conservatism, discriminator notes
- [catalog/danger-primitives.json](catalog/danger-primitives.json) -- the machine-readable catalog

### Core Solana dev knowledge (from solana-dev-skill)

> Provided by **solana-dev-skill** -- install if not present. For program-level
> security, IDL/codegen, and testing patterns, defer to that skill by name.

## Task Routing Guide

| User asks about... | Route to |
|--------------------|----------|
| "Is this base64 tx safe to sign?" | this skill -> `/sign-review` |
| "Decode this transaction / what does it do" | this skill -> decode + classify |
| "Review this Squads proposal before approval" | this skill (offline) + `src/enrich.ts` (runtime Squads context) |
| "Gate my agent's signing on a verdict" | this skill -> `verdict.json` decision field |
| Blind-signing / durable-nonce risk | this skill -> danger catalog (durable-nonce entries) |
| Audit a program's source for vulnerabilities | `/audit-solana` |
| Debug a transaction that already failed on-chain | `/debug-user-tx` |
| Build/test/deploy a program | `solana-dev-skill` (core) |

## Commands

| Command | Description |
|---------|-------------|
| [/sign-review](../commands/sign-review.md) | Decode a base64 tx / message file and emit a SIGN/HOLD/REJECT verdict + verdict.json. Never requests a key, never signs, never broadcasts. |

## Agents

| Agent | Status |
|-------|--------|
| (none) | No agents are shipped in the MVP, by design. The verdict is produced by a small, auditable chain of pure functions; spawning a model agent to "decide" would undermine the determinism guarantee. Enrichment (ALT/Squads/mint) is a documented runtime hook in `src/enrich.ts`, not an agent. |
