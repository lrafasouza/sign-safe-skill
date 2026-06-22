---
globs:
  - "**/*"
---

# Signing-Output Contract

These rules govern **any** output that describes a sign-safe verdict -- the CLI,
the `/sign-review` command, and any agent narrating a result. They enforce the
contract defined in
[../skill/references/verdict-contract.md](../skill/references/verdict-contract.md).

## 1. The verdict shape is fixed

Every machine-readable result is a `verdict.json` matching schema
`sign-safe/verdict@1`. The `decision` is exactly one of `SIGN`, `HOLD`, `REJECT`.
Do not invent intermediate verdicts or omit required fields.

## 2. Fail-closed framing

- Malformed / truncated / un-parseable input is reported as **REJECT** with
  `flags.decodeFailed = true`. Never report a partial parse as if it succeeded.
- Unresolved ALT references (`altLookupsPresent && rolesUnverified`) cap the
  verdict at **HOLD**. Never present such a transaction as signable.
- Any unknown (uncatalogued) program forbids **SIGN**.

## 3. Banned reassurance phrases (unconditional)

The following substrings are **forbidden** in any verdict-describing output --
human-readable or otherwise -- and the prohibition applies **even when the
verdict is SIGN**. Matching is case-insensitive.

- `safe`
- `totally safe`
- `no risk`
- `looks fine`
- `you can sign this`
- `nothing dangerous`
- `trust me`

> Note: this bans the standalone reassurance word "safe" in verdict narration.
> The skill's own *name* ("sign-safe") and references to "fail-closed" or
> "value-bearing" are fine; what is banned is telling a user a transaction *is
> safe* or that they *can sign it*.

### Why

A signing gate that reassures is worse than useless -- it manufactures false
confidence in exactly the moment a user is most exposed (the Drift April-2026
blind-signing incident is the canonical example). A SIGN verdict means only
"recognized instructions within thresholds"; it is **not** a guarantee of intent.

## 4. SIGN must stay qualified

When the decision is SIGN, the reason must state that it reflects recognized
instructions within thresholds and is **not a guarantee of intent**, and must
direct the operator to verify recipients and amounts themselves. Never shorten a
SIGN reason into an unconditional approval.

## 5. No signing, no keys, no broadcast

Output must never request a private key/seed/keypair, never claim to have signed,
and never claim to have broadcast a transaction. This tool reads bytes only.
