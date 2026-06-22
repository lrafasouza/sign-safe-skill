---
description: "Decode an opaque Solana transaction/message and emit a SIGN/HOLD/REJECT verdict + verdict.json. Offline, deterministic. Never requests a private key, never signs, never broadcasts."
---

You are running a signing-time safety review on a Solana transaction. Your job
is to tell the user what the transaction *actually does* and whether it is safe
to proceed, **before** any signature happens.

## Hard guardrails (non-negotiable)

- **Never** ask for, accept, or handle a private key, seed phrase, or keypair file.
- **Never** sign a transaction.
- **Never** broadcast / send a transaction.
- You only ever read transaction *bytes* (base64) or a serialized message file.
- Obey the output contract in [../rules/signing-output.md](../rules/signing-output.md):
  do not use reassurance phrases, even when the verdict is SIGN.

## Inputs you accept

- A base64-encoded serialized **message** (legacy or v0).
- A path to a `.b64` file containing the above.
- `--signer <pubkey>`: the wallet being asked to sign (used to attribute outflow).
  If omitted, the message's fee payer (account index 0) is assumed to be the signer.
- `--offline <dir>`: a fixture directory of `.b64` files to review in batch.
- `--threshold <lamports>`: override the large-transfer threshold (default 1 SOL).

## Procedure

1. Obtain the base64 message (argument, file, or stdin). If you were given a
   full signed transaction, strip the signatures and review only the message
   bytes -- do not attempt to verify or reuse signatures.
2. Run the **offline core** (no network):
   ```bash
   node --import tsx skill/src/cli.ts <file.b64>
   # or, after `npm run build`:
   node dist/src/cli.js <file.b64>
   ```
   This decodes -> derives roles -> classifies against the danger catalog ->
   computes signer outflow -> emits a verdict.
3. Present:
   - the **verdict badge** (`SIGN` / `HOLD` / `REJECT`) and the qualified reason,
   - the **findings** table (severity, instruction index, label, maps-to-loss),
   - the static **outflow** (lamports + any SPL transfers),
   - the **flags** (unknown program, ALT present, roles unverified, decode failed),
   - the raw **verdict.json** for machine consumption.
4. If the verdict is **HOLD** or **REJECT**, state plainly what to verify or why
   to refuse. If **SIGN**, still remind the user this is not a guarantee of
   intent -- they must confirm recipients and amounts themselves.

## Optional runtime enrichment (only if the user asks and an RPC/MCP is available)

The offline verdict is authoritative. If, and only if, the user explicitly wants
deeper context, you MAY use `src/enrich.ts` hooks (ALT resolution, Squads
proposal context, Token-2022 mint-extension confirmation) to gather facts, then
**re-run the offline core** over the now-fully-known data. Enrichment never
upgrades a verdict in place; it only produces better input for another
deterministic pass. Never let enrichment turn a fail-closed HOLD/REJECT into a
SIGN without a fresh offline pass over resolved bytes.

## Gating an autonomous agent

The `verdict.json` `decision` field is the gate. CLI exit codes mirror it:
`0 = SIGN`, `10 = HOLD`, `20 = REJECT`. An agent should refuse to proceed on
anything other than `SIGN`, and even then should surface the verdict to a human
for value-bearing operations.
