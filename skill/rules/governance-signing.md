# Governance Signing Rules

Rules for agents reviewing transactions in privileged or governance signing contexts.
These rules are additive and conservative: they supplement, never replace, the offline
sign-safe verdict. A transaction that is REJECT stays REJECT; these rules add conditions
under which additional transactions must be escalated to HOLD or REJECT.

## Rule 1: Durable nonce on a governance action is a hard stop

A transaction that uses a durable nonce (AdvanceNonceAccount at instruction index 0,
System program `11111111111111111111111111111111`) combined with ANY of the following
is an automatic REJECT regardless of the individual instruction severities:

- Any admin or authority transfer (inner or top-level)
- Any program upgrade
- Any Squads vaultTransactionExecute whose inner content has not been decoded
- Any unknown or uncatalogued program
- Any HOLD-severity finding other than the nonce advance itself

Rationale: a signed, non-expiring transaction (durable nonce) can be held by an
attacker and replayed at any future moment -- after personnel changes, after a
protocol emergency, after social engineering. This is exactly the Drift blind-signing
attack class (~$285M). In a governance context there is no legitimate use case for
a non-expiring transaction; governance votes use on-chain timeclocks, not durable
nonces.

To enable the hard stop in sign-safe: set `governanceContext: true` in VerdictContext.
This escalates even a bare durable-nonce transaction (no other finding) to REJECT.

## Rule 2: Verify the digest out of band

Before approving any governance transaction, compute the transaction digest on a
second, independent device:

```
node --import tsx skill/src/cli.ts <message.b64> --digest
```

The short code (format: XXXX-XXXX-XXXX-XXXX-XXXX) must match on both devices.
A mismatch means the bytes were modified in transit -- do not sign.

The full sha256 provides the strongest guarantee. The short code (80 bits of the
sha256) is human-readable for verbal or written confirmation.

## Rule 3: Zero-timelock admin configs are red flags

An admin configuration with zero timelock means authority changes take effect
immediately, with no delay for other council members to react. Treat any admin
config with `timelockSeconds == 0` or equivalent as a HOLD finding requiring
explicit acknowledgement.

Combined with a durable-nonce transaction, a zero-timelock admin config is
REJECT (the attack window is unbounded: the nonce never expires and the change
takes effect instantly on execution).

## Rule 4: Unknown inner instructions in Squads proposals must never be signed blind

A Squads vaultTransactionExecute instruction executes whatever is stored inside the
VaultTransaction PDA via CPI. Those inner instructions are NOT visible in the signed
top-level message. The offline sign-safe verdict is HOLD when no inner bytes are
provided (finding id: "squads-execute-unverified").

Never sign a Squads proposal whose inner instruction has not been decoded. The
procedure when RPC is available:

1. Run sign-safe offline on the signed message. If verdict is HOLD with
   "squads-execute-unverified", proceed to step 2.
2. Extract the VaultTransaction PDA address: it is the second account (account index 1)
   of the vaultTransactionExecute instruction in the top-level message.
3. Fetch the PDA: call `enrichSquads(vtAddress, getAccountInfo)` (see enrich.ts).
   This returns the raw account bytes.
4. Re-run sign-safe with the PDA bytes:
   `reviewBase64(b64, ctx, vtBytes)`
   The second verdict now shows the decoded inner instructions.
5. Only proceed to sign if the second verdict is acceptable and all inner
   instructions are recognized and non-dangerous.

If the PDA cannot be fetched (RPC unavailable, account not found, decode error),
the verdict remains HOLD. Do not sign: "cannot verify" is not "verified safe".

## Rule 5: Escalation is one-way (fail-closed preserved)

These rules only ADD findings or ESCALATE verdicts. They never:
- Turn a REJECT into HOLD or SIGN
- Turn a HOLD into SIGN
- Suppress or remove an existing finding

A verdict produced by applying these rules is always >= the offline sign-safe verdict
in severity. If any of these rules conflicts with a downstream system that wants to
downgrade the verdict, the downgrade must be rejected.

## Summary decision matrix

| Top-level content                          | Inner decoded? | Verdict floor |
|---------------------------------------------|---------------|---------------|
| Durable nonce + any HOLD/REJECT finding     | n/a           | REJECT        |
| Durable nonce + unknown program             | n/a           | REJECT        |
| Squads execute + inner admin transfer       | yes           | REJECT        |
| Squads execute + inner unresolved program   | yes (unresolved) | HOLD       |
| Squads execute, inner not fetched           | no            | HOLD          |
| Durable nonce alone (governanceContext=true)| n/a           | REJECT        |
| Durable nonce alone (governanceContext=false)| n/a          | HOLD          |
| Clean transaction, all recognized           | n/a           | SIGN (qualified) |

"SIGN (qualified)" means sign-safe recognized all instructions and found no
danger primitives -- it does NOT mean the transaction is intent-safe. Always
verify recipients, amounts, and program addresses yourself.
