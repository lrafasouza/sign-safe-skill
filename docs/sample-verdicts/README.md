# Sample verdicts

These are verbatim CLI stdout captures (`--json` mode) from real fixtures.
Each file can be reproduced exactly by running the command shown.

## sign.json — SIGN

Source fixture: `skill/fixtures/01_safe_sol_transfer.b64`

```bash
npm run cli -- skill/fixtures/01_safe_sol_transfer.b64 --json
```

A small System-program SOL transfer to a non-signer address. No danger primitive
detected. SIGN — the static policy recognizes this shape as benign. This is not a
guarantee of intent; verify recipients and amounts independently.

## hold.json — HOLD

Source fixture: `skill/fixtures/05_approve_delegate_hold.b64`

```bash
npm run cli -- skill/fixtures/05_approve_delegate_hold.b64 --json
```

An SPL Token `Approve` instruction grants delegate authority over a token account.
The delegate can silently drain the account afterward. HOLD — do not auto-sign;
human review required.

## reject.json — REJECT

Source fixture: `skill/fixtures/02_setauthority_reject.b64`

```bash
npm run cli -- skill/fixtures/02_setauthority_reject.b64 --json
```

An SPL Token `SetAuthority` instruction transfers mint authority to a new key.
A REJECT-class danger primitive is present. CLI exits with code 20.

## squads-hold.json — HOLD (Squads hidden authority, offline)

Source fixture: `skill/fixtures/squads_hidden_authority_hold.b64`

```bash
npm run cli -- skill/fixtures/squads_hidden_authority_hold.b64 --json
```

A Squads v4 `vaultTransactionExecute` instruction without the VaultTransaction PDA
bytes supplied. The inner CPI instructions are unknown offline. HOLD —
`squads-execute-unverified` finding, `requiresHumanReview: true`. Pass `--rpc` (or
`--vault-pda`) to resolve the inner instructions; if they contain an authority
mutation (e.g. `update_admin`), the verdict escalates to REJECT.

This is the canonical offline representation of the Drift blind-signing attack
class: signer sees only the Squads shell; the dangerous inner instruction is hidden
in the VaultTransaction PDA until `--rpc` is provided.
