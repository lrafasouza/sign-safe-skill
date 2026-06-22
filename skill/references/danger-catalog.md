# Danger Primitive Catalog -- Rationale

Human-readable rationale for every entry in
[../catalog/danger-primitives.json](../catalog/danger-primitives.json). The JSON
is the machine-readable source of truth; this file explains *why* each primitive
is dangerous and what concrete loss it maps to. Matching is by canonical mainnet
`programId` plus a leading instruction discriminator.

Severity legend: **REJECT** = never sign as-is; **HOLD** = stop and require human
review; **INFO** = noted, never escalates on its own.

## Authority handoffs (REJECT)

### `spl-set-authority` -- SPL Token `SetAuthority` (disc 6)
- **Program:** SPL Token (`TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA`)
- **Maps to loss:** Hands mint / freeze / account-owner authority to an attacker.
  Once they hold mint authority they can inflate supply; freeze authority lets
  them lock holders; owner authority lets them move funds.

### `token2022-set-authority` -- Token-2022 `SetAuthority` (disc 6)
- **Program:** Token-2022 (`TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb`)
- **Maps to loss:** Everything above, plus control over Token-2022 **extension**
  authorities (transfer hook, transfer-fee config, etc.), which widens the blast
  radius considerably.

### `bpf-upgrade` -- BPF Loader Upgradeable `Upgrade` (disc 3)
- **Program:** BPF Loader Upgradeable (`BPFLoaderUpgradeab1e11111111111111111111111`)
- **Maps to loss:** Replaces a program's executable bytecode. An attacker can
  swap in a draining program in a single instruction -- an **instant rug** of
  every user of that program.

### `bpf-set-upgrade-authority` -- BPF Loader Upgradeable `SetAuthority` (disc 4)
- **Program:** BPF Loader Upgradeable
- **Maps to loss:** Transfers a program's **upgrade authority**. The rug is not
  instant, but the attacker now holds the key to a later upgrade-rug.

### `bpf-set-upgrade-authority-checked` -- BPF Loader Upgradeable `SetAuthorityChecked` (disc 7)
- **Program:** BPF Loader Upgradeable
- **Maps to loss:** The checked variant of the upgrade-authority transfer — same
  loss class as `SetAuthority`. (C15/V4 require all four loader power
  instructions to be caught.)

### `bpf-close` -- BPF Loader Upgradeable `Close` (disc 5)
- **Program:** BPF Loader Upgradeable
- **Maps to loss:** Closes a buffer / programdata account and **drains its
  lamports**; can destroy a program's upgrade data or sweep funds to an attacker.

### `system-assign` -- System `Assign` (disc 1)  ·  `system-assign-with-seed` (disc 10)
- **Program:** System (`11111111111111111111111111111111`)
- **Maps to loss:** Reassigns an account's **owner program** to an arbitrary
  program, handing it full control of the account's data and lamports. V4 treats
  this ownership change as highest-severity.

## Durable nonce vectors (HOLD) — non-expiry only at instruction index 0

### `durable-nonce-advance` -- System `AdvanceNonceAccount` (disc 4)
- **Program:** System (`11111111111111111111111111111111`)
- **Index gate (C17):** a transaction is durable-nonce-backed **only when this is
  instruction index 0**. At index ≥ 1 it is a routine nonce advance and is
  emitted as an INFO note (`nonce-advance-noninitial`), not a HOLD — raising the
  non-expiry flag for a non-initial advance is a false positive.
- **Maps to loss:** A durable nonce **removes blockhash expiry**. A transaction
  signed against a durable nonce does not go stale, so it can be **held and
  replayed later**, at a time of the attacker's choosing. This is the core
  enabling vector of the **Drift April-2026 blind-signing incident**.
- **Drift composite (V3):** a durable-nonce marker at ix0 **plus** any
  authority/ownership change is escalated to **REJECT/CRITICAL** by the verdict
  layer, regardless of the individual findings' severities — a held, non-expiring
  transaction that also hands over authority is the exact Drift signature.

### `durable-nonce-initialize` -- System `Initialize/Authorize NonceAccount` (disc 6/7)
- **Program:** System
- **Maps to loss:** Creates a nonce account or **redirects its authority**,
  setting up or hijacking the durable-nonce hold/replay vector above.

## Spend / sweep grants (HOLD)

### `spl-approve-delegate` -- SPL Token `Approve` / `ApproveChecked` (disc 4/13)
- **Program:** SPL Token
- **Maps to loss:** Grants a **delegate** authority to spend tokens from the
  account. A malicious delegate can **silently drain** the account in a separate,
  later transaction the user never sees.

### `spl-close-account` -- SPL Token `CloseAccount` (disc 9)
- **Program:** SPL Token
- **Maps to loss:** Closes a token account and **sweeps its rent lamports** to a
  destination that may be attacker-controlled. Combined with a prior transfer it
  is a clean-out pattern.

### `token2022-approve-delegate` -- Token-2022 `Approve` / `ApproveChecked` (disc 4/13)
- **Program:** Token-2022
- **Maps to loss:** Identical seizure vector to the SPL Token version, on a
  Token-2022 mint. Token-2022 reuses the base instruction tags (C2), so Approve
  must be catalogued for **both** program ids — otherwise a Token-2022 delegate
  grant would slip through as a clean SIGN.

### `token2022-close-account` -- Token-2022 `CloseAccount` (disc 9)
- **Program:** Token-2022
- **Maps to loss:** Same clean-out / lamport-sweep pattern as the SPL Token
  version, on a Token-2022 account.

### `token2022-permanent-delegate` -- Token-2022 PermanentDelegate (disc 35) (HOLD)
- **Program:** Token-2022
- **Maps to loss:** A **permanent delegate** can move or burn tokens from *any*
  holder of the mint, **irrevocably**. Configuring it, or exercising it, is a
  seizure vector that ordinary holders cannot opt out of.

## Direct outflow (HOLD, threshold-gated)

### `system-large-transfer` -- System `Transfer` over threshold (disc 2)
- **Program:** System
- **Maps to loss:** A direct SOL outflow from the signer above the configured
  threshold (default **1 SOL = 1,000,000,000 lamports**). Small transfers are
  not flagged; large ones demand confirmation of the recipient and amount.

### `system-transfer-with-seed` -- System `TransferWithSeed` (disc 11) (HOLD)
- **Program:** System
- **Maps to loss:** Transfers lamports out of a seed-derived account the signer
  controls — direct SOL outflow via a less obvious path than a plain Transfer.

### `system-withdraw-nonce` -- System `WithdrawNonceAccount` (disc 5) (HOLD)
- **Program:** System
- **Maps to loss:** Withdraws lamports out of a nonce account to an arbitrary
  recipient — a direct SOL drain via a path even less obvious than `TransferWithSeed`.
  (Outflow accounting also widened to count `CreateAccount` (tag 0) and
  `CreateAccountWithSeed` (tag 3, variable-offset lamports) funding so a large
  account-creation can trip the threshold.)

### `spl-withdraw-excess-lamports` / `token2022-withdraw-excess-lamports` — `WithdrawExcessLamports` (disc 38) (HOLD)
- **Program:** SPL Token AND Token-2022 (both expose tag 38)
- **Maps to loss:** Sweeps lamports above rent-exemption out of a token-program-
  owned account to an arbitrary destination — a direct SOL outflow on a single
  signature, via a far less-obvious path than a plain Transfer.

### `spl-unwrap-lamports` / `token2022-unwrap-lamports` — `UnwrapLamports` (disc 45) (HOLD)
- **Program:** SPL Token AND Token-2022
- **Maps to loss:** Transfers lamports out of a native (wrapped-SOL) account to a
  destination that may be attacker-controlled — a direct SOL outflow.

### `spl-batch` / `token2022-batch` — `Batch` (disc 255) (HOLD)
- **Program:** SPL Token AND Token-2022
- **Maps to loss:** Executes a sequence of packed sub-instructions. sign-safe does
  NOT yet decode the inner instructions individually, so a Batch is flagged HOLD
  **wholesale** — it can never silently SIGN, and the operator is told to review
  the batched contents. (Recursive sub-instruction decoding is a planned
  enhancement; HOLD is the fail-closed minimum.)

## Token-2022 extension sub-instructions (outer tag + inner discriminator)

Some Token-2022 extension tags select an extension with byte 0 and a
sub-instruction with byte 1. The catalog matches BOTH bytes (`subDiscriminator`),
so dangerous sub-instructions are flagged while config sub-instructions under the
same tag are not. (Verified against the canonical `solana-program/token-2022`
interface enums.)

### `token2022-confidential-mint` / `token2022-confidential-burn` — `ConfidentialMintBurn` (tag 42, sub 3/4) (HOLD)
- **Maps to loss:** The confidential-balance encodings of MintTo (sub 3) and Burn
  (sub 4) — same supply-inflation / permanent-loss classes as the plain `MintTo`
  and `Burn` the catalog already HOLDs. `InitializeMint` (42, sub 0) is config and
  correctly stays SIGN.

### `token2022-withdraw-withheld-fees` — `TransferFee::WithdrawWithheld` (tag 26, sub 2/3) (HOLD)
- **Maps to loss:** Moves withheld transfer-fee tokens out to a destination under
  the withdraw-withheld authority. `TransferCheckedWithFee` (26, sub 1, a normal
  transfer) and `HarvestWithheldTokensToMint` (26, sub 4, permissionless
  consolidation to the mint) are correctly NOT flagged.

### `token2022-confidential-withdraw-withheld-fees` — `ConfidentialTransferFee::WithdrawWithheld` (tag 37, sub 1/2) (HOLD)
- **Maps to loss:** Confidential variant of the withheld-fee token outflow. The
  harvest/enable/disable sub-instructions (37, sub 3/4/5) are permissionless or
  config and correctly stay SIGN.

## Freeze & supply control (HOLD)

These are mint/freeze-authority powers. A signer being asked to authorize one is
either the legitimate authority performing an admin action or a victim of a
sneaked-in instruction — either way it warrants review, never a silent SIGN.
Catalogued for **both** SPL Token and Token-2022 (C2).

### `spl-freeze-account` / `token2022-freeze-account` -- `FreezeAccount` (disc 10)
- **Maps to loss:** Freezes a holder's token account (the freeze authority's
  power) — the building block of sell-side **honeypots** and transfer denial.

### `spl-mint-to` / `token2022-mint-to` -- `MintTo` / `MintToChecked` (disc 7/14)
- **Maps to loss:** Mints new tokens (the mint authority's power). Unexpected
  **supply inflation** can dilute holders or drain pools and dump on the market.

### `spl-burn` / `token2022-burn` -- `Burn` / `BurnChecked` (disc 8/15)
- **Maps to loss:** **Irreversibly destroys** tokens from the account (callable
  by the owner or an approved delegate). A blind-signed Burn is a permanent,
  unrecoverable loss of the signer's own balance.

## Token-2022 TLV extensions (surfaced even on a byte-identical plain Transfer)

A transfer of a permanent-delegate / transfer-hook / fee token is byte-identical
to a vanilla transfer at the instruction level (C9). The danger lives in the
mint/account **TLV**, not the instruction stream. `src/tlv.ts` is a PURE walker
over *already-fetched* account bytes (the fetch is the online `enrich.ts` hook);
it surfaces PermanentDelegate (ext 12), TransferHook (14), TransferFeeConfig (1),
NonTransferable (9), DefaultAccountState (6), InterestBearing (10),
ScaledUiAmount (25) and Pausable (26) (V5), walks ALL entries, and fail-closes on
a TLV length that runs past the buffer. A base-length (82-byte mint / 165-byte
account) buffer has no account-type byte and no extensions — it is never
over-read.

## Always benign

### ComputeBudget (`ComputeBudget111111111111111111111111111111`)
- ComputeBudget instructions (borsh, single `u8` tag at byte 0: set compute-unit
  limit/price) are **INFO** and never treated as a danger or as an unknown
  program. They are transaction metadata, not value-bearing operations. The
  u32-LE-tag rule is never applied here (it is the System/BPF encoding).
