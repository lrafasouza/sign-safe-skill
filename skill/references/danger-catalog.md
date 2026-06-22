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

## Durable nonce vectors (HOLD)

### `durable-nonce-advance` -- System `AdvanceNonceAccount` (disc 4)
- **Program:** System (`11111111111111111111111111111111`)
- **Maps to loss:** A durable nonce **removes blockhash expiry**. A transaction
  signed against a durable nonce does not go stale, so it can be **held and
  replayed later**, at a time of the attacker's choosing. This is the core
  enabling vector of the **Drift April-2026 blind-signing incident**: signers
  approved a transaction whose durable-nonce framing let it be executed under
  conditions they never intended.

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

## Always benign

### ComputeBudget (`ComputeBudget111111111111111111111111111111`)
- ComputeBudget instructions (set compute-unit limit/price) are **INFO** and
  never treated as a danger or as an unknown program. They are transaction
  metadata, not value-bearing operations.
