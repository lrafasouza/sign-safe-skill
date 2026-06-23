# Changelog

All notable changes to sign-safe are documented here.
Format: [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] - 2026-06-22

### Added

- **Transfer recipient surfacing / clear-signed transfers** (`src/outflow.ts`,
  `src/types.ts`): every `System Transfer` and `SPL Transfer / TransferChecked`
  instruction now carries a resolved `RecipientRef` + `LamportTransfer` in the
  outflow. The verdict's SIGN reason explicitly names the destination address
  ("sends X lamports to ADDR") so signers see where their funds are going even
  on a SIGN verdict. A new `outboundToNonSigner` flag on `StaticOutflow` is true
  whenever value leaves to an address that is not a message signer — surfaced per
  transfer and rolled up at the outflow level.

- **DeFi/NFT program registry** (`src/registry.ts` +
  `catalog/program-registry.json`, 5 programs, 15 dangerous instructions):
  a second classification tier between the native-program catalog and the
  truly-unknown path. Programs in the registry are named and never trigger the
  blanket unknown-program-writable REJECT path. Instead:
    - A listed dangerous instruction → its configured severity with a clear label.
    - Any instruction on a recognized but uncatalogued path → mandatory HOLD
      (never SIGN). Programs: **Metaplex Token Metadata** (8 dangerous
      instructions: Transfer, Delegate, Revoke, Burn pNFT/legacy,
      UpdateMetadata/V2, Update — REJECT for transfer/burn, HOLD for
      delegate/update), **Metaplex Bubblegum cNFT** (7: Transfer v1/v2, Delegate
      v1/v2, Burn v1/v2, MintTo — REJECT for transfer/burn, HOLD for delegate),
      **Jupiter Aggregator v6** (recognize-only, all instructions HOLD),
      **Orca Whirlpools** (recognize-only, all HOLD),
      **Raydium AMM v4** (recognize-only, all HOLD). NFT drains (Metaplex
      Transfer, Bubblegum Transfer/Burn) are now explicitly named in verdicts
      rather than appearing as generic REJECT.

- **Injectable address-reputation blocklist** (`src/reputation.ts`,
  `VerdictContext.recipientBlocklist`): pass a `ReadonlySet<string>` or
  `readonly string[]` of known-bad base58 addresses as
  `ctx.recipientBlocklist`. The offline core screens all transfer recipients,
  SPL Approve delegates, and SetAuthority new-authorities; any hit becomes a
  REJECT finding `"blocklisted-recipient"`. No-op when no blocklist is provided
  (byte-identical behavior for existing callers). Fetching the blocklist from a
  community API lives in `enrich.ts reconRecipients()` (injectable fetcher,
  never imported by the core).

- **`holdOutboundTransfers` policy flag** (`VerdictContext.holdOutboundTransfers`):
  when true, any SOL or SPL transfer whose recipient is not a signer of the
  message is escalated to at least HOLD (finding `"policy-outbound-transfer"`).
  Self-transfers (signer → signer) are unaffected. Default false — existing
  verdict behavior is unchanged.

- **54 new tests** (3 new test files, 292 total up from 238):
  - `program-registry.test.ts` (30): registry catalog validation, Jupiter HOLD,
    Metaplex Transfer REJECT, Delegate HOLD, Burn REJECT, unrecognized-instruction
    HOLD (fail-closed), Bubblegum Transfer/Burn REJECT, Delegate HOLD, unknown-disc
    HOLD, Orca/Raydium recognized HOLD, truly-unknown-program REJECT unchanged,
    native SPL Transfer still SIGN (no regression), recognized-program never SIGN.
  - `recipient.test.ts` (8): System Transfer recipient surfacing, outboundToNonSigner
    true/false, self-transfer detection, SIGN reason string includes destination,
    SPL Transfer destination index, TransferChecked uses index [2] not [1] (mint),
    ALT-sourced recipient marked unresolved.
  - `reputation.test.ts` (16): blocklist REJECT on SOL transfer, SPL Approve
    delegate REJECT, no blocklist unchanged, holdOutboundTransfers escalation,
    self-transfer not escalated, no-match SIGN, array-form blocklist, screenAddresses
    unit tests (empty/hit/null-skip/multi-hit), reconRecipients injectable (frozen
    stub, fail-open on error, end-to-end with reviewBase64), core isolation invariant.

### Changed

- **Test count**: 238 -> 292 (54 new checks across 3 new test files).
- **Test file count**: 13 -> 16.
- **DeFi/NFT program registry**: 5 recognized programs (15 total dangerous
  instructions across Metaplex Token Metadata and Bubblegum; 3 recognize-only
  programs). Recognized programs are HOLD-with-label, not REJECT.
- README and SKILL.md updated with accurate test counts, new feature descriptions,
  honest coverage section, and repository structure reflecting new source files.

### Invariants preserved

- Offline core is dependency-free: `registry.ts` and `reputation.ts` import
  nothing from the network layer and nothing from `enrich.ts`.
- `enrich.ts` is never imported by any core module (test imports are to
  `enrich.ts` only in `reputation.test.ts` for the `reconRecipients` unit test,
  which tests the non-core enrich layer in isolation — the core modules and
  the core-pipeline tests remain enrich-free).
- Fail-closed: a recognized DeFi/NFT program with an unrecognized instruction
  stays HOLD (never SIGN). A recognized dangerous instruction adds/escalates
  severity; it never turns a value-moving instruction into SIGN.
- All 238 pre-existing tests continue to pass (no regressions).

## [0.2.0] - 2026-06-22

### Added

- **Squads v4 VaultTransaction offline clear-signing** (`src/squads.ts` +
  `src/classify-inner.ts`): given the VaultTransaction PDA account bytes, the
  offline core borsh-decodes the embedded message, resolves inner program IDs
  from the `account_keys` array, and classifies them against the new Anchor
  authority-mutation registry. A Squads execute with an inner `update_admin`
  discriminator is now REJECT with a finding that names the authority transfer
  explicitly ("Anchor: update_admin (admin transfer) [inner, via Squads vault]").

- **Anchor authority-mutation registry** (`catalog/anchor-danger.json`, 11
  entries): discriminator-matched danger catalog for Anchor programs. Entries
  cover admin/owner/authority transfer functions (`update_admin`, `set_admin`,
  `transfer_admin`, `set_owner`, `transfer_ownership`, `set_authority`,
  `update_authority`, `set_upgrade_authority` -- REJECT severity) and
  governance-level mutations (`update_whitelist`, `add_collateral`,
  `update_oracle` -- HOLD severity). A `program: "*"` entry matches any program
  carrying that discriminator; a specific base58 id narrows to one program.

- **Durable-nonce escalation broadening**: a durable-nonce carrier combined with
  ANY non-INFO finding (not just an explicit authority change) escalates to
  REJECT (Drift composite). Previously the composite was limited to
  authority/ownership changes; now unknown programs, delegate grants, and Squads
  HOLD findings alongside a nonce also trigger REJECT.

- **`governanceContext` flag** (`VerdictContext.governanceContext`): when true,
  even a bare durable-nonce transaction with no other finding is escalated to
  REJECT. Models strict privileged-signing policies where non-expiring
  transactions are never acceptable.

- **Out-of-band transaction digest** (`src/digest.ts`): pure SHA-256 of the raw
  message bytes plus a 20-hex-char human-verifiable short code
  (`XXXX-XXXX-XXXX-XXXX-XXXX`) for cross-device byte-identity confirmation.

- **Injectable enrich wrappers** (`src/enrich.ts`): `enrichSquads` (fetches
  VaultTransaction PDA bytes for the second, inner-decoded pass),
  `reconNonceAccounts` (decodes nonce authority, attributes signer-controlled
  nonces), `enrichAlt` (stub for future ALT resolution). All accept injectable
  fetcher callbacks (never a global RPC URL) and are never imported by the core
  or tests.

- **Real mainnet Squads VaultTransaction PDA fixture**
  (`skill/fixtures/real/accounts/squads_vault_transaction.b64` + `.meta.json`,
  344 bytes): frozen from mainnet slot 428217162, account
  `5udTJFsR7jnBTcTV6sRYbmLcDrBC2RK8eVp8rvBYMg5F`. Both inner instructions
  reference ALT-space program IDs (indices 5 and 7 >= 5 account keys), making
  it a natural regression fixture for the ALT-unresolved fail-closed path.

- **55 new tests** (13 test files, 238 total up from 10 files, 183):
  - `squads.test.ts` (28): discriminator math, borsh decode against real fixture,
    ALT-space resolution, structural fail-closed (bad disc, truncation, trailing
    junk, over-long Vec), determinism, purity (no network imports).
  - `squad-verdict.test.ts` (13): Squads execute verdict integration; Drift
    composite (nonce + execute) REJECT; bare nonce stays HOLD (regression guard);
    `governanceContext` escalates to REJECT; never SIGN a Squads execute
    (including zero-instruction vault).
  - `digest.test.ts` (14): SHA-256 correctness, short-code format, determinism,
    out-of-band identity, purity.

### Fixed

- **SKILL.md honesty fix**: previously overstated Squads inner decode as
  automatic. Now accurate: the offline core decodes inner instructions WHEN GIVEN
  the VaultTransaction PDA bytes; fetching those bytes is the `enrichSquads`
  runtime step. The two-pass flow (offline review -> fetch PDA -> offline review
  with inner bytes) is documented explicitly.

- **Fail-closed for empty VaultTransaction**: a vault that decodes to zero inner
  instructions was previously treated as "verified" (no mandatory HOLD injected),
  allowing a Squads execute with an empty instruction vector to reach SIGN.
  Fixed: `squadsExecuteWithoutInner` now fires when `squadsInnerFindings` is
  empty (`length === 0`) in addition to when decode fails or bytes are absent.

### Changed

- **Test count**: 183 -> 238 (55 new checks across 3 new test files).
- **Test file count**: 10 -> 13.
- **Danger primitive coverage**: 35 native-program entries (unchanged) + 11
  Anchor authority-mutation entries (new). Total catalogued danger shapes: 46.
- **No-network assertion (T11.3)** extended to cover `squads.ts` and `digest.ts`.
- README and SKILL.md updated with accurate Squads clear-signing description,
  new test counts, "How sign-safe would have caught Drift" section, and
  repository structure reflecting new source files.

### Invariants preserved

- Offline core is dependency-free: `squads.ts`, `classify-inner.ts`, and
  `digest.ts` import nothing from the network layer and nothing from `enrich.ts`.
- `enrich.ts` is never imported by any core module or test.
- All 183 pre-existing tests continue to pass (no regressions).
- Fail-closed: no new code path can produce SIGN where the previous code
  produced HOLD or REJECT.
