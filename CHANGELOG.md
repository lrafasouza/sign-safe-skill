# Changelog

All notable changes to sign-safe are documented here.
Format: [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
