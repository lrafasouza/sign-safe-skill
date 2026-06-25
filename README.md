# sign-safe -- Solana Signing-Time Safety Gate

![CI](https://github.com/lrafasouza/sign-safe-skill/actions/workflows/ci.yml/badge.svg)

A Claude Code skill (and a runnable TypeScript library) that decodes an opaque
Solana transaction **before you sign it**, classifies it against a danger-primitive
catalog, computes the signer-perspective outflow, and emits a **SIGN / HOLD /
REJECT** verdict plus a machine-readable `verdict.json` for autonomous-agent gating.

> **Extends**: [solana-dev-skill](https://github.com/solana-foundation/solana-dev-skill)
> -- core Solana development (programs, frontend, testing, security). sign-safe
> layers a signing-time gate on top; it does not duplicate the core skill.

## What's new in v0.5

- **Transaction simulation** (`--simulate`, escalate-only): parses `simulateTransaction`
  `innerInstructions` + pre/post balances to surface real signer outflow and catch
  swap-output drains (proceeds routed to a non-signer). Advisory only — never downgrades
  a static REJECT.
- **Native Stake program**: Authorize / AuthorizeChecked / AuthorizeWithSeed → REJECT
  (authority transfer); Withdraw → HOLD (REJECT under `--strict`).
- **Programmatic API + adapters**: import `reviewBase64` / `reviewWithEnrichment` directly,
  or pass a web3.js / `@solana/kit` transaction via `sign-safe-skill/adapters`. Zero-dependency
  core; web3.js + kit are optional peers.
- **Signing gate + MCP**: `guardedSignTransaction` / MWA wrapper throws on REJECT *before*
  the key is touched; a zero-dep `sign-safe-mcp` stdio server exposes `review_transaction` to agents.
- **Verdict schema**: a `requiresHumanReview` boolean + a closed `Finding.category` taxonomy
  for machine consumers.
- **More coverage**: durable-nonce fee-payer asymmetry (the Drift council shape), the
  Lighthouse guard as an INFO-only positive signal, and Marginfi v2 + Squads v4 in
  the registry.
- **725 tests across 35 files** (up from 607/29 in v0.4), including a 13-case adversarial
  threat sweep; the precision report now leads with benign SIGN precision + HOLD rate.

## What's new in v0.4

- **Online enrichment** (`--rpc <url>`): resolves Address Lookup Tables, auto-fetches
  and clear-signs Squads VaultTransaction PDA inner instructions, and screens Token-2022
  mint extensions (PermanentDelegate / TransferHook). Without `--rpc`, behavior is
  byte-identical and fully offline.
- **Two-tier posture (default)**: an unknown program writing a value-bearing account
  is now HOLD instead of REJECT, calibrated by a precision study on 100 real benign
  mainnet transactions (0 false-REJECTs). Use `--strict` to restore the aggressive
  single-tier posture for institutional signing.
- **Clear-signing registry expanded to 12 programs**: Metaplex Token Metadata,
  Metaplex Bubblegum, Jupiter v6, Orca Whirlpools, Raydium AMM v4, Pump.fun,
  Pump AMM/PumpSwap, Raydium CLMM, Raydium CPMM, Drift, Kamino klend, Meteora DLMM,
  Programs may have safe and dangerous instruction tiers or recognize-only coverage;
  unlisted instructions remain HOLD.
- **Precision study** (`docs/precision-report.md`): 100 real frozen mainnet benign
  transactions + 37 synthetic malicious patterns. Default: 33% SIGN / 67% HOLD /
  0% false-REJECT. Malicious recall: 100%.
- **607 tests across 29 files** (up from 292/16 in v0.3).
- **`--vault-pda <pubkey>`** overrides the auto-extracted Squads PDA address.
- **`--digest`** prints the SHA-256 short code for cross-device byte-identity confirmation.
- **`--json`** emits `verdict.json` only (machine-readable, no human prose).
- **`--threshold <lamports>`** overrides the large-transfer HOLD threshold.

## The problem (Drift, 2026)

In late March 2026, signers on Drift's security multisig **blind-signed**
**durable-nonce** transactions that looked routine but transferred administrative
control. A durable-nonce message has no blockhash expiry, so the signed payloads
stayed valid until they were executed on **April 1, 2026** to drain roughly
**$285M** -- a governance/signing compromise, not a smart-contract bug
([Chainalysis](https://www.chainalysis.com/blog/lessons-from-the-drift-hack/),
[TRM Labs](https://www.trmlabs.com/resources/blog/north-korean-hackers-attack-drift-protocol-in-285-million-heist)).
The signers saw an inscrutable base64 blob and an "Approve" button: no decode, no
danger classification, no outflow accounting between the blob and their signature.

sign-safe is the missing layer: a deterministic, offline gate that sits between
the bytes and the signature. It is **complementary to** transaction simulation
(Blowfish / Phantom-style) -- static decoding flags authority/ownership changes and
danger-primitive shapes [that simulation has been shown to miss](https://www.coinspect.com/blog/transaction-simulation-challenges/)
([Blockaid](https://www.blockaid.io/blog/bypasses-how-attackers-evade-transaction-simulation)),
while simulation catches economic/oracle outcomes that static decoding cannot. Use both.

sign-safe is also positioned as the **wallet-side, usable-today complement to
[sRFC 39 "Solana Clear Sign"](https://github.com/solana-foundation/SRFCs/discussions/4)**:
it does not require per-program IDL adoption or wallet firmware changes — it runs
as a CLI gate or agent skill over any base64 message, today.

### How sign-safe would have caught Drift

The Drift attack had two layers: the transaction was (1) a **durable-nonce
carrier** (non-expiring, can be replayed at any future block), and (2) executed
via a **Squads `vaultTransactionExecute`** whose CPI inner instruction was an
**`update_admin`** -- an admin authority transfer to the attacker's address.
Neither piece was visible in the signed top-level message bytes; signers saw only
the Squads program id and an opaque 8-byte discriminator.

With sign-safe:

1. **Durable nonce alone is NEVER SIGN.** An `AdvanceNonceAccount` at ix0 forces
   at minimum HOLD -- a non-expiring transaction is always flagged regardless of
   the rest of the payload.

2. **Squads execute without inner bytes is NEVER SIGN.** The offline core detects
   `vaultTransactionExecute` by program id + Anchor discriminator (`c208a15799a4…`)
   and injects a mandatory HOLD finding (`squads-execute-unverified`). A signer
   cannot approve without first fetching the VaultTransaction PDA bytes.

3. **Durable nonce + a REJECT-class inner danger = REJECT (Drift composite).** In
   default mode, nonce + the mandatory unverified-Squads HOLD remains HOLD until
   the VaultTransaction is fetched or another REJECT-class danger is present.
   `--strict` broadens nonce + any non-INFO finding to REJECT.

4. **With `--rpc` (or the VaultTransaction PDA bytes), the inner `update_admin` is
   decoded and named.** The offline core borsh-decodes the `VaultTransaction`,
   resolves inner program IDs from the embedded `account_keys` array, and classifies
   the leading 8 bytes against the Anchor authority-mutation registry. It finds
   `a1b028d53cb8b3e4` = `update_admin` -> REJECT, emitting a finding labelled
   **"Anchor: update_admin (admin transfer) [inner, via Squads vault]"**. The signer
   now sees exactly what they are about to approve: not a Squads shell, but an admin handoff.

Verdict path summary: `durable-nonce at ix0` + `squads-execute-unverified` ->
**HOLD** by default (REJECT under `--strict`). With the PDA bytes, nonce +
`anchor-inner-update_admin` -> **REJECT**, exit code 20, before any key is touched.

## What it does

Given a base64 message (legacy or v0), the deterministic core:

1. **decodes** the wire format with our own parser (no web3.js dependency in the
   core), enforcing the runtime sanitization invariants (D19),
2. **derives roles** with a **two-layer writability model** — the positional
   partition (`is_writable_index`) AND the runtime demotion layer
   (reserved-account-keys + program-id demotion, SIMD-0105) — exposing both
   modes; Address-Lookup-Table accounts keep their real writable/readonly role
   but are marked `addressVerified: false` (their concrete address is unknown
   offline),
3. **classifies** each instruction against a 35-entry danger catalog covering
   **both SPL Token and Token-2022** (authority/ownership handoffs, program
   upgrade/close, durable nonces incl. nonce withdrawals, delegate/approve
   grants, account closes & freezes, mint/supply changes, token burns, large
   transfers) plus a pure Token-2022 TLV extension walker, **and** against a
   **14-program DeFi/NFT registry** (Metaplex Token Metadata, Bubblegum cNFT,
   Jupiter v6, Orca Whirlpools, Raydium AMM v4, Pump.fun, Pump AMM/PumpSwap,
   Raydium CLMM, Raydium CPMM, Drift, Kamino klend, Meteora DLMM, Marginfi v2,
   Squads v4) that names
   NFT transfers/burns and has a safe-instruction tier so routine swaps SIGN,
4. **surfaces transfer recipients** in every SOL and SPL transfer -- the verdict
   and SIGN reason explicitly name the destination address ("sends X lamports to
   ADDR"), and an `outboundToNonSigner` flag identifies when value leaves to an
   external address,
5. **screens recipients, delegates, and new-authorities** against an optional
   injectable drainer blocklist (`ctx.recipientBlocklist`): any match becomes a
   REJECT finding. An optional `holdOutboundTransfers` policy flag escalates all
   external-recipient transfers to at least HOLD,
6. **computes** the statically-declared signer outflow,
7. **emits** a `SIGN / HOLD / REJECT` verdict + `verdict.json`, escalating the
   Drift composite (durable-nonce marker at ix0 + authority change) to REJECT,
8. **clear-signs Squads v4 proposals** (WHEN given the VaultTransaction PDA
   bytes, or automatically with `--rpc`): offline borsh-decodes the PDA, resolves
   inner program IDs from the embedded account_keys array, classifies them against
   the 11-entry **Anchor authority-mutation registry** (`catalog/anchor-danger.json`),
   and folds the inner findings into the verdict,
9. **computes a deterministic transaction digest** (`digest.ts`, SHA-256 with a
   20-hex-char human-verifiable short code `XXXX-XXXX-XXXX-XXXX-XXXX`) so
   signers can confirm byte identity across devices out-of-band.

**Fail-closed by construction:** malformed input -> REJECT; unresolved ALT
references can never produce SIGN; truly unknown programs can never produce
SIGN, and in `--strict` mode if they write to a value-bearing account they force
REJECT; a recognized DeFi/NFT program with an unrecognized instruction is HOLD,
never SIGN.

### The SIGN / HOLD / REJECT contract

The verdict is a three-way, severity-ordered decision. The decision is always
the **worst** outcome triggered by any instruction (REJECT dominates HOLD
dominates SIGN), and the exit code mirrors it so agents and scripts can gate on
it directly.

| Verdict | Exit | Meaning | Triggered by |
|---------|------|---------|--------------|
| **SIGN** | `0` | Every instruction is recognized and within thresholds. Still *not* a guarantee of intent — verify recipients and amounts yourself. | No danger primitives, no unknown programs, no unverified ALT references, outflow under threshold. |
| **HOLD** | `10` | Needs a human. Plausibly legitimate but capable of loss; do not auto-sign. | Delegate grants, account closes, durable-nonce setup, permanent-delegate, large transfers, unknown programs (default mode), or any unverified ALT reference. |
| **REJECT** | `20` | Do not sign. Either a catastrophic primitive or the bytes could not be trusted. | Authority handoffs, program upgrades, the Drift-style durable-nonce composite, blocklist hits, decode failure, or (in `--strict` mode) an unknown program writing to a value-bearing account. |

A SIGN verdict is deliberately the weakest claim in the system: it says "nothing
in this blob is recognized as dangerous," never "this is safe."

## Quickstart

```bash
git clone https://github.com/lrafasouza/sign-safe-skill sign-safe
cd sign-safe
npm install
npm run gen-fixtures   # (re)generate the 10 synthetic .b64 fixtures from @solana/web3.js
npm test               # 725 tests across 35 files
```

### Offline (no RPC required)

```bash
# Review a base64 message file:
node --import tsx skill/src/cli.ts skill/fixtures/02_setauthority_reject.b64

# Pipe base64 on stdin:
cat msg.b64 | node --import tsx skill/src/cli.ts

# JSON only (for agents):
node --import tsx skill/src/cli.ts msg.b64 --json

# Override the large-transfer threshold (lamports):
node --import tsx skill/src/cli.ts msg.b64 --threshold 5000000000

# Compute the SHA-256 short code for cross-device confirmation:
node --import tsx skill/src/cli.ts msg.b64 --digest

# Institutional / strict mode (unknown writable -> REJECT):
node --import tsx skill/src/cli.ts msg.b64 --strict
```

### With RPC (ALT resolution + Squads auto-clear-sign)

`--rpc` is a trusted enrichment input. A malicious or faulty endpoint can withhold or falsify enrichment, but it cannot remove or downgrade findings derived from the signed transaction bytes. Helius MCP/RPC is a natural production backend; record the endpoint and treat its responses as provenance-bearing data.

```bash
# v0 transaction with ALTs: resolves lookup tables, upgrades HOLD -> SIGN if clean
node --import tsx skill/src/cli.ts msg_v0.b64 --rpc https://api.mainnet-beta.solana.com

# Squads proposal: auto-fetches the VaultTransaction PDA and decodes inner instructions
node --import tsx skill/src/cli.ts squads_propose.b64 --rpc https://api.mainnet-beta.solana.com

# Override the auto-extracted Squads vault PDA address:
node --import tsx skill/src/cli.ts squads_propose.b64 \
  --rpc https://api.mainnet-beta.solana.com \
  --vault-pda 5udTJFsR7jnBTcTV6sRYbmLcDrBC2RK8eVp8rvBYMg5F
```

### `verdict.json` shape

The `--json` flag emits a machine-readable verdict that agents gate on:

```jsonc
{
  "schema": "sign-safe/verdict@1",
  "decision": "SIGN" | "HOLD" | "REJECT",   // gate on this
  "reason": "string",                         // qualified, factual; never reassuring
  "messageVersion": "legacy" | 0,
  "worstSeverity": "INFO" | "HOLD" | "REJECT",
  "findings": [
    {
      "id": "spl-set-authority",
      "label": "SPL Token SetAuthority",
      "severity": "REJECT",
      "instructionIndex": 0,
      "programId": "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
      "detail": "SetAuthority on spl-token: authority_type=0 (MintTokens), new_authority=<base58>.",
      "mapsToLoss": "Hands mint/freeze/owner authority to an attacker, who can then mint, freeze, or seize at will."
    }
  ],
  "outflow": {
    "lamports": "0",          // base-10 decimal string (exact past 2^53)
    "splTransfers": [],
    "exceedsLamportThreshold": false
  },
  "flags": {
    "unknownProgramPresent": false,
    "altLookupsPresent": false,
    "rolesUnverified": false,
    "decodeFailed": false
  },
  "unknownPrograms": []
}
```

See [skill/references/verdict-contract.md](skill/references/verdict-contract.md)
for the full decision-rule specification and the banned-reassurance-phrase contract.

## CLI flags

| Flag | Default | Description |
|------|---------|-------------|
| `--rpc <url>` | (offline) | Enable on-chain enrichment: ALT resolution, Squads PDA auto-fetch, Token-2022 mint-extension screening. |
| `--vault-pda <pubkey>` | (auto-extracted) | Override the Squads VaultTransaction PDA address (requires `--rpc`). |
| `--strict` | off | Restore aggressive posture: unknown writable → REJECT, broad durable-nonce composite. |
| `--threshold <lamports>` | 1 SOL | Override the large-transfer HOLD threshold. |
| `--json` | off | Emit `verdict.json` only (no human prose). Exit code still mirrors verdict. |
| `--digest` | off | Print the SHA-256 short code (`XXXX-XXXX-XXXX-XXXX-XXXX`) for cross-device byte-identity confirmation. |

Exit codes: **0 = SIGN**, **10 = HOLD**, **20 = REJECT**.

## Real CLI output: a REJECT (fixture 02) vs a SIGN (fixture 01)

The contrast below is the whole point of the skill. Same command, two opaque
base64 blobs, two opposite verdicts — decided offline, before any signature.

**A dangerous transaction is caught (fixture 02 — an SPL `SetAuthority`):**

```console
$ node --import tsx skill/src/cli.ts skill/fixtures/02_setauthority_reject.b64

================================================================
[ REJECT ]  Contains a REJECT-class danger primitive: SPL Token SetAuthority.
================================================================
message version : legacy
worst severity  : REJECT
static outflow  : 0 lamports
flags           : unknownProgram=false alt=false unverifiedRoles=false decodeFailed=false

findings (1):
  - [REJECT] ix#0 SPL Token SetAuthority
      SetAuthority on spl-token: authority_type=0 (MintTokens), new_authority=<base58>.
      maps to loss: Hands mint/freeze/owner authority to an attacker, who can then mint, freeze, or seize at will.

verdict.json:
{
  "schema": "sign-safe/verdict@1",
  "decision": "REJECT",
  "reason": "Contains a REJECT-class danger primitive: SPL Token SetAuthority.",
  "messageVersion": "legacy",
  "worstSeverity": "REJECT",
  "findings": [
    {
      "id": "spl-set-authority",
      "label": "SPL Token SetAuthority",
      "severity": "REJECT",
      "instructionIndex": 0,
      "programId": "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
      "detail": "SetAuthority on spl-token: authority_type=0 (MintTokens), new_authority=<base58>.",
      "mapsToLoss": "Hands mint/freeze/owner authority to an attacker, who can then mint, freeze, or seize at will."
    }
  ],
  "outflow": { "lamports": "0", "splTransfers": [], "exceedsLamportThreshold": false },
  "flags": { "unknownProgramPresent": false, "altLookupsPresent": false, "rolesUnverified": false, "decodeFailed": false },
  "unknownPrograms": []
}
$ echo $?
20
```

**A benign transaction passes (fixture 01 — a 0.01 SOL System transfer):**

```console
$ node --import tsx skill/src/cli.ts skill/fixtures/01_safe_sol_transfer.b64

================================================================
[ SIGN ]  Recognized instructions within thresholds; no danger primitives, unknown programs, or unverified ALT references. Not a guarantee of intent -- verify the recipients and amounts yourself.
================================================================
message version : legacy
worst severity  : INFO
static outflow  : 10000000 lamports
flags           : unknownProgram=false alt=false unverifiedRoles=false decodeFailed=false

findings (0):
  (none)

verdict.json:
{
  "schema": "sign-safe/verdict@1",
  "decision": "SIGN",
  "reason": "Recognized instructions within thresholds; no danger primitives, unknown programs, or unverified ALT references. Not a guarantee of intent -- verify the recipients and amounts yourself.",
  "messageVersion": "legacy",
  "worstSeverity": "INFO",
  "findings": [],
  "outflow": { "lamports": "10000000", "splTransfers": [], "exceedsLamportThreshold": false },
  "flags": { "unknownProgramPresent": false, "altLookupsPresent": false, "rolesUnverified": false, "decodeFailed": false },
  "unknownPrograms": []
}
$ echo $?
0
```

Even a SIGN verdict refuses to call the transaction "safe": it states what was
checked and hands intent verification back to the human. CLI exit codes mirror
the verdict so scripts and agents can gate on them: **`0 = SIGN`, `10 = HOLD`,
`20 = REJECT`**.

## Precision

A precision study against a frozen, offline corpus of **100 real benign mainnet
transactions** (from slots 428289500 and 428290000) + **37 synthetic malicious
patterns** across 7 attack families. Full methodology and per-fixture detail: see
[docs/precision-report.md](docs/precision-report.md).

**Default mode (two-tier posture):**

| Metric | Value |
|--------|-------|
| Benign corpus size | 100 transactions |
| Benign false-REJECT | **0** |
| Benign SIGN rate | 33% |
| Benign HOLD rate | 67% |
| Malicious recall | **100%** (37 / 37) |

All 37 malicious patterns are caught (HOLD or REJECT). No missed detections.
Zero benign transactions are false-REJECTed.

## Demo fixtures

The 10 synthetic fixtures under `skill/fixtures/` cover the main verdict paths.
Each is a serialized base64 message generated from `@solana/web3.js` and
cross-validated against both web3.js (v1) and `@solana/kit` (v2).

| Fixture | Description | Expected verdict |
|---------|-------------|-----------------|
| `01_safe_sol_transfer.b64` | 0.01 SOL System Transfer (within threshold) | SIGN |
| `02_setauthority_reject.b64` | SPL Token SetAuthority (mint authority handoff) | REJECT |
| `03_bpf_upgrade_reject.b64` | BPF Loader Upgrade (bytecode replacement) | REJECT |
| `04_durable_nonce_drift.b64` | Durable nonce advance at ix0 (Drift replay vector) | HOLD |
| `05_approve_delegate_hold.b64` | SPL Token Approve (delegate spend grant) | HOLD |
| `06_close_account_hold.b64` | SPL Token CloseAccount (sweeps lamports) | HOLD |
| `07_large_transfer_hold.b64` | SOL System Transfer > 1 SOL threshold | HOLD |
| `08_unknown_program_reject.b64` | Unknown program writing a value-bearing account | HOLD (default) / REJECT (`--strict`) |
| `09_v0_alt_unverified.b64` | v0 message with Address Lookup Table references (offline) | HOLD |
| `10_token2022_permdelegate_hold.b64` | Token-2022 transfer with PermanentDelegate mint extension | HOLD |

Each fixture has a committed `*.verdict.json` golden. Regenerate all goldens with
`npm run gen-goldens` (review each decision before committing — the goldens are a
security contract).

## The danger catalog (35 primitives)

| id | program | detection | severity | maps to loss |
|----|---------|-----------|----------|--------------|
| `spl-set-authority` | SPL Token | SetAuthority (6) | REJECT | mint/freeze/owner authority handoff |
| `token2022-set-authority` | Token-2022 | SetAuthority (6) | REJECT | + extension authorities |
| `token2022-permanent-delegate` | Token-2022 | PermanentDelegate (35) | HOLD | irrevocable seizure of any holder's tokens |
| `bpf-upgrade` | BPF Loader Upgradeable | Upgrade (3) | REJECT | bytecode replacement -> instant rug |
| `bpf-set-upgrade-authority` | BPF Loader Upgradeable | SetAuthority (4) | REJECT | upgrade-authority handoff -> later rug |
| `bpf-set-upgrade-authority-checked` | BPF Loader Upgradeable | SetAuthorityChecked (7) | REJECT | upgrade-authority handoff (checked) |
| `bpf-close` | BPF Loader Upgradeable | Close (5) | REJECT | destroys/drains buffer/programdata account |
| `system-assign` | System | Assign (1) | REJECT | reassigns account owner to arbitrary program |
| `system-assign-with-seed` | System | AssignWithSeed (10) | REJECT | seed-account ownership change |
| `system-transfer-with-seed` | System | TransferWithSeed (11) | HOLD | SOL outflow from a seed-derived account |
| `durable-nonce-advance` | System | AdvanceNonceAccount (4) **at ix0 only** | HOLD | replay/hold vector (Drift 2026); + authority change ⇒ REJECT |
| `durable-nonce-initialize` | System | Initialize/Authorize Nonce (6/7) | HOLD | sets/redirects nonce authority |
| `spl-approve-delegate` | SPL Token | Approve/ApproveChecked (4/13) | HOLD | delegate spend -> silent drain |
| `spl-close-account` | SPL Token | CloseAccount (9) | HOLD | sweeps lamports to a destination |
| `token2022-approve-delegate` | Token-2022 | Approve/ApproveChecked (4/13) | HOLD | delegate spend -> silent drain |
| `token2022-close-account` | Token-2022 | CloseAccount (9) | HOLD | sweeps lamports to a destination |
| `spl-freeze-account` | SPL Token | FreezeAccount (10) | HOLD | freezes a holder -> honeypot / denial |
| `token2022-freeze-account` | Token-2022 | FreezeAccount (10) | HOLD | freezes a holder -> honeypot / denial |
| `spl-mint-to` | SPL Token | MintTo/MintToChecked (7/14) | HOLD | supply inflation -> dilute / dump |
| `token2022-mint-to` | Token-2022 | MintTo/MintToChecked (7/14) | HOLD | supply inflation -> dilute / dump |
| `spl-burn` | SPL Token | Burn/BurnChecked (8/15) | HOLD | irreversible loss of the signer's tokens |
| `token2022-burn` | Token-2022 | Burn/BurnChecked (8/15) | HOLD | irreversible loss of the signer's tokens |
| `spl-withdraw-excess-lamports` | SPL Token | WithdrawExcessLamports (38) | HOLD | sweeps excess SOL from a token account |
| `token2022-withdraw-excess-lamports` | Token-2022 | WithdrawExcessLamports (38) | HOLD | sweeps excess SOL from a token account |
| `spl-unwrap-lamports` | SPL Token | UnwrapLamports (45) | HOLD | SOL outflow from a wrapped-SOL account |
| `token2022-unwrap-lamports` | Token-2022 | UnwrapLamports (45) | HOLD | SOL outflow from a wrapped-SOL account |
| `spl-batch` | SPL Token | Batch (255) | HOLD | batched sub-instructions not individually decoded |
| `token2022-batch` | Token-2022 | Batch (255) | HOLD | batched sub-instructions not individually decoded |
| `token2022-confidential-mint` | Token-2022 | ConfidentialMintBurn::Mint (42,3) | HOLD | confidential supply inflation |
| `token2022-confidential-burn` | Token-2022 | ConfidentialMintBurn::Burn (42,4) | HOLD | irreversible confidential burn |
| `token2022-withdraw-withheld-fees` | Token-2022 | TransferFee::WithdrawWithheld (26,2/3) | HOLD | withheld-fee token outflow |
| `token2022-confidential-withdraw-withheld-fees` | Token-2022 | ConfTransferFee::WithdrawWithheld (37,1/2) | HOLD | withheld-fee token outflow (confidential) |
| `token2022-permissioned-burn` | Token-2022 | PermissionedBurn::Burn (46,1/2/3) | HOLD | irreversible permissioned token burn |
| `system-withdraw-nonce` | System | WithdrawNonceAccount (5) | HOLD | SOL drain from a nonce account |
| `system-large-transfer` | System | Transfer (2) over threshold | HOLD | direct SOL outflow above threshold |

See [skill/references/danger-catalog.md](skill/references/danger-catalog.md) for
full rationale and [skill/catalog/danger-primitives.json](skill/catalog/danger-primitives.json)
for the machine-readable source.

## Scope

**In scope (what sign-safe decides):**

- Decoding legacy and v0 serialized messages from opaque base64, with our own
  dependency-free wire parser.
- Deriving signer / writable / readonly roles and flagging every
  Address-Lookup-Table reference as `unverified` (resolved with `--rpc`).
- Classifying instructions against a 35-entry danger-primitive catalog
  (authority handoffs, program upgrades, durable nonces, delegate grants,
  account closes, large transfers) plus a pure Token-2022 TLV extension walker.
- **DeFi/NFT program registry** (14 programs, `catalog/program-registry.json`):
  Metaplex Token Metadata, Metaplex Bubblegum (cNFT), Jupiter Aggregator v6,
  Orca Whirlpools, Raydium AMM v4, Pump.fun, Pump AMM/PumpSwap, Raydium CLMM,
  Raydium CPMM, Drift, Kamino klend, Meteora DLMM, Marginfi v2, Squads v4. Safe instructions SIGN;
  dangerous instructions are labeled at the correct severity; unrecognized
  instructions on recognized programs are HOLD (never SIGN).
- **Transfer recipient surfacing**: every SOL and SPL transfer surfaces the
  destination address in the outflow and the SIGN reason string. An
  `outboundToNonSigner` flag identifies when value is leaving to an external
  address.
- **Injectable blocklist**: `ctx.recipientBlocklist` accepts a set of known-bad
  addresses; any transfer recipient, SPL Approve delegate, or SetAuthority
  new-authority that matches is REJECT.
- **Outbound-transfer policy** (`ctx.holdOutboundTransfers`): escalate all
  external-recipient transfers to at least HOLD for strict signing policies.
- Offline clear-signing of Squads v4 VaultTransaction proposals: when the PDA
  bytes are provided (or auto-fetched with `--rpc`), decoding inner instructions
  and classifying them against an 11-entry Anchor authority-mutation registry.
- Durable-nonce escalation: a bare durable nonce is HOLD; combined with a
  REJECT-class finding it escalates to REJECT (the Drift-class composite).
  `governanceContext` makes even a bare durable nonce REJECT. `--strict` broadens
  the composite to trigger on any non-INFO finding.
- Out-of-band digest: SHA-256 + 20-hex-char short code for cross-device byte
  identity confirmation (`src/digest.ts`, exposed by the CLI `--digest` flag).
- Computing the statically-declared signer outflow (lamports + SPL transfers).
- Emitting a `SIGN / HOLD / REJECT` verdict and a machine-readable
  `verdict.json` with a verdict-mirroring exit code.

**Out of scope (and what to use instead):**

| Not this | Use instead |
|----------|-------------|
| A program source-code audit | `/audit-solana` |
| A debugger for a landed/failed transaction | `/debug-user-tx` |
| A replacement for core Solana dev knowledge | `solana-dev-skill` |
| Simulating runtime balance changes against live cluster state | a simulation/`simulateTransaction` tool |
| Catching post-sign state changes or TOCTOU races | simulation (Blowfish / Phantom-style) + Lighthouse |
| Signing, broadcasting, or touching a private key | your wallet — sign-safe never asks for a key |
| A guarantee that a SIGN'd transaction matches your *intent* | your own check of recipients and amounts |

sign-safe is a **static, offline (or optionally enriched), fail-closed
pre-signing gate**, not a runtime simulator and not a signer. It tells you what
a blob *is*; you still confirm it is what you *meant*.

### What sign-safe catches and what it does not (honest coverage)

**Catches (HOLD or REJECT by static analysis):**

| Category | How it is caught |
|---|---|
| Owner/authority reassignment | `system-assign`, `spl-set-authority`, `bpf-set-upgrade-authority`, etc. — all REJECT |
| Durable-nonce non-expiry | `durable-nonce-advance` at ix0 — always at least HOLD, escalates to REJECT when combined with a REJECT-class danger |
| Delegate / approval grants | `spl-approve-delegate`, `token2022-approve-delegate` — HOLD |
| Account closes and freezes | `spl-close-account`, `spl-freeze-account` (and Token-2022 equivalents) — HOLD |
| Honeypot / program-upgrade | `bpf-upgrade`, `bpf-close` — REJECT |
| Squads inner authority transfer | Inner `update_admin` / `set_admin` / etc. decoded from VaultTransaction PDA — REJECT |
| NFT / cNFT transfer (theft vector) | Metaplex Transfer (disc 49), Bubblegum Transfer (disc `a334c8e7…`) — REJECT |
| NFT delegate grant | Metaplex Delegate (disc 44), Bubblegum Delegate (disc `5a934bb2…`) — HOLD |
| NFT burn | Metaplex Burn (disc 41/29), Bubblegum Burn — REJECT |
| Unknown DeFi program (default: writing value) | Unknown program present → HOLD; `--strict`: writing value → REJECT |
| Known DeFi program, unrecognized instruction | Recognized (Jupiter/Orca/Raydium/etc.) but unlisted instruction — HOLD |
| Transfer recipient on drainer blocklist | `recipientBlocklist` injection — REJECT per hit |
| Outbound transfer policy | `holdOutboundTransfers` flag — HOLD for any external-recipient transfer |

**Not caught by static analysis alone (use the indicated mitigation):**

| Not caught | Why | Mitigation |
|---|---|---|
| A plain SOL transfer to an attacker | SIGN by default — recipient is surfaced in the verdict, but sign-safe cannot know if the address is malicious without external information | Provide `recipientBlocklist` via `enrich.ts reconRecipients()` (community blocklist); verify the destination address yourself |
| Address-poisoning / lookalike mints | Requires recognizing visual similarity of base58 strings — beyond static decoding | Visual UI hygiene; blocklist of known poison addresses |
| Economic/oracle outcomes | Token price at signing is not in the bytes | Pair with transaction simulation (Blowfish / Phantom-style) |
| Post-sign state changes / TOCTOU | If on-chain state changes between gate time and landing, the gate cannot know | Lighthouse or simulation with state pinning |
| Endpoint compromise (malicious injector) | If the bytes are tampered before reaching sign-safe, the gate cannot know | Hardware wallet or separate device; out-of-band digest (`--digest`) confirms byte identity across devices |
| A new dangerous instruction on a known program not yet in the catalog | Only catalogued primitives are flagged by name | Add a data row to `catalog/danger-primitives.json` or `catalog/program-registry.json` (one-line change, no code edit) |

**One-line coverage summary:** sign-safe catches owner-reassignment, durable nonces, approvals, closes, honeypots, hidden Squads inner instructions, and named NFT/DeFi dangers; a plain transfer to an attacker is SIGN by default (surfaced recipient + optional blocklist/policy mitigate it); address-poisoning, lookalike mints, economic-oracle effects, post-sign TOCTOU, and endpoint malware are out of scope and need reputation data, simulation, or endpoint security.

## Why this skill is different: it actually runs, and it is tested

Most skills are prose. This one ships a small, **pure-function** TypeScript core
with a deterministic, fully **offline** test suite (`vitest` + `fast-check`),
**725 tests across 35 files** (`npm test`):

- **10 synthetic golden fixtures** -- serialized messages built with
  `@solana/web3.js`, decoded by *our own* parser, verdicts deep-equal-checked
  against committed `verdict.json` goldens (regenerable, reviewed, with
  `npm run gen-goldens`).
- **5 REAL mainnet fixtures** (`skill/fixtures/real/`) -- captured once from
  `api.mainnet-beta.solana.com`, frozen as base64 of the signed message bytes
  with full provenance (signature, slot, cluster, capture date -- see each
  `*.meta.json`) and decoded **offline** at run time. No test makes a network call.
- **Differential cross-validation** on EVERY fixture against **two** independent
  references -- `@solana/web3.js` (v1) and `@solana/kit` (v2) -- on version, header,
  static keys, blockhash, per-instruction program ids / account indexes / data,
  and ALT count; plus a disagreement ⇒ fail-closed (V10) guard.
- **Property-based** (fast-check, seed 42): round-trip identity
  (`encode(decode(b)) === b`), fail-closed on arbitrary `uint8Array`, no
  trailing-byte tolerance, and compact-u16 invariants over `[0, 65535]`.
- **Role-derivation goldens** (SDK `test_is_writable_index` / `test_is_maybe_writable`,
  program-id demotion flip, multi-lookup ordering, reserved-key vs Incinerator).
- **Determinism**, **fail-closed** adversarial inputs (truncation, trailing
  garbage, out-of-range index, unsupported version `0x81`, empty/single-byte),
  **prompt-injection** (decoded data never interpolated, V8), and a
  **no-network** assertion (core modules import no http/https/net/fetch).

## Install

The repo is **self-contained** — the core has no runtime dependency on any
sibling skill, and there is **no postinstall and no curl** anywhere in it. It
installs two ways: as a submodule inside a skills kit, or standalone.

### As a submodule inside `solana-ai-kit` (kit integration)

Add `sign-safe` to an existing kit (e.g. `solanabr/solana-ai-kit`) as a git
submodule, then commit the pointer:

```bash
# from the root of your fork of solanabr/solana-ai-kit
git submodule add https://github.com/lrafasouza/sign-safe-skill .claude/skills/ext/sign-safe
git commit -m "feat: add sign-safe signing-time safety gate as a submodule"

# anyone cloning the kit then pulls the skill in with:
git clone --recurse-submodules https://github.com/solanabr/solana-ai-kit
# or, in an existing checkout:
git submodule update --init --recursive
```

The kit picks up `.claude/skills/ext/sign-safe/skill/SKILL.md` (add a routing row
to the hub `.claude/skills/SKILL.md`), the `/sign-review` command, and the
signing-output rule. The skill references the core `solana-dev-skill` **by name**
only (never by a relative path or a nested submodule), so it composes with the
rest of the kit without creating a second, conflicting dependency graph.

### Standalone (clone and run the gate locally)

```bash
git clone https://github.com/lrafasouza/sign-safe-skill sign-safe
cd sign-safe
npm install
npm run gen-fixtures   # (re)generate the 10 synthetic .b64 fixtures from @solana/web3.js
npm test               # vitest: golden + differential (web3.js + kit) + PBT + real fixtures + fail-closed
```

The real mainnet fixtures under `skill/fixtures/real/` are committed (frozen
bytes + provenance) and read offline; `gen-fixtures` does NOT touch them and no
test makes a network call.

You can also drop the `skill/`, `commands/`, and `rules/` directories directly
under a Claude Code skills root (e.g. `~/.claude/skills/sign-safe/`) if you are
wiring it into Claude Code by hand rather than through a kit.

## How it is tested

```
$ npm test            # vitest run -- the full suite (exits nonzero on any fail)

 ✓ skill/test/decode.test.ts                     (25 tests)   compact-u16 vectors/rejection, D19, versions, fail-closed
 ✓ skill/test/roles.test.ts                      (13 tests)   is_writable_index + demotion goldens, multi-lookup, reserved
 ✓ skill/test/classify.test.ts                   (21 tests)   Transfer/TransferChecked, SetAuthority, TLV, loader, routing
 ✓ skill/test/catalog-coverage.test.ts           (29 tests)   dangerous shapes never SIGN (SPL+T22 + confidential + permissioned)
 ✓ skill/test/verdict.test.ts                    (12 tests)   durable nonce ix0 gate, Drift composite, prompt-injection, V2
 ✓ skill/test/squads.test.ts                     (28 tests)   VaultTransaction borsh decode, discriminator math, ALT-unresolved fail-closed
 ✓ skill/test/squad-verdict.test.ts              (13 tests)   Squads execute verdict integration, durable-nonce+execute REJECT, governanceContext
 ✓ skill/test/digest.test.ts                     (14 tests)   SHA-256 digest, short-code format, determinism, out-of-band byte identity
 ✓ skill/test/pbt.test.ts                        ( 7 tests)   round-trip, fail-closed, no-trailing, compact-u16 (fast-check)
 ✓ skill/test/fixtures.test.ts                   (52 tests)   golden + web3.js + kit differential + disagreement + no-network
 ✓ skill/test/real-fixtures.test.ts              (14 tests)   REAL mainnet txs decoded offline + cross-validated
 ✓ skill/test/fulltx.test.ts                     ( 9 tests)   full signed-tx input stripped + fail-closed (W011 §7)
 ✓ skill/test/program-registry.test.ts           (56 tests)   DeFi/NFT registry: 14 programs; dangerous instructions named; unrecognized HOLD
 ✓ skill/test/recipient.test.ts                  ( 8 tests)   System + SPL Transfer recipient surfacing; outboundToNonSigner; ALT-unresolved marker
 ✓ skill/test/reputation.test.ts                 (16 tests)   blocklist REJECT; holdOutboundTransfers HOLD; screenAddresses unit; reconRecipients stub
 ✓ skill/test/legacy-runner.test.ts              ( 1 test )   runs the standalone node smoke runner
 ✓ skill/test/alt.test.ts                        (...)        ALT bincode decoder, resolvedAltTables channel, fail-closed on bad layout
 ✓ skill/test/rpc.test.ts                        ( 7 tests)   RPC fetcher; injectable stub; offline-identical without --rpc
 ✓ skill/test/cli-args.test.ts                   (13 tests)   CLI flag parsing: --rpc, --vault-pda, --strict, --threshold, --json, --digest
 ✓ skill/test/registry-discriminators.test.ts    (127 tests)  self-verifying: sha256("global:"+ixName)[..8] matches every registry entry
 ✓ skill/test/precision.test.ts                  (10 tests)   offline precision harness: 100 benign + 37 malicious, confusion matrix
 ✓ skill/test/extract-vault-address.test.ts      ( 4 tests)   auto-extract Squads vault PDA from account index 2
 ... (additional files)

 Test Files  29 passed (29)
      Tests  725 passed (725)
```

There are two entry points: `npm test` (vitest, the full suite) and
`npm run test:fixtures` (the dependency-light standalone node runner, usable in a
minimal checkout and used as the CI determinism oracle). `npm run gen-goldens`
regenerates the committed golden `verdict.json` from the current core (only after
reviewing each decision — the goldens are a security contract).

Run in CI on every push/PR via `.github/workflows/ci.yml` (`npm ci` +
type-check + `npm test`), across Node 20 and 22, with a determinism gate (two
runs of the node runner must be byte-identical) and a fixture-drift guard
(`npm run gen-fixtures` must not change any committed `.b64`).

The real fixtures are captured ONCE and committed; the suite reads the frozen
bytes and makes **no network calls at run time**. Re-capturing is a manual,
out-of-band step (see `skill/fixtures/real/*.meta.json` for provenance).

Solana libraries are used **only** for fixture generation and cross-validation,
never by the core. The cross-check now covers **all 10 fixtures** against **two
independent, current implementations** — `@solana/web3.js` (v1) and
`@solana/kit` (v2, the modern stack) — using kit's
`getCompiledTransactionMessageDecoder` on the same serialized bytes. The core
decoder is our own dependency-free wire parser, so agreeing with both proves it
is correct, not merely self-consistent or pinned to a single legacy library.

The banned-reassurance-phrase contract is **executable**, not just prose:
`src/banned.ts` is run over every verdict's narrative fields inside
`buildVerdict`/`rejectVerdict`, so any reason or finding string that reintroduces
"safe" / "no risk" / etc. fails loud (and the gate fails closed to REJECT).

## Validation

A reviewer can reproduce the entire result from a clean clone with three
commands and no network access at test time:

```bash
npm install            # deps for generation + cross-validation only (no postinstall, no curl)
npm run gen-fixtures   # rebuild the 10 synthetic .b64 from @solana/web3.js (deterministic, byte-identical)
npm test               # 725 checks, 35 files, fully offline; exits nonzero on any failure
```

Expected: `Tests  725 passed (725)`, and `git status` clean afterward (the
deterministic generator reproduces the committed `.b64` byte-for-byte). To also
confirm the type contract: `npx tsc --noEmit` (exit 0).

What those 725 checks actually validate:

| Coverage area | Where | What it proves |
|---|---|---|
| **Golden verdicts** | `fixtures.test.ts` | All 10 synthetic fixtures' verdicts deep-equal committed `verdict.json` goldens (the SIGN/HOLD/REJECT contract is frozen). |
| **Dual-reference cross-validation** | `fixtures.test.ts`, `real-fixtures.test.ts` | Our dependency-free decoder agrees with **both** `@solana/web3.js` (v1) and `@solana/kit` (v2) on version, header, static keys, blockhash, per-ix program id/accounts/data, and ALT count — on every fixture. |
| **Property-based** | `pbt.test.ts` | fast-check (seed 42): `encode(decode(b)) === b` round-trip, fail-closed on arbitrary `Uint8Array`, no trailing-byte tolerance, compact-u16 invariants over `[0, 65535]`. |
| **Real mainnet fixtures** | `real-fixtures.test.ts` | 5 frozen mainnet txs decoded **offline** and cross-validated; each carries a `*.meta.json` with signature, slot, cluster, and capture date for provenance. |
| **SDK role / demotion goldens** | `roles.test.ts` | Two-layer writability against SDK semantics: `is_writable_index` partition, runtime program-id demotion flip (SIMD-0105), multi-lookup ordering, reserved-key set vs Incinerator, ALT accounts marked `addressVerified: false`. |
| **Full-tx input + untrusted data (W011)** | `fulltx.test.ts` | A full signed transaction (signatures + message) is detected, signatures stripped (never verified), and the inner message reaches the same verdict as the bare message; garbage fails closed. |
| **Catalog coverage (never false-SIGN)** | `catalog-coverage.test.ts` | Dangerous shapes most easily missed — Token-2022 `Approve`/`CloseAccount`/`Freeze`/`MintTo`, `Burn`, System `WithdrawNonceAccount`, large `CreateAccount` — must **never** return SIGN. |
| **Squads VaultTransaction decode** | `squads.test.ts` | Discriminator math, borsh decode of frozen real mainnet PDA fixture, ALT-space program-id resolution (fail-closed null when index >= accountKeys.len), structural fail-closed. |
| **Squads + verdict integration** | `squad-verdict.test.ts` | Execute without inner bytes -> HOLD; with inner `update_admin` -> REJECT; durable-nonce + execute -> REJECT (Drift composite); `governanceContext` -> REJECT. |
| **Transaction digest** | `digest.test.ts` | SHA-256 correctness, short-code format and determinism, out-of-band identity confirmation, no-network purity. |
| **Fail-closed / adversarial** | `decode.test.ts`, `verdict.test.ts` | Truncation, trailing garbage, out-of-range index, unsupported version `0x81`, empty/single-byte → REJECT; unresolved ALT never SIGN; prompt-injection (V8); banned reassurance phrases fail loud. |
| **DeFi/NFT program registry** | `program-registry.test.ts` | 14 programs with verified per-instruction discriminators; safe instructions SIGN; dangerous instructions labeled; unrecognized-instruction HOLD (fail-closed); truly-unknown-program REJECT unchanged (strict) / HOLD (default). |
| **Self-verifying discriminators** | `registry-discriminators.test.ts` | 127 checks: `sha256("global:"+ixName)[..8]` recomputed live and compared against every entry in `program-registry.json`. |
| **Recipient surfacing** | `recipient.test.ts` | System Transfer surfaces recipient base58 address, `outboundToNonSigner` true when non-signer, SIGN reason names destination; SPL Transfer, TransferChecked, ALT-sourced recipient marked unresolved. |
| **Blocklist + policy** | `reputation.test.ts` | Blocklist REJECT on SOL transfer to known-bad address; SPL Approve delegate blocklist; `holdOutboundTransfers` escalation; `reconRecipients` injectable. |
| **ALT decoding + resolution** | `alt.test.ts` | Bincode layout decoder, `resolvedAltTables` channel pass-through, fail-closed on malformed account bytes, partial-table index out-of-range. |
| **RPC fetcher** | `rpc.test.ts` | JSON-RPC `getAccountInfo` injector; frozen stub; offline-identical behavior when no `--rpc`. |
| **CLI args** | `cli-args.test.ts` | Flag parsing correctness: `--rpc`, `--vault-pda`, `--strict`, `--threshold`, `--json`, `--digest`. |
| **Precision harness** | `precision.test.ts` | 100 benign + 37 malicious offline corpus; 0 false-REJECTs on benign; 100% malicious recall; ALT sub-test. |
| **Determinism** | `run.ts` + CI | The standalone node runner's output is byte-identical across two runs (no timing/nondeterminism in the core). |
| **No-network** | `fixtures.test.ts` | Core modules import no `http`/`https`/`net`/`fetch`; the suite makes zero network calls at run time. |

> **On `npm audit`:** any advisories come exclusively from **dev** dependencies
> (the `vitest`/`vite`/`esbuild` toolchain and `@solana/web3.js`'s transitive
> deps used only for fixture generation + cross-validation). The shipped runtime
> core has **zero** dependencies (`"dependencies": {}`), so none of these reach a
> consumer of the skill.

CI (`.github/workflows/ci.yml`) runs exactly this on every push and PR across
Node 20 and 22, plus a determinism gate (two byte-identical runner runs) and a
fixture-drift guard (`gen-fixtures` must not change any committed `.b64`). The
real fixtures are committed, so CI never depends on the network — it just decodes
the frozen bytes.

## Repository structure

```
sign-safe-skill/
├── package.json            # build / test / gen-fixtures (no postinstall, no curl)
├── tsconfig.json           # strict, NodeNext, ES2022
├── LICENSE                 # MIT
├── README.md               # this file
├── CLAUDE.md               # how an agent should use this skill
├── commands/
│   └── sign-review.md      # the /sign-review command (frontmatter description)
├── rules/
│   └── signing-output.md   # verdict contract + banned reassurance phrases
└── skill/
    ├── SKILL.md            # thin router hub (frontmatter: name, description)
    ├── references/
    │   ├── verdict-contract.md        # verdict.json schema + decision rules
    │   ├── danger-catalog.md          # rationale for each catalog entry
    │   └── decode-notes.md            # message parse details, ALT conservatism
    ├── catalog/
    │   ├── danger-primitives.json     # 35-entry native-program danger catalog
    │   ├── anchor-danger.json         # 11-entry Anchor authority-mutation registry
    │   └── program-registry.json      # 14-program DeFi/NFT registry
    ├── src/
    │   ├── types.ts        # the shared contract (two-layer role model + RecipientRef)
    │   ├── decode.ts       # PURE base64 -> DecodedMessage (legacy + v0) + re-encoder
    │   ├── roles.ts        # PURE two-layer writability (partition + demotion) + reserved set
    │   ├── classify.ts     # PURE instruction x catalog + registry -> Finding[]
    │   ├── classify-inner.ts # PURE inner-instruction classifier (Squads VaultTransaction)
    │   ├── registry.ts     # PURE DeFi/NFT program registry lookup (program-registry.json)
    │   ├── reputation.ts   # PURE address-reputation blocklist screening (screenAddresses)
    │   ├── outflow.ts      # PURE statically-declared signer outflow + recipient surfacing
    │   ├── tlv.ts          # PURE Token-2022 mint/account TLV extension walker
    │   ├── alt.ts          # PURE ALT account bincode decoder (resolvedAltTables channel)
    │   ├── banned.ts       # PURE banned-reassurance-phrase enforcement
    │   ├── squads.ts       # PURE Squads v4 VaultTransaction borsh decoder
    │   ├── digest.ts       # PURE SHA-256 transaction digest + short-code
    │   ├── verdict.ts      # PURE Finding[] -> Verdict + verdict.json (Drift composite)
    │   ├── rpc.ts          # IMPURE JSON-RPC getAccountInfo fetcher (host layer)
    │   ├── enrich.ts       # IMPURE runtime hooks (NEVER imported by core/tests)
    │   └── cli.ts          # thin CLI wrapper (--rpc, --vault-pda, --strict, --json, --digest)
    ├── fixtures/
    │   ├── generate.ts     # builds the synthetic .b64 fixtures with @solana/web3.js
    │   ├── gen-goldens.ts  # regenerates the golden verdict.json from the core
    │   ├── NN_*.b64        # 10 synthetic serialized messages
    │   ├── NN_*.verdict.json   # 10 golden verdicts
    │   └── real/           # REAL mainnet fixtures (frozen .b64 + .meta.json provenance)
    │       └── accounts/   # frozen on-chain account bytes (Squads VaultTransaction PDA)
    ├── corpus/             # precision study: 100 benign + 37 malicious offline fixtures
    └── test/
        ├── helpers.ts               # offline message-byte builders + fixture loaders
        ├── decode.test.ts           # wire-format / compact-u16 / sanitization / fail-closed
        ├── roles.test.ts            # role-derivation goldens (partition + demotion)
        ├── classify.test.ts         # instruction classification + TLV
        ├── verdict.test.ts          # durable nonce / Drift composite / prompt-injection
        ├── squads.test.ts           # VaultTransaction decode, discriminator, ALT-unresolved, real fixture
        ├── squad-verdict.test.ts    # Squads+verdict integration, governanceContext, never-SIGN
        ├── digest.test.ts           # SHA-256 digest, short-code, determinism, out-of-band identity
        ├── pbt.test.ts              # fast-check property-based tests (seed 42)
        ├── fixtures.test.ts         # golden + web3.js/kit differential + no-network
        ├── real-fixtures.test.ts    # real mainnet txs decoded offline + cross-validated
        ├── program-registry.test.ts # DeFi/NFT registry: 14 programs, verified discriminators
        ├── recipient.test.ts        # recipient surfacing, outboundToNonSigner, ALT-unresolved
        ├── reputation.test.ts       # blocklist REJECT, holdOutboundTransfers HOLD, screenAddresses unit
        ├── legacy-runner.test.ts    # wraps run.ts so it is part of `npm test`
        ├── alt.test.ts              # ALT bincode decoder + resolvedAltTables channel
        ├── rpc.test.ts              # RPC fetcher + injectable stub + offline-identical
        ├── cli-args.test.ts         # CLI flag parsing correctness
        ├── registry-discriminators.test.ts  # self-verifying discriminators (127 checks)
        ├── precision.test.ts        # offline precision harness (100 benign + 37 malicious)
        ├── extract-vault-address.test.ts    # Squads PDA auto-extraction
        ├── fulltx.test.ts           # full signed-tx input stripped + fail-closed (W011)
        └── run.ts                   # standalone node smoke runner (npm run test:fixtures)
```

## License

MIT -- see [LICENSE](LICENSE).
