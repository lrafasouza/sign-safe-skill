# sign-safe Submission Packet

## Current Evidence

- Project: `sign-safe-skill`
- Repository: https://github.com/lrafasouza/sign-safe-skill
- Bounty PR: https://github.com/solanabr/skill-bounty/pull/4
- Solana AI Kit PR: https://github.com/solanabr/solana-ai-kit/pull/34
- Version: `0.5.0`
- Local validation target: 777 tests across 40 files
- Precision report: 36% SIGN / 64% HOLD / 0% false-REJECT on the frozen benign corpus
- Curated malicious corpus: 37/37 held or rejected before signing
- Runtime dependency posture: zero runtime dependencies in the deterministic core

## What It Does

sign-safe reviews Solana transaction bytes before a wallet or autonomous agent
signs them. It decodes legacy and v0 messages, derives signer/writable roles,
classifies danger primitives, computes signer-perspective outflow, and emits a
machine-readable SIGN, HOLD, or REJECT verdict.

## Why It Matters

Agent wallets fail when the signer cannot understand the transaction it is about
to authorize. Simulation alone can miss authority changes and durable-nonce
replay shapes. sign-safe adds a deterministic pre-signing layer that fails closed
on unknown or unverifiable transaction structure.

## Reproduce

```bash
npm install
npm run verify:all
```

For the evaluator-facing attack proof:

```bash
npm run demo:attack-pack
```

Expected attack-pack summary:

```txt
False SIGN: 0
RESULT: 37/37 attack fixtures held or rejected before signing
```

## Coverage Highlights

- 37 native danger primitives, including SPL Token, Token-2022, System Program,
  BPF Loader, durable nonce, Native Stake, bounded ATA, and Memo recognition.
- 14-program DeFi/NFT registry covering Jupiter, Orca, Raydium, Pump.fun,
  Drift, Kamino, Meteora, Marginfi, Squads, Metaplex, and Bubblegum.
- Squads v4 VaultTransaction inner-instruction clear-signing when PDA bytes are
  supplied or fetched through RPC enrichment.
- JSON Schema and MCP `outputSchema` for agent integration.
- `guardedSignTransaction` wrapper for signer gates.

## Honest Limitations

- SIGN does not mean "safe"; it means recognized and within configured thresholds.
- The malicious recall figure is for the committed curated corpus, not a claim
  that every malicious Solana transaction is caught.
- Optional RPC enrichment can improve context but the deterministic core remains
  offline and fail-closed.
- sign-safe does not enforce limits on-chain and should be paired with multisig,
  policy, or spending-limit systems when custody risk requires it.

## Suggested Judge Flow

1. Read the README top section for the product framing.
2. Run `npm run verify:all`.
3. Run `npm run demo:attack-pack`.
4. Inspect `docs/precision-report.md`.
5. Inspect `SECURITY.md` for the exact security boundary.
