# sign-safe Submission Packet

## Current Evidence

- Project: `sign-safe-skill`
- Repository: https://github.com/lrafasouza/sign-safe-skill
- Bounty PR: https://github.com/solanabr/skill-bounty/pull/4
- Solana AI Kit PR: https://github.com/solanabr/solana-ai-kit/pull/34
- Version: `0.6.0`
- Local validation target: 800 tests across 42 files
- Precision report: 18.4% SIGN / 81.6% HOLD / 0% false-REJECT on the frozen benign corpus
- Curated malicious corpus: 37/37 held or rejected before signing
- Real on-chain attacks: 2 publicly-documented Drift (Apr 2026) exploit transactions held (HOLD) — see docs/real-attacks.md
- Runtime dependency posture: zero runtime dependencies in the deterministic core
- Reproducible sample verdicts (verbatim CLI output): `docs/sample-verdicts/` (SIGN / HOLD / REJECT / Squads-HOLD)
- Adversarial RPC test: findings derived from the signed bytes cannot be removed or downgraded by RPC enrichment (`skill/test/rpc-adversarial.test.ts`)
- Fail-closed behavior documented in `docs/failure-recovery.md`

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

Per-transaction verdict (offline, no RPC):

```bash
npm run cli -- skill/fixtures/02_setauthority_reject.b64 --json   # REJECT (exit 20)
npm run cli -- skill/fixtures/01_safe_sol_transfer.b64 --json     # SIGN (exit 0)
```

Compare against the committed verbatim outputs in `docs/sample-verdicts/`. For the 3-minute path, see the **Evaluator Quickstart** at the top of the README.

## Coverage Highlights

- 37 native danger primitives, including SPL Token, Token-2022, System Program,
  BPF Loader, durable nonce, Native Stake, bounded ATA, and Memo recognition.
- 14-program DeFi/NFT registry covering Jupiter, Orca, Raydium, Pump.fun,
  Drift, Kamino, Meteora, Marginfi, Squads, Metaplex, and Bubblegum.
- Squads v4 VaultTransaction inner-instruction clear-signing when PDA bytes are
  supplied or fetched through RPC enrichment.
- JSON Schema and MCP `outputSchema` for agent integration.
- `guardedSignTransaction` wrapper for signer gates.
- Runnable MCP client example (`examples/mcp-client-call.ts`) calling the real `sign-safe-mcp` server: base64 in, verdict.json out.
- `--simulate` (with `--rpc`) ingests innerInstructions + balance diff, escalate-only; fail-closed (REJECT) when used without `--rpc`.

## Honest Limitations

- SIGN does not mean "safe"; it means recognized and within configured thresholds.
- The malicious recall figure is for the committed curated corpus, not a claim
  that every malicious Solana transaction is caught.
- Optional RPC enrichment can improve context but the deterministic core remains
  offline and fail-closed.
- sign-safe does not enforce limits on-chain and should be paired with multisig,
  policy, or spending-limit systems when custody risk requires it.

## Suggested Judge Flow

1. Read the **Evaluator Quickstart** at the top of the README (3-minute framing + commands).
2. Run `npm run verify:all` (800 tests / 42 files, fixtures, attack replay, pack, audit).
3. Run `npm run demo:attack-pack` (37/37 held or rejected, False SIGN: 0).
4. Run a per-transaction verdict via `npm run cli -- <fixture> --json` and compare to `docs/sample-verdicts/`.
5. Read `DEMO.md` Scenario 4 (Squads hidden-authority HOLD) and `docs/failure-recovery.md` (fail-closed behavior).
6. Inspect `docs/precision-report.md` and `SECURITY.md` for the exact metrics and security boundary.
