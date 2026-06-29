# Bounty Rubric Checklist

| Area | Evidence | Status |
|---|---|---|
| Agent-wallet relevance | Pre-signing SIGN/HOLD/REJECT gate, `guardedSignTransaction`, MCP `review_transaction`, and JSON verdicts for automation. | Covered |
| Reproducibility | `npm run verify:all` runs build, tests, fixture runner, attack replay, pack dry-run, and production audit. | Covered |
| Attack proof | `npm run demo:attack-pack` replays 37 curated malicious fixtures and fails if any fixture receives SIGN. | Covered |
| Test depth | 800 tests across 42 files after the evaluator proof assets; frozen benign corpus and curated malicious corpus. | Covered |
| Precision honesty | `docs/precision-report.md` reports 18.4% SIGN, 81.6% HOLD, 0% false-REJECT on the frozen benign corpus. | Covered |
| Security boundary | `SECURITY.md` states pre-signing scope, no custody, no on-chain enforcement, and limitations. | Covered |
| Solana AI Kit fit | Skill docs, command docs, MCP server, programmatic API, and adapter exports. | Covered |
| Limitations | README, precision report, submission packet, and security policy avoid claiming that SIGN means safe. | Covered |

## Reviewer Commands

```bash
npm install
npm run verify:all
npm run demo:attack-pack
```

## Evidence Files

- `README.md`
- `docs/precision-report.md`
- `SECURITY.md`
- `SUBMISSION.md`
- `skill/schema/verdict.schema.json`
- `skill/corpus/malicious.ts`
- `scripts/demo-attack-pack.mjs`
- `scripts/verify-all.mjs`
