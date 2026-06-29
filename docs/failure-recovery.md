# sign-safe failure-mode mapping

Concrete table of failure modes, their verdict outcomes, and the finding id or flag that surfaces them. Grounded in `skill/src/classify.ts`, `skill/src/verdict.ts`, `skill/src/rpc.ts`, and `skill/src/simulate.ts`.

| Failure mode | Verdict | Finding id / flag | Source |
|---|---|---|---|
| Malformed or truncated input (base64 decode error, bad message header, or compact-u16 overflow) | **REJECT** | `flags.decodeFailed: true`; reason: `"Decode failed (fail-closed): ..."` | `verdict.ts` → `rejectVerdict()` |
| Unknown program (not in catalog or registry), default mode | **HOLD** | `flags.unknownProgramPresent: true`; `unknownPrograms[]` populated; no finding id (verdict layer escalates) | `verdict.ts` decision rule |
| Unknown program writing a value-bearing account, `--strict` mode | **REJECT** | `flags.unknownProgramPresent: true`; no finding id | `verdict.ts` `unknownWritableReject` path |
| Unresolved Address Lookup Table (offline, no `--rpc`) | **>=HOLD** | `flags.altLookupsPresent: true`, `flags.rolesUnverified: true`, `addressVerified: false` on ALT accounts | `roles.ts` + `verdict.ts` |
| Squads `VaultTransaction` execute without PDA bytes (offline or PDA fetch failed) | **HOLD** | `id: "squads-execute-unverified"` | `classify-inner.ts` / `verdict.ts` |
| RPC error or timeout during online enrichment (`--rpc`) | **REJECT** | `flags.decodeFailed: true`; reason: `"Online enrichment error: ..."` (AbortController timeout → thrown, caught by `cli.ts`) | `rpc.ts` + `cli.ts` catch block |
| `--simulate` given without `--rpc` | **REJECT** (before network) | `parseArgs()` throws; `cli.ts` catch → `rejectVerdict()`; `flags.decodeFailed: true` | `cli.ts` ~line 152–156 |
| Simulation RPC call fails or returns an error | **HOLD** (at minimum) | `simulation.ok: false`; verdict raised but not lowered below the offline result | `simulate.ts` fail-closed path + `verdict.ts` simulation fold |
| Squads VaultTransaction inner `update_admin` instruction decoded | **REJECT** | `id: "anchor-inner-update_admin"` | `catalog/anchor-danger.json` + `classify-inner.ts` |
| Durable-nonce advance at ix0 (bare, no companion danger) | **HOLD** | `id: "durable-nonce-advance"` | `classify.ts` + `verdict.ts` |
| Durable-nonce + REJECT-class finding (default) | **REJECT** | Composite: `durable-nonce-advance` + any `severity: "REJECT"` finding | `verdict.ts` `driftCompositeDefault` |
| Durable-nonce + any non-INFO finding (`--strict`) | **REJECT** | Composite: `durable-nonce-advance` + any non-INFO finding or unknown program | `verdict.ts` `driftCompositeStrict` |

All paths above are fail-closed: an error never silently produces SIGN.
