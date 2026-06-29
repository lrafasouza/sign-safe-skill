# Spike — A (real malicious corpus) retrieval feasibility

> Date: 2026-06-29. Purpose: determine how many real, in-class, publicly-documented attack txns' RAW signed bytes we can retrieve (sign-safe decodes raw base64). Gates workstream A.

## Candidate incident (anchor): Drift Protocol, ~$285M (Apr 1 2026)

Verified real and documented (Chainalysis, Cyfrin, QuillAudits, NewsBTC). In sign-safe's threat class: durable-nonce pre-signed + blind-signed governance → fake-collateral whitelist → drain.

On-chain identifiers (from the QuillAudits postmortem):
- Attacker wallets (SOL): `HkGz4KmoZ7Zmk7HN6ndJ31UJ1qZ2qgwQxgVqQwovpZES`, `H7PiGqqUaanBovwKgEtreJbKmQe6dbq6VTrw6guy7ZgL`
- Exploit tx signatures:
  - `2HvMSgDEfKhNryYZKhjowrBY55rUx5MWtcWkG9hqxZCFBaTiahPwfynP1dxBSRk9s5UTVc8LFeS4Btvkm9pc2C4H`
  - `4BKBmAJn6TdsENij7CsVbyMVLJU1tX27nfrMM1zgKv1bs2KJy6Am2NqdA3nJm4g9C6eC64UAf5sNs974ygB9RsN1`
- Drift Vault `JCNCMFXo5M5qwUPg2Utu1u6YWp3MbygxqBsBeXXJfrw` · Vault State `5zpq7DvB6UdFFvpmBPspGPNfUGoBRRCE2HHg5u3gxcsN` · V2 Program `dRiftyHA39MWEi3m9aunc5MzRF1JYuBsbn6VPcn33UH`

## Retrieval attempts

1. **Helius MCP** (the chosen path) — `heliusTransaction.parseTransactions(<sig>)` → **401 Unauthorized** ("API key is invalid or expired"). `heliusChain.getNetworkStatus` → same 401. The Helius MCP is globally unauthorized in this session. Also note: even when authorized, the MCP exposes *parsed* txns + chain state but **no raw `getTransaction(base64)`** action — sign-safe needs the raw signed bytes, so the MCP alone is insufficient for capture regardless of auth.
2. **Public RPC** (`api.mainnet-beta.solana.com`, used by `capture-benign.ts`) — non-archival; April-2026 txns are pruned → will return null for these signatures. Not usable for old attack txns.

## Conclusion (honest)

- **Real-bytes retrieval for A is BLOCKED with current resources.** We have the real signatures + full provenance, but no working archival endpoint that returns raw `getTransaction(base64)`.
- **Unblock options:**
  1. A valid **Helius API key** (or any **archival RPC URL** with `getTransaction` base64) → `capture-malicious.ts` fetches the raw bytes → genuine real corpus A. *(Recommended — A's entire value is the real bytes.)*
  2. Defer A to a later round (when a key is available); ship D/E/C/F/B now.
  3. Labeled-synthetic fallback ("modeled on Drift") — **low marginal value**: we already have synthetic Squads + durable-nonce fixtures, so a modeled-Drift fixture adds little over the existing 37-pack. Not recommended as a substitute for the real thing.
- **F is unaffected:** growing the benign corpus uses recent txns, which the public RPC retains — no key needed.

## Decision needed

Provide a valid Helius API key / archival RPC URL to make A real, or choose defer / labeled-synthetic. The rest of v0.6.0 (D, E, C, F, B, GIF) does not depend on this.
