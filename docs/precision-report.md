# Sign-Safe Precision Report

Generated: 2026-06-25T03:27:57.222Z
Pinned slots: 428290000, 428289500

## 1. Signing Precision and Review Rate

Total benign fixtures: **100**
Benign SIGN precision: **100.0%** (33/33 SIGN decisions across this corpus were benign).
Benign HOLD rate: **67.0%** (67/100).

These are corpus measurements, not population-wide guarantees. A zero false-REJECT count is useful calibration evidence, but zero false positives is not the optimization target for a fail-closed signing gate; the HOLD rate shows the review cost directly.

| Decision | Count | Pct |
|----------|-------|-----|
| SIGN     |    33 | 33.0% |
| HOLD     |    67 | 67.0% |
| REJECT   |     0 | 0.0% |

### Category Breakdown (benign)

| Version | HasALT | Count |
|---------|--------|-------|
| 0 | no-ALT | 20 |
| 0 | with-ALT | 38 |
| legacy | no-ALT | 42 |

## 2. False-REJECTs (Benign REJECTs — Target: 0)

**None.** Zero false-REJECTs. All benign transactions were classified SIGN or HOLD.

## 3. Benign HOLD Analysis

Total benign HOLDs: **67**

| Category | Count | Explanation |
|----------|-------|-------------|
| Has unresolved ALT | 1 | ALT accounts could not be resolved (fail-closed HOLD) |
| Has resolved ALT   | 28 | ALT resolved but other HOLD finding present |
| No ALT (other)     | 38 | HOLD from non-ALT finding (large transfer, nonce, etc.) |

### Benign HOLDs (non-ALT causes) — review findings:

- **428289500-0.json** (slot=428289500): programIds=[T1pyyaTNZsKv2WcRAB8oVnk93mLJw2XzjtVYqCsaHqt] findings=[]
- **428289500-11.json** (slot=428289500): programIds=[2DNbzPochEcyCcWMbL4d9S3u9QqQEj5bbe6cSZFvKsbh, ComputeBudget111111111111111111111111111111] findings=[]
- **428289500-12.json** (slot=428289500): programIds=[9H6tua7jkLhdm3w8BvgpTn5LZNU7g4ZynDmCiNN3q6Rp, ComputeBudget111111111111111111111111111111] findings=[]
- **428289500-15.json** (slot=428289500): programIds=[TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb, MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr] findings=[]
- **428289500-19.json** (slot=428289500): programIds=[BiSoNHVpsVZW2F7rx2eQ59yQwKxzU5NvBcmKshCSUypi, ComputeBudget111111111111111111111111111111] findings=[]
- **428289500-20.json** (slot=428289500): programIds=[9H6tua7jkLhdm3w8BvgpTn5LZNU7g4ZynDmCiNN3q6Rp, ComputeBudget111111111111111111111111111111] findings=[]
- **428289500-22.json** (slot=428289500): programIds=[ComputeBudget111111111111111111111111111111, MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr, TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA] findings=[]
- **428289500-27.json** (slot=428289500): programIds=[BiSoNHVpsVZW2F7rx2eQ59yQwKxzU5NvBcmKshCSUypi, ComputeBudget111111111111111111111111111111] findings=[]
- **428289500-28.json** (slot=428289500): programIds=[11111111111111111111111111111111, dijkbkCAKfFTCxQg3u1pg82gVU1jJGHBBRcteD11mBu, ComputeBudget111111111111111111111111111111] findings=[durable-nonce-advance]
- **428289500-3.json** (slot=428289500): programIds=[EtrnLzgbS7nMMy5fbD42kXiUzGg8XQzJ972Xtk1cjWih, ComputeBudget111111111111111111111111111111, 11111111111111111111111111111111] findings=[]
- **428289500-30.json** (slot=428289500): programIds=[ComputeBudget111111111111111111111111111111, ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL, pAMMBay6oceH9fJKBRHGP5D4bD4sWpmSwMn52FMfXEA, TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA] findings=[spl-close-account]
- **428289500-36.json** (slot=428289500): programIds=[11111111111111111111111111111111, dijkbkCAKfFTCxQg3u1pg82gVU1jJGHBBRcteD11mBu, ComputeBudget111111111111111111111111111111] findings=[durable-nonce-advance]
- **428289500-39.json** (slot=428289500): programIds=[6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P, TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb, 11111111111111111111111111111111] findings=[token2022-close-account, registry-pump-fun-unknown-instruction]
- **428289500-4.json** (slot=428289500): programIds=[9H6tua7jkLhdm3w8BvgpTn5LZNU7g4ZynDmCiNN3q6Rp, ComputeBudget111111111111111111111111111111] findings=[]
- **428289500-43.json** (slot=428289500): programIds=[ComputeBudget111111111111111111111111111111, 11111111111111111111111111111111] findings=[system-large-transfer]
- **428289500-44.json** (slot=428289500): programIds=[9H6tua7jkLhdm3w8BvgpTn5LZNU7g4ZynDmCiNN3q6Rp, ComputeBudget111111111111111111111111111111] findings=[]
- **428289500-46.json** (slot=428289500): programIds=[ComputeBudget111111111111111111111111111111, ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL, 11111111111111111111111111111111, TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA, pAMMBay6oceH9fJKBRHGP5D4bD4sWpmSwMn52FMfXEA] findings=[spl-close-account]
- **428289500-7.json** (slot=428289500): programIds=[TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb, MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr] findings=[]
- **428290000-0.json** (slot=428290000): programIds=[ComputeBudget111111111111111111111111111111, A5X6pdbNATpoPYm1Qk5igf31zkiz2UT44uMuDsbsqTAp] findings=[]
- **428290000-1.json** (slot=428290000): programIds=[ComputeBudget111111111111111111111111111111, ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL, 11111111111111111111111111111111, TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA, pAMMBay6oceH9fJKBRHGP5D4bD4sWpmSwMn52FMfXEA] findings=[registry-pump-amm-unknown-instruction, spl-close-account]
- **428290000-12.json** (slot=428290000): programIds=[ComputeBudget111111111111111111111111111111, ojh19ojaKduoJZuaJADhcVGp4xt1TcdAvZmpVsCorch] findings=[]
- **428290000-15.json** (slot=428290000): programIds=[ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL, TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb] findings=[]
- **428290000-2.json** (slot=428290000): programIds=[T1pyyaTNZsKv2WcRAB8oVnk93mLJw2XzjtVYqCsaHqt] findings=[]
- **428290000-20.json** (slot=428290000): programIds=[ComputeBudget111111111111111111111111111111, ojh19ojaKduoJZuaJADhcVGp4xt1TcdAvZmpVsCorch] findings=[]
- **428290000-23.json** (slot=428290000): programIds=[ComputeBudget111111111111111111111111111111, TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb] findings=[token2022-close-account]
- **428290000-26.json** (slot=428290000): programIds=[sa12qbQyuQqEaDcEqEPKmZEGTdzSMaqj87nKRYbE3QE, Secp256r1SigVerify1111111111111111111111111] findings=[]
- **428290000-28.json** (slot=428290000): programIds=[ComputeBudget111111111111111111111111111111, ojh19ojaKduoJZuaJADhcVGp4xt1TcdAvZmpVsCorch] findings=[]
- **428290000-32.json** (slot=428290000): programIds=[TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA, ComputeBudget111111111111111111111111111111] findings=[spl-burn]
- **428290000-33.json** (slot=428290000): programIds=[sa12qbQyuQqEaDcEqEPKmZEGTdzSMaqj87nKRYbE3QE] findings=[]
- **428290000-35.json** (slot=428290000): programIds=[ComputeBudget111111111111111111111111111111, TessVdML9pBGgG9yGks7o4HewRaXVAMuoVj4x83GLQH] findings=[]
- **428290000-39.json** (slot=428290000): programIds=[ComputeBudget111111111111111111111111111111, ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL, 11111111111111111111111111111111, TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA, pAMMBay6oceH9fJKBRHGP5D4bD4sWpmSwMn52FMfXEA] findings=[spl-close-account]
- **428290000-4.json** (slot=428290000): programIds=[9H6tua7jkLhdm3w8BvgpTn5LZNU7g4ZynDmCiNN3q6Rp, ComputeBudget111111111111111111111111111111] findings=[]
- **428290000-42.json** (slot=428290000): programIds=[ComputeBudget111111111111111111111111111111, TessVdML9pBGgG9yGks7o4HewRaXVAMuoVj4x83GLQH] findings=[]
- **428290000-46.json** (slot=428290000): programIds=[ComputeBudget111111111111111111111111111111, ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL, cpamdpZCGKUy5JxQXB4dcpGPiikHawvSWAd6mEn1sGG, TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA] findings=[]
- **428290000-47.json** (slot=428290000): programIds=[DLv3NggMiSaef97YCkew5xKUHDh13tVGZ7tydt3ZeAru] findings=[]
- **428290000-49.json** (slot=428290000): programIds=[ComputeBudget111111111111111111111111111111, TessVdML9pBGgG9yGks7o4HewRaXVAMuoVj4x83GLQH] findings=[]
- **428290000-7.json** (slot=428290000): programIds=[ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL, TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb] findings=[]
- **428290000-8.json** (slot=428290000): programIds=[ComputeBudget111111111111111111111111111111, QuaNtZsgYRe5Z9Bk4LZ4cTD9tbkVoyCNf1R2BN9bBDv] findings=[]

## 4. ALT Sub-test (A2 Win: Resolution vs Empty Fetcher)

Comparing 5 benign v0+ALT fixtures: decision WITH resolved ALTs vs WITHOUT (empty fetcher).

| Fixture | With Resolution | Without Resolution | Improvement |
|---------|-----------------|-------------------|-------------|
| 428289500-1.json | SIGN | HOLD | YES — less conservative with resolution |
| 428289500-10.json | HOLD | HOLD | no change |
| 428289500-13.json | HOLD | HOLD | no change |
| 428289500-17.json | HOLD | HOLD | no change |
| 428289500-18.json | HOLD | HOLD | no change |

ALT resolution improvements: **1/5** fixtures showed reduced severity with resolved ALTs.

## 5. Malicious Corpus Recall

Total malicious fixtures: **37**

Caveat: this is a curated, mostly synthetic illustrative set designed around known loss primitives. Its recall measures coverage of these fixtures only; it does not mean the gate catches every malicious transaction. Adding independently sourced real mainnet malicious signatures would materially strengthen this evaluation.

| Family | Total | Caught (HOLD+REJECT) | Recall |
|--------|-------|---------------------|--------|
| SetAuthority-AccountOwner | 7 | 7 | 100.0% |
| System-Assign | 5 | 5 | 100.0% |
| SPL-Approve | 5 | 5 | 100.0% |
| Multi-Transfer-Sweep | 5 | 5 | 100.0% |
| Durable-Nonce-Sensitive | 5 | 5 | 100.0% |
| Token2022-PermanentDelegate | 5 | 5 | 100.0% |
| Squads-Hidden-Authority | 5 | 5 | 100.0% |
| **TOTAL** | **37** | **37** | **100.0%** |

All curated malicious fixtures were caught (HOLD or REJECT). No fixture in this illustrative set received SIGN.

### Per-Fixture Detail (Malicious)

| Family | Expected | Got | Caught | Note |
|--------|----------|-----|--------|------|
| SetAuthority-AccountOwner | REJECT | REJECT | YES | SPL Token SetAuthority(AccountOwner) changes account ownership to a new key |
| SetAuthority-AccountOwner | REJECT | REJECT | YES | SPL Token SetAuthority(AccountOwner) second variant different new authority |
| SetAuthority-AccountOwner | REJECT | REJECT | YES | SPL Token SetAuthority(AccountOwner) third variant |
| SetAuthority-AccountOwner | REJECT | REJECT | YES | SPL Token SetAuthority(AccountOwner) fourth variant different key |
| SetAuthority-AccountOwner | REJECT | REJECT | YES | SPL Token SetAuthority(AccountOwner) fifth variant |
| SetAuthority-AccountOwner | REJECT | REJECT | YES | Token-2022 SetAuthority(AccountOwner) — same disc, different program |
| SetAuthority-AccountOwner | REJECT | REJECT | YES | Token-2022 SetAuthority(AccountOwner) second variant |
| System-Assign | REJECT | REJECT | YES | System Assign changes program owner of an account |
| System-Assign | REJECT | HOLD | YES | System AssignWithSeed changes program owner with seed derivation |
| System-Assign | REJECT | REJECT | YES | System Assign to BPFLoader-like owner |
| System-Assign | REJECT | REJECT | YES | ComputeBudget + System Assign — compute prefix doesn't launder danger |
| System-Assign | REJECT | REJECT | YES | System Assign on a non-signer account (still dangerous) |
| SPL-Approve | HOLD | HOLD | YES | SPL Token Approve grants spending authority to a non-signer delegate |
| SPL-Approve | HOLD | HOLD | YES | SPL Token ApproveChecked with large amount to non-signer delegate |
| SPL-Approve | HOLD | HOLD | YES | Token-2022 Approve (same disc=4) to non-signer delegate |
| SPL-Approve | HOLD | HOLD | YES | Token-2022 ApproveChecked to non-signer delegate |
| SPL-Approve | HOLD | HOLD | YES | SPL Token Approve with max u64 amount |
| Multi-Transfer-Sweep | HOLD | HOLD | YES | 3 SOL transfers in one tx — total 3 SOL exceeds 1 SOL threshold |
| Multi-Transfer-Sweep | HOLD | HOLD | YES | 5 SOL transfers — total 5 SOL |
| Multi-Transfer-Sweep | HOLD | HOLD | YES | 10 SOL transfers — draining sweep pattern |
| Multi-Transfer-Sweep | HOLD | HOLD | YES | 2 SOL transfers — 2 SOL total (above threshold) |
| Multi-Transfer-Sweep | HOLD | HOLD | YES | 8 SOL transfers — major sweep |
| Durable-Nonce-Sensitive | HOLD | HOLD | YES | Bare durable-nonce (AdvanceNonceAccount at ix0) — replay risk |
| Durable-Nonce-Sensitive | REJECT | REJECT | YES | Durable-nonce + SetAuthority — Drift attack shape (REJECT due to Drift composite |
| Durable-Nonce-Sensitive | REJECT | REJECT | YES | Durable-nonce + Assign — the combination is Drift-composite (REJECT) |
| Durable-Nonce-Sensitive | HOLD | HOLD | YES | Durable-nonce + large SOL transfer — at least HOLD from nonce detection |
| Durable-Nonce-Sensitive | HOLD | HOLD | YES | Durable-nonce + SPL Approve — dual danger (nonce HOLD + approve HOLD) |
| Token2022-PermanentDelegate | HOLD | HOLD | YES | Token-2022 TransferChecked with PermanentDelegate mint extension → HOLD |
| Token2022-PermanentDelegate | HOLD | HOLD | YES | Token-2022 TransferChecked with PermanentDelegate — second variant (same mint, d |
| Token2022-PermanentDelegate | HOLD | HOLD | YES | Token-2022 TransferChecked with PermanentDelegate — different mint |
| Token2022-PermanentDelegate | HOLD | HOLD | YES | Token-2022 TransferChecked with TransferHook extension → HOLD |
| Token2022-PermanentDelegate | HOLD | HOLD | YES | Token-2022 with both PermanentDelegate AND TransferHook — dual extension danger |
| Squads-Hidden-Authority | HOLD | HOLD | YES | Squads vaultTransactionExecute without inner bytes → HOLD (squads-execute-unveri |
| Squads-Hidden-Authority | REJECT | REJECT | YES | Squads vaultTransactionExecute with inner update_admin discriminator → REJECT |
| Squads-Hidden-Authority | REJECT | HOLD | YES | Squads execute with inner SetAuthority(AccountOwner) → REJECT |
| Squads-Hidden-Authority | REJECT | HOLD | YES | Durable-nonce + Squads execute = Drift composite → REJECT |
| Squads-Hidden-Authority | HOLD | HOLD | YES | Squads execute with unresolved ALT inner program → HOLD (fail-closed) |

## 6. Summary

| Metric | Value |
|--------|-------|
| Benign corpus size | 100 transactions |
| Benign SIGN precision | 100.0% (33/33) |
| Benign SIGN rate | 33.0% |
| Benign false-REJECT | 0 |
| Benign HOLD rate | 67.0% |
| HOLDs with unresolved ALT | 1 |
| HOLDs without ALT | 38 |
| Malicious corpus size | 37 fixtures |
| Curated malicious-set recall | 100.0% (37/37) |
| ALT sub-test wins | 1/5 |
| SetAuthority-AccountOwner recall | 100.0% (7/7) |
| System-Assign recall | 100.0% (5/5) |
| SPL-Approve recall | 100.0% (5/5) |
