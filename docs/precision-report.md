# Sign-Safe Precision Report

Generated: 2026-06-29T22:59:00.599Z
Pinned slots: 428290000, 428289500

## 1. Signing Precision and Review Rate

Total benign fixtures: **500**
Benign SIGN precision: **100.0%** (92/92 SIGN decisions across this corpus were benign).
Benign HOLD rate: **81.6%** (408/500).

These are corpus measurements, not population-wide guarantees. A zero false-REJECT count is useful calibration evidence, but zero false positives is not the optimization target for a fail-closed signing gate; the HOLD rate shows the review cost directly.

Prior corpus (v0.5.x, 100 tx): 36% SIGN / 64% HOLD / 0 false-REJECT. This larger, more diverse 500-tx sample is more conservative (lower SIGN rate); the load-bearing property -- 0 false-REJECT -- holds at scale.

| Decision | Count | Pct |
|----------|-------|-----|
| SIGN     |    92 | 18.4% |
| HOLD     |   408 | 81.6% |
| REJECT   |     0 | 0.0% |

### Category Breakdown (benign)

| Version | HasALT | Count |
|---------|--------|-------|
| 0 | no-ALT | 101 |
| 0 | with-ALT | 195 |
| legacy | no-ALT | 204 |

## 2. False-REJECTs (Benign REJECTs — Target: 0)

**None.** Zero false-REJECTs. All benign transactions were classified SIGN or HOLD.

## 3. Benign HOLD Analysis

Total benign HOLDs: **408**

| Category | Count | Explanation |
|----------|-------|-------------|
| Has unresolved ALT | 1 | ALT accounts could not be resolved (fail-closed HOLD) |
| Has resolved ALT   | 164 | ALT resolved but other HOLD finding present |
| No ALT (other)     | 243 | HOLD from non-ALT finding (large transfer, nonce, etc.) |

### Benign HOLDs (non-ALT causes) — review findings:

- **428289500-0.json** (slot=428289500): programIds=[T1pyyaTNZsKv2WcRAB8oVnk93mLJw2XzjtVYqCsaHqt] findings=[]
- **428289500-11.json** (slot=428289500): programIds=[2DNbzPochEcyCcWMbL4d9S3u9QqQEj5bbe6cSZFvKsbh, ComputeBudget111111111111111111111111111111] findings=[]
- **428289500-12.json** (slot=428289500): programIds=[9H6tua7jkLhdm3w8BvgpTn5LZNU7g4ZynDmCiNN3q6Rp, ComputeBudget111111111111111111111111111111] findings=[]
- **428289500-19.json** (slot=428289500): programIds=[BiSoNHVpsVZW2F7rx2eQ59yQwKxzU5NvBcmKshCSUypi, ComputeBudget111111111111111111111111111111] findings=[]
- **428289500-20.json** (slot=428289500): programIds=[9H6tua7jkLhdm3w8BvgpTn5LZNU7g4ZynDmCiNN3q6Rp, ComputeBudget111111111111111111111111111111] findings=[]
- **428289500-27.json** (slot=428289500): programIds=[BiSoNHVpsVZW2F7rx2eQ59yQwKxzU5NvBcmKshCSUypi, ComputeBudget111111111111111111111111111111] findings=[]
- **428289500-28.json** (slot=428289500): programIds=[11111111111111111111111111111111, dijkbkCAKfFTCxQg3u1pg82gVU1jJGHBBRcteD11mBu, ComputeBudget111111111111111111111111111111] findings=[durable-nonce-advance]
- **428289500-3.json** (slot=428289500): programIds=[EtrnLzgbS7nMMy5fbD42kXiUzGg8XQzJ972Xtk1cjWih, ComputeBudget111111111111111111111111111111, 11111111111111111111111111111111] findings=[]
- **428289500-30.json** (slot=428289500): programIds=[ComputeBudget111111111111111111111111111111, ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL, pAMMBay6oceH9fJKBRHGP5D4bD4sWpmSwMn52FMfXEA, TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA] findings=[spl-close-account]
- **428289500-36.json** (slot=428289500): programIds=[11111111111111111111111111111111, dijkbkCAKfFTCxQg3u1pg82gVU1jJGHBBRcteD11mBu, ComputeBudget111111111111111111111111111111] findings=[durable-nonce-advance]
- **428289500-39.json** (slot=428289500): programIds=[6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P, TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb, 11111111111111111111111111111111] findings=[token2022-close-account, registry-pump-fun-unknown-instruction]
- **428289500-4.json** (slot=428289500): programIds=[9H6tua7jkLhdm3w8BvgpTn5LZNU7g4ZynDmCiNN3q6Rp, ComputeBudget111111111111111111111111111111] findings=[]
- **428289500-43.json** (slot=428289500): programIds=[ComputeBudget111111111111111111111111111111, 11111111111111111111111111111111] findings=[system-large-transfer]
- **428289500-44.json** (slot=428289500): programIds=[9H6tua7jkLhdm3w8BvgpTn5LZNU7g4ZynDmCiNN3q6Rp, ComputeBudget111111111111111111111111111111] findings=[]
- **428289500-46.json** (slot=428289500): programIds=[ComputeBudget111111111111111111111111111111, ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL, 11111111111111111111111111111111, TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA, pAMMBay6oceH9fJKBRHGP5D4bD4sWpmSwMn52FMfXEA] findings=[spl-unrecognized-instruction, spl-close-account]
- **428290000-0.json** (slot=428290000): programIds=[ComputeBudget111111111111111111111111111111, A5X6pdbNATpoPYm1Qk5igf31zkiz2UT44uMuDsbsqTAp] findings=[]
- **428290000-1.json** (slot=428290000): programIds=[ComputeBudget111111111111111111111111111111, ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL, 11111111111111111111111111111111, TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA, pAMMBay6oceH9fJKBRHGP5D4bD4sWpmSwMn52FMfXEA] findings=[spl-unrecognized-instruction, registry-pump-amm-unknown-instruction, spl-close-account]
- **428290000-12.json** (slot=428290000): programIds=[ComputeBudget111111111111111111111111111111, ojh19ojaKduoJZuaJADhcVGp4xt1TcdAvZmpVsCorch] findings=[]
- **428290000-15.json** (slot=428290000): programIds=[ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL, TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb] findings=[ata-create-idempotent-external-wallet]
- **428290000-2.json** (slot=428290000): programIds=[T1pyyaTNZsKv2WcRAB8oVnk93mLJw2XzjtVYqCsaHqt] findings=[]
- **428290000-20.json** (slot=428290000): programIds=[ComputeBudget111111111111111111111111111111, ojh19ojaKduoJZuaJADhcVGp4xt1TcdAvZmpVsCorch] findings=[]
- **428290000-23.json** (slot=428290000): programIds=[ComputeBudget111111111111111111111111111111, TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb] findings=[token2022-close-account]
- **428290000-26.json** (slot=428290000): programIds=[sa12qbQyuQqEaDcEqEPKmZEGTdzSMaqj87nKRYbE3QE, Secp256r1SigVerify1111111111111111111111111] findings=[]
- **428290000-28.json** (slot=428290000): programIds=[ComputeBudget111111111111111111111111111111, ojh19ojaKduoJZuaJADhcVGp4xt1TcdAvZmpVsCorch] findings=[]
- **428290000-32.json** (slot=428290000): programIds=[TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA, ComputeBudget111111111111111111111111111111] findings=[spl-burn]
- **428290000-33.json** (slot=428290000): programIds=[sa12qbQyuQqEaDcEqEPKmZEGTdzSMaqj87nKRYbE3QE] findings=[]
- **428290000-35.json** (slot=428290000): programIds=[ComputeBudget111111111111111111111111111111, TessVdML9pBGgG9yGks7o4HewRaXVAMuoVj4x83GLQH] findings=[]
- **428290000-39.json** (slot=428290000): programIds=[ComputeBudget111111111111111111111111111111, ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL, 11111111111111111111111111111111, TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA, pAMMBay6oceH9fJKBRHGP5D4bD4sWpmSwMn52FMfXEA] findings=[spl-unrecognized-instruction, spl-close-account]
- **428290000-4.json** (slot=428290000): programIds=[9H6tua7jkLhdm3w8BvgpTn5LZNU7g4ZynDmCiNN3q6Rp, ComputeBudget111111111111111111111111111111] findings=[]
- **428290000-42.json** (slot=428290000): programIds=[ComputeBudget111111111111111111111111111111, TessVdML9pBGgG9yGks7o4HewRaXVAMuoVj4x83GLQH] findings=[]
- **428290000-46.json** (slot=428290000): programIds=[ComputeBudget111111111111111111111111111111, ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL, cpamdpZCGKUy5JxQXB4dcpGPiikHawvSWAd6mEn1sGG, TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA] findings=[]
- **428290000-47.json** (slot=428290000): programIds=[DLv3NggMiSaef97YCkew5xKUHDh13tVGZ7tydt3ZeAru] findings=[]
- **428290000-49.json** (slot=428290000): programIds=[ComputeBudget111111111111111111111111111111, TessVdML9pBGgG9yGks7o4HewRaXVAMuoVj4x83GLQH] findings=[]
- **428290000-7.json** (slot=428290000): programIds=[ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL, TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb] findings=[ata-create-idempotent-external-wallet]
- **428290000-8.json** (slot=428290000): programIds=[ComputeBudget111111111111111111111111111111, QuaNtZsgYRe5Z9Bk4LZ4cTD9tbkVoyCNf1R2BN9bBDv] findings=[]
- **429745000-1.json** (slot=429745000): programIds=[9H6tua7jkLhdm3w8BvgpTn5LZNU7g4ZynDmCiNN3q6Rp, ComputeBudget111111111111111111111111111111] findings=[]
- **429745000-12.json** (slot=429745000): programIds=[BiSoNHVpsVZW2F7rx2eQ59yQwKxzU5NvBcmKshCSUypi] findings=[]
- **429745000-15.json** (slot=429745000): programIds=[11111111111111111111111111111111, dijkbkCAKfFTCxQg3u1pg82gVU1jJGHBBRcteD11mBu, ComputeBudget111111111111111111111111111111] findings=[durable-nonce-advance]
- **429745000-16.json** (slot=429745000): programIds=[EtrnLzgbS7nMMy5fbD42kXiUzGg8XQzJ972Xtk1cjWih, ComputeBudget111111111111111111111111111111] findings=[]
- **429745000-17.json** (slot=429745000): programIds=[ComputeBudget111111111111111111111111111111, ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL, 11111111111111111111111111111111, TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA, cpamdpZCGKUy5JxQXB4dcpGPiikHawvSWAd6mEn1sGG] findings=[spl-unrecognized-instruction, spl-close-account]
- **429745000-19.json** (slot=429745000): programIds=[BiSoNHVpsVZW2F7rx2eQ59yQwKxzU5NvBcmKshCSUypi] findings=[]
- **429745000-2.json** (slot=429745000): programIds=[ComputeBudget111111111111111111111111111111, 11111111111111111111111111111111] findings=[system-large-transfer]
- **429745000-22.json** (slot=429745000): programIds=[11111111111111111111111111111111, ComputeBudget111111111111111111111111111111, E2uCGJ4TtYyKPGaK57UMfbs9sgaumwDEZF1aAY6fF3mS] findings=[durable-nonce-advance]
- **429745000-23.json** (slot=429745000): programIds=[BiSoNHVpsVZW2F7rx2eQ59yQwKxzU5NvBcmKshCSUypi, ComputeBudget111111111111111111111111111111] findings=[]
- **429745000-24.json** (slot=429745000): programIds=[ComputeBudget111111111111111111111111111111, ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL, 675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8, TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA] findings=[registry-raydium-amm-v4-unknown-instruction, spl-close-account]
- **429745000-26.json** (slot=429745000): programIds=[BiSoNHVpsVZW2F7rx2eQ59yQwKxzU5NvBcmKshCSUypi] findings=[]
- **429745000-29.json** (slot=429745000): programIds=[ComputeBudget111111111111111111111111111111, QuaNtZsgYRe5Z9Bk4LZ4cTD9tbkVoyCNf1R2BN9bBDv] findings=[]
- **429745000-30.json** (slot=429745000): programIds=[ComputeBudget111111111111111111111111111111, FW6zUqn4iKRaeopwwhwsquTY6ABWLLgjxtrC3VPnaWBf] findings=[]
- **429745000-31.json** (slot=429745000): programIds=[ComputeBudget111111111111111111111111111111, ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL, cpamdpZCGKUy5JxQXB4dcpGPiikHawvSWAd6mEn1sGG, TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA] findings=[spl-close-account]
- **429745000-33.json** (slot=429745000): programIds=[BiSoNHVpsVZW2F7rx2eQ59yQwKxzU5NvBcmKshCSUypi] findings=[]
- **429745000-36.json** (slot=429745000): programIds=[ComputeBudget111111111111111111111111111111, riptK81hDxhe5pW5jSzSM9iRA8azgEgLJ4dXkPtBS7j] findings=[]
- **429745000-37.json** (slot=429745000): programIds=[ComputeBudget111111111111111111111111111111, phDEVv4w6BcfkLrLNeXr8HhhgQxnxziVGXpGPcaadMf] findings=[]
- **429745000-38.json** (slot=429745000): programIds=[ComputeBudget111111111111111111111111111111, ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL, 11111111111111111111111111111111, TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA, cpamdpZCGKUy5JxQXB4dcpGPiikHawvSWAd6mEn1sGG] findings=[spl-unrecognized-instruction, spl-close-account]
- **429745000-40.json** (slot=429745000): programIds=[BiSoNHVpsVZW2F7rx2eQ59yQwKxzU5NvBcmKshCSUypi] findings=[]
- **429745000-43.json** (slot=429745000): programIds=[ComputeBudget111111111111111111111111111111, TessVdML9pBGgG9yGks7o4HewRaXVAMuoVj4x83GLQH] findings=[]
- **429745000-44.json** (slot=429745000): programIds=[ComputeBudget111111111111111111111111111111, phDEVv4w6BcfkLrLNeXr8HhhgQxnxziVGXpGPcaadMf] findings=[]
- **429745000-45.json** (slot=429745000): programIds=[ComputeBudget111111111111111111111111111111, ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL, 11111111111111111111111111111111, TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA, cpamdpZCGKUy5JxQXB4dcpGPiikHawvSWAd6mEn1sGG] findings=[spl-unrecognized-instruction, spl-close-account]
- **429745000-47.json** (slot=429745000): programIds=[BiSoNHVpsVZW2F7rx2eQ59yQwKxzU5NvBcmKshCSUypi] findings=[]
- **429745000-5.json** (slot=429745000): programIds=[T1pyyaTNZsKv2WcRAB8oVnk93mLJw2XzjtVYqCsaHqt] findings=[]
- **429745000-8.json** (slot=429745000): programIds=[11111111111111111111111111111111, dijkbkCAKfFTCxQg3u1pg82gVU1jJGHBBRcteD11mBu, ComputeBudget111111111111111111111111111111] findings=[durable-nonce-advance]
- **429745000-9.json** (slot=429745000): programIds=[ComputeBudget111111111111111111111111111111, QuaNtZsgYRe5Z9Bk4LZ4cTD9tbkVoyCNf1R2BN9bBDv] findings=[]
- **429746000-0.json** (slot=429746000): programIds=[T1pyyaTNZsKv2WcRAB8oVnk93mLJw2XzjtVYqCsaHqt] findings=[]
- **429746000-1.json** (slot=429746000): programIds=[ComputeBudget111111111111111111111111111111, ojh19ojaKduoJZuaJADhcVGp4xt1TcdAvZmpVsCorch, 11111111111111111111111111111111] findings=[]
- **429746000-13.json** (slot=429746000): programIds=[BiSoNHVpsVZW2F7rx2eQ59yQwKxzU5NvBcmKshCSUypi, ComputeBudget111111111111111111111111111111, 11111111111111111111111111111111] findings=[]
- **429746000-14.json** (slot=429746000): programIds=[ComputeBudget111111111111111111111111111111, ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL, 11111111111111111111111111111111, TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA, cpamdpZCGKUy5JxQXB4dcpGPiikHawvSWAd6mEn1sGG] findings=[spl-unrecognized-instruction, spl-close-account, spl-unrecognized-instruction, spl-close-account]
- **429746000-16.json** (slot=429746000): programIds=[ComputeBudget111111111111111111111111111111, fastC7gqs2WUXgcyNna2BZAe9mte4zcTGprv3mv18N3] findings=[]
- **429746000-20.json** (slot=429746000): programIds=[ComputeBudget111111111111111111111111111111, 11111111111111111111111111111111, 3enQj1Awmf1WVGarKdL2NxoDWUto6XN1mX2Q3HNfghFW] findings=[]
- **429746000-21.json** (slot=429746000): programIds=[ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL, 11111111111111111111111111111111, TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA, pAMMBay6oceH9fJKBRHGP5D4bD4sWpmSwMn52FMfXEA] findings=[system-large-transfer, spl-unrecognized-instruction, spl-close-account, spl-close-account]
- **429746000-22.json** (slot=429746000): programIds=[HADRoNbLovyqhCsocfYQYB7QdfCAAinN9HTePvBCVDQ8] findings=[]
- **429746000-23.json** (slot=429746000): programIds=[ComputeBudget111111111111111111111111111111, fastC7gqs2WUXgcyNna2BZAe9mte4zcTGprv3mv18N3] findings=[]
- **429746000-27.json** (slot=429746000): programIds=[11111111111111111111111111111111, ComputeBudget111111111111111111111111111111, BoobsBSMpFRBA91sNwKLYShRRQPH5GjoCH4NhLUt4yRo] findings=[durable-nonce-advance]
- **429746000-28.json** (slot=429746000): programIds=[ComputeBudget111111111111111111111111111111, ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL, 11111111111111111111111111111111, TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA, pAMMBay6oceH9fJKBRHGP5D4bD4sWpmSwMn52FMfXEA] findings=[spl-unrecognized-instruction, spl-close-account]
- **429746000-29.json** (slot=429746000): programIds=[EtrnLzgbS7nMMy5fbD42kXiUzGg8XQzJ972Xtk1cjWih] findings=[]
- **429746000-30.json** (slot=429746000): programIds=[11111111111111111111111111111111, dijkbkCAKfFTCxQg3u1pg82gVU1jJGHBBRcteD11mBu, ComputeBudget111111111111111111111111111111] findings=[durable-nonce-advance]
- **429746000-34.json** (slot=429746000): programIds=[BiSoNHVpsVZW2F7rx2eQ59yQwKxzU5NvBcmKshCSUypi, ComputeBudget111111111111111111111111111111, 11111111111111111111111111111111] findings=[]
- **429746000-35.json** (slot=429746000): programIds=[ComputeBudget111111111111111111111111111111, ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL, 11111111111111111111111111111111, TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA, cpamdpZCGKUy5JxQXB4dcpGPiikHawvSWAd6mEn1sGG] findings=[spl-unrecognized-instruction, spl-close-account]
- **429746000-37.json** (slot=429746000): programIds=[ComputeBudget111111111111111111111111111111, E2uCGJ4TtYyKPGaK57UMfbs9sgaumwDEZF1aAY6fF3mS, 11111111111111111111111111111111] findings=[]
- **429746000-41.json** (slot=429746000): programIds=[ComputeBudget111111111111111111111111111111, idemJL67fKhpev5vKcxHrosuVyTat6wVC9sFfoPVg3Y, FD1amxhTsDpwzoVX41dxp2ygAESURV2zdUACzxM1Dfw9] findings=[]
- **429746000-42.json** (slot=429746000): programIds=[ComputeBudget111111111111111111111111111111, ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL, 11111111111111111111111111111111, TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA, cpamdpZCGKUy5JxQXB4dcpGPiikHawvSWAd6mEn1sGG] findings=[spl-unrecognized-instruction, spl-close-account]
- **429746000-44.json** (slot=429746000): programIds=[9H6tua7jkLhdm3w8BvgpTn5LZNU7g4ZynDmCiNN3q6Rp, 11111111111111111111111111111111, ComputeBudget111111111111111111111111111111] findings=[]
- **429746000-48.json** (slot=429746000): programIds=[EtrnLzgbS7nMMy5fbD42kXiUzGg8XQzJ972Xtk1cjWih, ComputeBudget111111111111111111111111111111] findings=[]
- **429746000-49.json** (slot=429746000): programIds=[ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL, 11111111111111111111111111111111, TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA, pAMMBay6oceH9fJKBRHGP5D4bD4sWpmSwMn52FMfXEA] findings=[system-large-transfer, spl-unrecognized-instruction, spl-close-account, spl-close-account]
- **429746000-6.json** (slot=429746000): programIds=[ComputeBudget111111111111111111111111111111, ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL, 11111111111111111111111111111111, TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA, pAMMBay6oceH9fJKBRHGP5D4bD4sWpmSwMn52FMfXEA] findings=[system-large-transfer, spl-unrecognized-instruction, spl-close-account]
- **429746000-7.json** (slot=429746000): programIds=[ComputeBudget111111111111111111111111111111, ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL, 11111111111111111111111111111111, TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA, JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4] findings=[spl-unrecognized-instruction, spl-close-account]
- **429746000-9.json** (slot=429746000): programIds=[ComputeBudget111111111111111111111111111111, TessVdML9pBGgG9yGks7o4HewRaXVAMuoVj4x83GLQH, 11111111111111111111111111111111] findings=[]
- **429747000-0.json** (slot=429747000): programIds=[9H6tua7jkLhdm3w8BvgpTn5LZNU7g4ZynDmCiNN3q6Rp, ComputeBudget111111111111111111111111111111] findings=[]
- **429747000-12.json** (slot=429747000): programIds=[BiSoNHVpsVZW2F7rx2eQ59yQwKxzU5NvBcmKshCSUypi, ComputeBudget111111111111111111111111111111] findings=[]
- **429747000-14.json** (slot=429747000): programIds=[ComputeBudget111111111111111111111111111111, ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL, cpamdpZCGKUy5JxQXB4dcpGPiikHawvSWAd6mEn1sGG, TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA] findings=[spl-close-account]
- **429747000-15.json** (slot=429747000): programIds=[ComputeBudget111111111111111111111111111111, 6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P, TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb, 11111111111111111111111111111111] findings=[token2022-close-account]
- **429747000-17.json** (slot=429747000): programIds=[11111111111111111111111111111111, dijkbkCAKfFTCxQg3u1pg82gVU1jJGHBBRcteD11mBu, ComputeBudget111111111111111111111111111111] findings=[durable-nonce-advance]
- **429747000-19.json** (slot=429747000): programIds=[HA1hgvskN1goEsb33rNHFBcDXBaYyLyyqfGwGMgTUwNo] findings=[]
- **429747000-2.json** (slot=429747000): programIds=[T1pyyaTNZsKv2WcRAB8oVnk93mLJw2XzjtVYqCsaHqt] findings=[]
- **429747000-20.json** (slot=429747000): programIds=[BiSoNHVpsVZW2F7rx2eQ59yQwKxzU5NvBcmKshCSUypi, ComputeBudget111111111111111111111111111111] findings=[]
- **429747000-22.json** (slot=429747000): programIds=[ComputeBudget111111111111111111111111111111, ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL, cpamdpZCGKUy5JxQXB4dcpGPiikHawvSWAd6mEn1sGG, TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA] findings=[spl-close-account]
- **429747000-23.json** (slot=429747000): programIds=[ComputeBudget111111111111111111111111111111, ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL, pAMMBay6oceH9fJKBRHGP5D4bD4sWpmSwMn52FMfXEA, TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb, TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA] findings=[token2022-close-account, spl-close-account]
- **429747000-25.json** (slot=429747000): programIds=[11111111111111111111111111111111, dijkbkCAKfFTCxQg3u1pg82gVU1jJGHBBRcteD11mBu, ComputeBudget111111111111111111111111111111] findings=[durable-nonce-advance]
- **429747000-27.json** (slot=429747000): programIds=[HA1hgvskN1goEsb33rNHFBcDXBaYyLyyqfGwGMgTUwNo] findings=[]
- **429747000-28.json** (slot=429747000): programIds=[11111111111111111111111111111111, EtrnLzgbS7nMMy5fbD42kXiUzGg8XQzJ972Xtk1cjWih, ComputeBudget111111111111111111111111111111] findings=[durable-nonce-advance]
- **429747000-3.json** (slot=429747000): programIds=[ComputeBudget111111111111111111111111111111, mmm3XBJg5gk8XJxEKBvdgptZz6SgK4tXvn36sodowMc] findings=[]
- **429747000-30.json** (slot=429747000): programIds=[ComputeBudget111111111111111111111111111111, ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL, 11111111111111111111111111111111, TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA, cpamdpZCGKUy5JxQXB4dcpGPiikHawvSWAd6mEn1sGG] findings=[spl-unrecognized-instruction, spl-close-account]
- **429747000-31.json** (slot=429747000): programIds=[ComputeBudget111111111111111111111111111111, 11111111111111111111111111111111, TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA, FLUXubRmkEi2q6K3Y9kBPg9248ggaZVsoSFhtJHSrm1X, TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb] findings=[spl-unrecognized-instruction, token2022-burn, token2022-close-account, spl-close-account]
- **429747000-33.json** (slot=429747000): programIds=[11111111111111111111111111111111, dijkbkCAKfFTCxQg3u1pg82gVU1jJGHBBRcteD11mBu, ComputeBudget111111111111111111111111111111] findings=[durable-nonce-advance]
- **429747000-35.json** (slot=429747000): programIds=[B8AwYzFmc3ZB5EWWVtJcJhJtEmKL78W5i3kZrL1uMCmP] findings=[]
- **429747000-36.json** (slot=429747000): programIds=[EtrnLzgbS7nMMy5fbD42kXiUzGg8XQzJ972Xtk1cjWih, ComputeBudget111111111111111111111111111111] findings=[]
- **429747000-38.json** (slot=429747000): programIds=[ComputeBudget111111111111111111111111111111, ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL, 11111111111111111111111111111111, TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA, cpamdpZCGKUy5JxQXB4dcpGPiikHawvSWAd6mEn1sGG] findings=[spl-unrecognized-instruction, spl-close-account]
- **429747000-40.json** (slot=429747000): programIds=[ComputeBudget111111111111111111111111111111, ojh19ojaKduoJZuaJADhcVGp4xt1TcdAvZmpVsCorch] findings=[]
- **429747000-43.json** (slot=429747000): programIds=[EtrnLzgbS7nMMy5fbD42kXiUzGg8XQzJ972Xtk1cjWih, ComputeBudget111111111111111111111111111111] findings=[]
- **429747000-45.json** (slot=429747000): programIds=[ComputeBudget111111111111111111111111111111, ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL, cpamdpZCGKUy5JxQXB4dcpGPiikHawvSWAd6mEn1sGG, TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA] findings=[spl-close-account]
- **429747000-47.json** (slot=429747000): programIds=[ComputeBudget111111111111111111111111111111, ojh19ojaKduoJZuaJADhcVGp4xt1TcdAvZmpVsCorch] findings=[]
- **429747000-49.json** (slot=429747000): programIds=[4FEFPeMH68BbkrrZW2ak9wWXUS7JCkvXqBkGf5Bg6wmh] findings=[]
- **429747000-5.json** (slot=429747000): programIds=[ComputeBudget111111111111111111111111111111, ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL, cpamdpZCGKUy5JxQXB4dcpGPiikHawvSWAd6mEn1sGG, TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA] findings=[spl-close-account]
- **429747000-6.json** (slot=429747000): programIds=[TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb] findings=[token2022-close-account]
- **429747000-8.json** (slot=429747000): programIds=[ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL, JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4, TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA] findings=[spl-close-account]
- **429747000-9.json** (slot=429747000): programIds=[9H6tua7jkLhdm3w8BvgpTn5LZNU7g4ZynDmCiNN3q6Rp, ComputeBudget111111111111111111111111111111] findings=[]
- **429748000-0.json** (slot=429748000): programIds=[T1pyyaTNZsKv2WcRAB8oVnk93mLJw2XzjtVYqCsaHqt] findings=[]
- **429748000-11.json** (slot=429748000): programIds=[ComputeBudget111111111111111111111111111111, TessVdML9pBGgG9yGks7o4HewRaXVAMuoVj4x83GLQH] findings=[]
- **429748000-12.json** (slot=429748000): programIds=[ComputeBudget111111111111111111111111111111, QuaNtZsgYRe5Z9Bk4LZ4cTD9tbkVoyCNf1R2BN9bBDv] findings=[]
- **429748000-13.json** (slot=429748000): programIds=[ComputeBudget111111111111111111111111111111, 11111111111111111111111111111111, ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL, TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA] findings=[spl-unrecognized-instruction, spl-close-account]
- **429748000-14.json** (slot=429748000): programIds=[ComputeBudget111111111111111111111111111111, ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL, pAMMBay6oceH9fJKBRHGP5D4bD4sWpmSwMn52FMfXEA, TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA, TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb] findings=[spl-close-account, token2022-close-account]
- **429748000-16.json** (slot=429748000): programIds=[EtrnLzgbS7nMMy5fbD42kXiUzGg8XQzJ972Xtk1cjWih] findings=[]
- **429748000-19.json** (slot=429748000): programIds=[ComputeBudget111111111111111111111111111111, TessVdML9pBGgG9yGks7o4HewRaXVAMuoVj4x83GLQH] findings=[]
- **429748000-20.json** (slot=429748000): programIds=[ComputeBudget111111111111111111111111111111, idemJL67fKhpev5vKcxHrosuVyTat6wVC9sFfoPVg3Y, FD1amxhTsDpwzoVX41dxp2ygAESURV2zdUACzxM1Dfw9] findings=[]
- **429748000-21.json** (slot=429748000): programIds=[ComputeBudget111111111111111111111111111111, ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL, 11111111111111111111111111111111, TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA, cpamdpZCGKUy5JxQXB4dcpGPiikHawvSWAd6mEn1sGG] findings=[spl-unrecognized-instruction, spl-close-account]
- **429748000-22.json** (slot=429748000): programIds=[TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb] findings=[token2022-burn]
- **429748000-24.json** (slot=429748000): programIds=[sa12qbQyuQqEaDcEqEPKmZEGTdzSMaqj87nKRYbE3QE, Ed25519SigVerify111111111111111111111111111] findings=[]
- **429748000-27.json** (slot=429748000): programIds=[ComputeBudget111111111111111111111111111111, TessVdML9pBGgG9yGks7o4HewRaXVAMuoVj4x83GLQH] findings=[]
- **429748000-28.json** (slot=429748000): programIds=[ComputeBudget111111111111111111111111111111, FW6zUqn4iKRaeopwwhwsquTY6ABWLLgjxtrC3VPnaWBf] findings=[]
- **429748000-3.json** (slot=429748000): programIds=[9H6tua7jkLhdm3w8BvgpTn5LZNU7g4ZynDmCiNN3q6Rp, ComputeBudget111111111111111111111111111111] findings=[]
- **429748000-30.json** (slot=429748000): programIds=[TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb] findings=[token2022-close-account]
- **429748000-32.json** (slot=429748000): programIds=[sa12qbQyuQqEaDcEqEPKmZEGTdzSMaqj87nKRYbE3QE] findings=[]
- **429748000-35.json** (slot=429748000): programIds=[ComputeBudget111111111111111111111111111111, TessVdML9pBGgG9yGks7o4HewRaXVAMuoVj4x83GLQH] findings=[]
- **429748000-36.json** (slot=429748000): programIds=[EtrnLzgbS7nMMy5fbD42kXiUzGg8XQzJ972Xtk1cjWih, ComputeBudget111111111111111111111111111111] findings=[]
- **429748000-37.json** (slot=429748000): programIds=[ComputeBudget111111111111111111111111111111, ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL, 11111111111111111111111111111111, TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA, LBUZKhRxPF3XUpBCjp4YzTKgLccjZhTSDM9YuVaPwxo] findings=[spl-unrecognized-instruction, registry-meteora-dlmm-unknown-instruction, spl-close-account]
- **429748000-4.json** (slot=429748000): programIds=[ComputeBudget111111111111111111111111111111, ALPHAQmeA7bjrVuccPsYPiCvsi428SNwte66Srvs4pHA] findings=[]
- **429748000-40.json** (slot=429748000): programIds=[oreV3EG1i9BEgiAJ8b177Z2S2rMarzak4NMv1kULvWv] findings=[]
- **429748000-43.json** (slot=429748000): programIds=[ComputeBudget111111111111111111111111111111, TessVdML9pBGgG9yGks7o4HewRaXVAMuoVj4x83GLQH] findings=[]
- **429748000-44.json** (slot=429748000): programIds=[EtrnLzgbS7nMMy5fbD42kXiUzGg8XQzJ972Xtk1cjWih, ComputeBudget111111111111111111111111111111] findings=[]
- **429748000-45.json** (slot=429748000): programIds=[ComputeBudget111111111111111111111111111111, ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL, cpamdpZCGKUy5JxQXB4dcpGPiikHawvSWAd6mEn1sGG, TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA] findings=[spl-close-account]
- **429748000-8.json** (slot=429748000): programIds=[EtrnLzgbS7nMMy5fbD42kXiUzGg8XQzJ972Xtk1cjWih] findings=[]
- **429749000-0.json** (slot=429749000): programIds=[T1pyyaTNZsKv2WcRAB8oVnk93mLJw2XzjtVYqCsaHqt] findings=[]
- **429749000-1.json** (slot=429749000): programIds=[ComputeBudget111111111111111111111111111111, ojh19ojaKduoJZuaJADhcVGp4xt1TcdAvZmpVsCorch] findings=[]
- **429749000-10.json** (slot=429749000): programIds=[ComputeBudget111111111111111111111111111111, TessVdML9pBGgG9yGks7o4HewRaXVAMuoVj4x83GLQH] findings=[]
- **429749000-11.json** (slot=429749000): programIds=[ComputeBudget111111111111111111111111111111, idemJL67fKhpev5vKcxHrosuVyTat6wVC9sFfoPVg3Y, FD1amxhTsDpwzoVX41dxp2ygAESURV2zdUACzxM1Dfw9] findings=[]
- **429749000-14.json** (slot=429749000): programIds=[ComputeBudget111111111111111111111111111111, 11111111111111111111111111111111, 6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P, TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb] findings=[token2022-close-account]
- **429749000-16.json** (slot=429749000): programIds=[ComputeBudget111111111111111111111111111111, JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4] findings=[registry-jupiter-v6-unknown-instruction]
- **429749000-19.json** (slot=429749000): programIds=[ComputeBudget111111111111111111111111111111, TessVdML9pBGgG9yGks7o4HewRaXVAMuoVj4x83GLQH] findings=[]
- **429749000-2.json** (slot=429749000): programIds=[ComputeBudget111111111111111111111111111111, A5X6pdbNATpoPYm1Qk5igf31zkiz2UT44uMuDsbsqTAp] findings=[]
- **429749000-20.json** (slot=429749000): programIds=[FLUX6xBayGxLX9UcimVRxXFMHH6q43mAbRvDzSpCsvfK, ComputeBudget111111111111111111111111111111] findings=[]
- **429749000-22.json** (slot=429749000): programIds=[ComputeBudget111111111111111111111111111111, ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL, 11111111111111111111111111111111, TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA, cpamdpZCGKUy5JxQXB4dcpGPiikHawvSWAd6mEn1sGG] findings=[spl-unrecognized-instruction, spl-close-account]
- **429749000-23.json** (slot=429749000): programIds=[ComputeBudget111111111111111111111111111111, ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL, pAMMBay6oceH9fJKBRHGP5D4bD4sWpmSwMn52FMfXEA, TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA, TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb] findings=[spl-close-account, token2022-close-account]
- **429749000-28.json** (slot=429749000): programIds=[ComputeBudget111111111111111111111111111111, TessVdML9pBGgG9yGks7o4HewRaXVAMuoVj4x83GLQH] findings=[]
- **429749000-29.json** (slot=429749000): programIds=[ComputeBudget111111111111111111111111111111, QuaNtZsgYRe5Z9Bk4LZ4cTD9tbkVoyCNf1R2BN9bBDv] findings=[]
- **429749000-31.json** (slot=429749000): programIds=[ComputeBudget111111111111111111111111111111, ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL, 11111111111111111111111111111111, TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA, cpamdpZCGKUy5JxQXB4dcpGPiikHawvSWAd6mEn1sGG] findings=[spl-unrecognized-instruction, spl-close-account]
- **429749000-36.json** (slot=429749000): programIds=[ComputeBudget111111111111111111111111111111, TessVdML9pBGgG9yGks7o4HewRaXVAMuoVj4x83GLQH] findings=[]
- **429749000-37.json** (slot=429749000): programIds=[ComputeBudget111111111111111111111111111111, QuaNtZsgYRe5Z9Bk4LZ4cTD9tbkVoyCNf1R2BN9bBDv] findings=[]
- **429749000-39.json** (slot=429749000): programIds=[ComputeBudget111111111111111111111111111111, ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL, 11111111111111111111111111111111, TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA, cpamdpZCGKUy5JxQXB4dcpGPiikHawvSWAd6mEn1sGG] findings=[spl-unrecognized-instruction, spl-close-account, spl-unrecognized-instruction, spl-close-account]
- **429749000-4.json** (slot=429749000): programIds=[11111111111111111111111111111111, ComputeBudget111111111111111111111111111111, ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL, TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA] findings=[durable-nonce-advance, ata-create-idempotent-external-wallet]
- **429749000-40.json** (slot=429749000): programIds=[ComputeBudget111111111111111111111111111111, ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL, pAMMBay6oceH9fJKBRHGP5D4bD4sWpmSwMn52FMfXEA, TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA, TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb] findings=[spl-close-account, token2022-close-account]
- **429749000-43.json** (slot=429749000): programIds=[HbPEwwAbEqbTJ3H8gJc7VYw1VB7ZMTRAm5u1QvQiUk4E] findings=[]
- **429749000-44.json** (slot=429749000): programIds=[ComputeBudget111111111111111111111111111111, TessVdML9pBGgG9yGks7o4HewRaXVAMuoVj4x83GLQH] findings=[]
- **429749000-45.json** (slot=429749000): programIds=[ComputeBudget111111111111111111111111111111, QuaNtZsgYRe5Z9Bk4LZ4cTD9tbkVoyCNf1R2BN9bBDv] findings=[]
- **429749000-47.json** (slot=429749000): programIds=[ComputeBudget111111111111111111111111111111, ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL, 11111111111111111111111111111111, TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA, pAMMBay6oceH9fJKBRHGP5D4bD4sWpmSwMn52FMfXEA] findings=[spl-unrecognized-instruction, registry-pump-amm-unknown-instruction, spl-close-account]
- **429749000-48.json** (slot=429749000): programIds=[ComputeBudget111111111111111111111111111111, ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL, pAMMBay6oceH9fJKBRHGP5D4bD4sWpmSwMn52FMfXEA, TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA, TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb] findings=[spl-close-account, token2022-close-account]
- **429749000-5.json** (slot=429749000): programIds=[ComputeBudget111111111111111111111111111111, ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL, TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb] findings=[ata-create-idempotent-external-wallet, ata-create-idempotent-external-wallet, ata-create-idempotent-external-wallet, ata-create-idempotent-external-wallet, ata-create-idempotent-external-wallet, ata-create-idempotent-external-wallet, ata-create-idempotent-external-wallet, ata-create-idempotent-external-wallet]
- **429750000-0.json** (slot=429750000): programIds=[T1pyyaTNZsKv2WcRAB8oVnk93mLJw2XzjtVYqCsaHqt] findings=[]
- **429750000-1.json** (slot=429750000): programIds=[ComputeBudget111111111111111111111111111111, E2uCGJ4TtYyKPGaK57UMfbs9sgaumwDEZF1aAY6fF3mS] findings=[]
- **429750000-10.json** (slot=429750000): programIds=[ComputeBudget111111111111111111111111111111, W1LDCARDa67SPBG7TFpQivHnEZXRtxCFP13ysEd1bWR] findings=[]
- **429750000-11.json** (slot=429750000): programIds=[FLUX6xBayGxLX9UcimVRxXFMHH6q43mAbRvDzSpCsvfK, ComputeBudget111111111111111111111111111111] findings=[]
- **429750000-13.json** (slot=429750000): programIds=[ComputeBudget111111111111111111111111111111, 11111111111111111111111111111111, TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA, cpamdpZCGKUy5JxQXB4dcpGPiikHawvSWAd6mEn1sGG] findings=[spl-unrecognized-instruction, spl-unrecognized-instruction, spl-unrecognized-instruction, spl-close-account]
- **429750000-15.json** (slot=429750000): programIds=[ComputeBudget111111111111111111111111111111, TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb, 11111111111111111111111111111111] findings=[token2022-burn, token2022-close-account]
- **429750000-18.json** (slot=429750000): programIds=[ComputeBudget111111111111111111111111111111, W1LDCARDa67SPBG7TFpQivHnEZXRtxCFP13ysEd1bWR] findings=[]
- **429750000-2.json** (slot=429750000): programIds=[BiSoNHVpsVZW2F7rx2eQ59yQwKxzU5NvBcmKshCSUypi, ComputeBudget111111111111111111111111111111] findings=[]
- **429750000-21.json** (slot=429750000): programIds=[ComputeBudget111111111111111111111111111111, 11111111111111111111111111111111, ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL, 6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P, TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA] findings=[registry-pump-fun-unknown-instruction, spl-close-account]
- **429750000-23.json** (slot=429750000): programIds=[ComputeBudget111111111111111111111111111111, TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb] findings=[token2022-close-account]
- **429750000-26.json** (slot=429750000): programIds=[ComputeBudget111111111111111111111111111111, W1LDCARDa67SPBG7TFpQivHnEZXRtxCFP13ysEd1bWR] findings=[]
- **429750000-27.json** (slot=429750000): programIds=[ComputeBudget111111111111111111111111111111, SoLFiHG9TfgtdUXUjWAxi3LtvYuFyDLVhBWxdMZxyCe] findings=[]
- **429750000-29.json** (slot=429750000): programIds=[ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL, pAMMBay6oceH9fJKBRHGP5D4bD4sWpmSwMn52FMfXEA, TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA, 11111111111111111111111111111111, ComputeBudget111111111111111111111111111111] findings=[spl-close-account]
- **429750000-31.json** (slot=429750000): programIds=[ComputeBudget111111111111111111111111111111, ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL, TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb] findings=[ata-create-idempotent-external-wallet, token2022-approve-delegate]
- **429750000-34.json** (slot=429750000): programIds=[ComputeBudget111111111111111111111111111111, W1LDCARDa67SPBG7TFpQivHnEZXRtxCFP13ysEd1bWR] findings=[]
- **429750000-35.json** (slot=429750000): programIds=[ComputeBudget111111111111111111111111111111, SoLFiHG9TfgtdUXUjWAxi3LtvYuFyDLVhBWxdMZxyCe] findings=[]
- **429750000-37.json** (slot=429750000): programIds=[ComputeBudget111111111111111111111111111111, ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL, 11111111111111111111111111111111, TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA, cpamdpZCGKUy5JxQXB4dcpGPiikHawvSWAd6mEn1sGG] findings=[spl-unrecognized-instruction, spl-close-account]
- **429750000-41.json** (slot=429750000): programIds=[9H6tua7jkLhdm3w8BvgpTn5LZNU7g4ZynDmCiNN3q6Rp, ComputeBudget111111111111111111111111111111] findings=[]
- **429750000-42.json** (slot=429750000): programIds=[ComputeBudget111111111111111111111111111111, mERKcfxMC5SqJn4Ld4BUris3WKZZ1ojjWJ3A3J5CKxv, L2TExMFKdjpN9kozasaurPirfHy9P8sbXoAN1qA3S95] findings=[]
- **429750000-44.json** (slot=429750000): programIds=[ComputeBudget111111111111111111111111111111, ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL, 11111111111111111111111111111111, TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA, cpamdpZCGKUy5JxQXB4dcpGPiikHawvSWAd6mEn1sGG] findings=[spl-unrecognized-instruction, spl-close-account]
- **429750000-48.json** (slot=429750000): programIds=[ComputeBudget111111111111111111111111111111, E2uCGJ4TtYyKPGaK57UMfbs9sgaumwDEZF1aAY6fF3mS] findings=[]
- **429750000-49.json** (slot=429750000): programIds=[ComputeBudget111111111111111111111111111111, A5X6pdbNATpoPYm1Qk5igf31zkiz2UT44uMuDsbsqTAp] findings=[]
- **429750000-6.json** (slot=429750000): programIds=[ComputeBudget111111111111111111111111111111, TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA, TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb, 11111111111111111111111111111111] findings=[spl-close-account, token2022-close-account]
- **429750000-8.json** (slot=429750000): programIds=[ComputeBudget111111111111111111111111111111, ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL, 11111111111111111111111111111111, TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA, JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4] findings=[spl-unrecognized-instruction, spl-close-account]
- **429751000-0.json** (slot=429751000): programIds=[T1pyyaTNZsKv2WcRAB8oVnk93mLJw2XzjtVYqCsaHqt] findings=[]
- **429751000-1.json** (slot=429751000): programIds=[ComputeBudget111111111111111111111111111111, fastC7gqs2WUXgcyNna2BZAe9mte4zcTGprv3mv18N3] findings=[]
- **429751000-10.json** (slot=429751000): programIds=[ComputeBudget111111111111111111111111111111, E2uCGJ4TtYyKPGaK57UMfbs9sgaumwDEZF1aAY6fF3mS] findings=[]
- **429751000-11.json** (slot=429751000): programIds=[EtrnLzgbS7nMMy5fbD42kXiUzGg8XQzJ972Xtk1cjWih, ComputeBudget111111111111111111111111111111] findings=[]
- **429751000-12.json** (slot=429751000): programIds=[ComputeBudget111111111111111111111111111111, TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA] findings=[spl-close-account, spl-close-account, spl-close-account, spl-close-account, spl-close-account, spl-close-account, spl-close-account]
- **429751000-14.json** (slot=429751000): programIds=[ComputeBudget111111111111111111111111111111, TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb] findings=[token2022-close-account]
- **429751000-17.json** (slot=429751000): programIds=[ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL] findings=[ata-create-external-wallet]
- **429751000-18.json** (slot=429751000): programIds=[ComputeBudget111111111111111111111111111111, DZNTS5ujuiyx1mazqCPdYPzEyE2VrTPPb6QbqBUftJbY] findings=[]
- **429751000-19.json** (slot=429751000): programIds=[ComputeBudget111111111111111111111111111111, QuaNtZsgYRe5Z9Bk4LZ4cTD9tbkVoyCNf1R2BN9bBDv] findings=[]
- **429751000-2.json** (slot=429751000): programIds=[BiSoNHVpsVZW2F7rx2eQ59yQwKxzU5NvBcmKshCSUypi, ComputeBudget111111111111111111111111111111] findings=[]
- **429751000-20.json** (slot=429751000): programIds=[ComputeBudget111111111111111111111111111111, ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL, 11111111111111111111111111111111, TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA, cpamdpZCGKUy5JxQXB4dcpGPiikHawvSWAd6mEn1sGG] findings=[spl-unrecognized-instruction, spl-close-account]
- **429751000-22.json** (slot=429751000): programIds=[ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL, TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb, 11111111111111111111111111111111] findings=[ata-create-external-wallet]
- **429751000-25.json** (slot=429751000): programIds=[552HLD8APrtVRHkRvgkKiZw48gsLdiTXC3SS5kDLd2ka] findings=[]
- **429751000-26.json** (slot=429751000): programIds=[ComputeBudget111111111111111111111111111111, DZNTS5ujuiyx1mazqCPdYPzEyE2VrTPPb6QbqBUftJbY] findings=[]
- **429751000-27.json** (slot=429751000): programIds=[ComputeBudget111111111111111111111111111111, QuaNtZsgYRe5Z9Bk4LZ4cTD9tbkVoyCNf1R2BN9bBDv] findings=[]
- **429751000-3.json** (slot=429751000): programIds=[ComputeBudget111111111111111111111111111111, 11111111111111111111111111111111, TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA] findings=[spl-unrecognized-instruction, system-large-transfer, spl-unrecognized-instruction, spl-close-account]
- **429751000-33.json** (slot=429751000): programIds=[tbd3QdqF7Es36ifxUsW4uhf5fVkba94oKaGYXLZckT6] findings=[]
- **429751000-34.json** (slot=429751000): programIds=[ComputeBudget111111111111111111111111111111, DZNTS5ujuiyx1mazqCPdYPzEyE2VrTPPb6QbqBUftJbY] findings=[]
- **429751000-36.json** (slot=429751000): programIds=[ComputeBudget111111111111111111111111111111, 11111111111111111111111111111111, TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA] findings=[spl-unrecognized-instruction, system-large-transfer, spl-unrecognized-instruction, spl-close-account]
- **429751000-41.json** (slot=429751000): programIds=[EtrnLzgbS7nMMy5fbD42kXiUzGg8XQzJ972Xtk1cjWih] findings=[]
- **429751000-42.json** (slot=429751000): programIds=[9H6tua7jkLhdm3w8BvgpTn5LZNU7g4ZynDmCiNN3q6Rp, ComputeBudget111111111111111111111111111111] findings=[]
- **429751000-44.json** (slot=429751000): programIds=[ComputeBudget111111111111111111111111111111, ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL, cpamdpZCGKUy5JxQXB4dcpGPiikHawvSWAd6mEn1sGG, TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA] findings=[spl-close-account]
- **429751000-46.json** (slot=429751000): programIds=[TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb] findings=[token2022-permanent-delegate]
- **429751000-49.json** (slot=429751000): programIds=[11111111111111111111111111111111] findings=[system-large-transfer]
- **429751000-5.json** (slot=429751000): programIds=[ComputeBudget111111111111111111111111111111, 11111111111111111111111111111111, TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb] findings=[spl-unrecognized-instruction]
- **429751000-6.json** (slot=429751000): programIds=[ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL, 11111111111111111111111111111111, TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA, JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4, ComputeBudget111111111111111111111111111111] findings=[system-large-transfer, spl-unrecognized-instruction, spl-close-account, spl-close-account, system-large-transfer]
- **429752000-0.json** (slot=429752000): programIds=[T1pyyaTNZsKv2WcRAB8oVnk93mLJw2XzjtVYqCsaHqt] findings=[]
- **429752000-10.json** (slot=429752000): programIds=[BiSoNHVpsVZW2F7rx2eQ59yQwKxzU5NvBcmKshCSUypi, ComputeBudget111111111111111111111111111111] findings=[]
- **429752000-11.json** (slot=429752000): programIds=[ComputeBudget111111111111111111111111111111, fastC7gqs2WUXgcyNna2BZAe9mte4zcTGprv3mv18N3] findings=[]
- **429752000-12.json** (slot=429752000): programIds=[ComputeBudget111111111111111111111111111111, ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL, 11111111111111111111111111111111, TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA, cpamdpZCGKUy5JxQXB4dcpGPiikHawvSWAd6mEn1sGG] findings=[spl-unrecognized-instruction, spl-close-account]
- **429752000-13.json** (slot=429752000): programIds=[ComputeBudget111111111111111111111111111111, TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb, 11111111111111111111111111111111] findings=[token2022-close-account]
- **429752000-16.json** (slot=429752000): programIds=[HA1hgvskN1goEsb33rNHFBcDXBaYyLyyqfGwGMgTUwNo] findings=[]
- **429752000-18.json** (slot=429752000): programIds=[ComputeBudget111111111111111111111111111111, QuaNtZsgYRe5Z9Bk4LZ4cTD9tbkVoyCNf1R2BN9bBDv] findings=[]
- **429752000-19.json** (slot=429752000): programIds=[ComputeBudget111111111111111111111111111111, DZNTS5ujuiyx1mazqCPdYPzEyE2VrTPPb6QbqBUftJbY] findings=[]
- **429752000-2.json** (slot=429752000): programIds=[BiSoNHVpsVZW2F7rx2eQ59yQwKxzU5NvBcmKshCSUypi, ComputeBudget111111111111111111111111111111] findings=[]
- **429752000-20.json** (slot=429752000): programIds=[ComputeBudget111111111111111111111111111111, ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL, 11111111111111111111111111111111, TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA, cpamdpZCGKUy5JxQXB4dcpGPiikHawvSWAd6mEn1sGG] findings=[spl-unrecognized-instruction, spl-close-account]
- **429752000-21.json** (slot=429752000): programIds=[ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL, TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb, ComputeBudget111111111111111111111111111111] findings=[token2022-close-account]
- **429752000-24.json** (slot=429752000): programIds=[B8AwYzFmc3ZB5EWWVtJcJhJtEmKL78W5i3kZrL1uMCmP] findings=[]
- **429752000-26.json** (slot=429752000): programIds=[ComputeBudget111111111111111111111111111111, idemJL67fKhpev5vKcxHrosuVyTat6wVC9sFfoPVg3Y, FD1amxhTsDpwzoVX41dxp2ygAESURV2zdUACzxM1Dfw9] findings=[]
- **429752000-27.json** (slot=429752000): programIds=[9H6tua7jkLhdm3w8BvgpTn5LZNU7g4ZynDmCiNN3q6Rp, ComputeBudget111111111111111111111111111111] findings=[]
- **429752000-28.json** (slot=429752000): programIds=[ComputeBudget111111111111111111111111111111, zincUFpnqYwdYMc1KfH6rKcBvbcdVtHKckKhvrHLDsV, TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA] findings=[spl-unrecognized-instruction]
- **429752000-29.json** (slot=429752000): programIds=[11111111111111111111111111111111, TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb] findings=[durable-nonce-advance, token2022-close-account, token2022-close-account]
- **429752000-3.json** (slot=429752000): programIds=[ComputeBudget111111111111111111111111111111, E2uCGJ4TtYyKPGaK57UMfbs9sgaumwDEZF1aAY6fF3mS] findings=[]
- **429752000-32.json** (slot=429752000): programIds=[4FEFPeMH68BbkrrZW2ak9wWXUS7JCkvXqBkGf5Bg6wmh] findings=[]
- **429752000-34.json** (slot=429752000): programIds=[ComputeBudget111111111111111111111111111111, ALPHAQmeA7bjrVuccPsYPiCvsi428SNwte66Srvs4pHA] findings=[]
- **429752000-35.json** (slot=429752000): programIds=[ComputeBudget111111111111111111111111111111, TessVdML9pBGgG9yGks7o4HewRaXVAMuoVj4x83GLQH] findings=[]
- **429752000-36.json** (slot=429752000): programIds=[ComputeBudget111111111111111111111111111111, ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL, cpamdpZCGKUy5JxQXB4dcpGPiikHawvSWAd6mEn1sGG, TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA] findings=[spl-close-account]
- **429752000-40.json** (slot=429752000): programIds=[B8AwYzFmc3ZB5EWWVtJcJhJtEmKL78W5i3kZrL1uMCmP] findings=[]
- **429752000-42.json** (slot=429752000): programIds=[ComputeBudget111111111111111111111111111111, QuaNtZsgYRe5Z9Bk4LZ4cTD9tbkVoyCNf1R2BN9bBDv] findings=[]
- **429752000-43.json** (slot=429752000): programIds=[ComputeBudget111111111111111111111111111111, TessVdML9pBGgG9yGks7o4HewRaXVAMuoVj4x83GLQH] findings=[]
- **429752000-44.json** (slot=429752000): programIds=[ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL, pAMMBay6oceH9fJKBRHGP5D4bD4sWpmSwMn52FMfXEA, TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA] findings=[spl-close-account]
- **429752000-45.json** (slot=429752000): programIds=[ComputeBudget111111111111111111111111111111, ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL, pAMMBay6oceH9fJKBRHGP5D4bD4sWpmSwMn52FMfXEA, TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA, TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb] findings=[spl-close-account, token2022-close-account]
- **429752000-47.json** (slot=429752000): programIds=[HA1hgvskN1goEsb33rNHFBcDXBaYyLyyqfGwGMgTUwNo] findings=[]
- **429752000-49.json** (slot=429752000): programIds=[BiSoNHVpsVZW2F7rx2eQ59yQwKxzU5NvBcmKshCSUypi, ComputeBudget111111111111111111111111111111] findings=[]
- **429752000-8.json** (slot=429752000): programIds=[11111111111111111111111111111111] findings=[durable-nonce-advance]

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
| System-Assign | REJECT | REJECT | YES | System AssignWithSeed changes program owner with seed derivation |
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
| Benign corpus size | 500 transactions |
| Benign SIGN precision | 100.0% (92/92) |
| Benign SIGN rate | 18.4% |
| Benign false-REJECT | 0 |
| Benign HOLD rate | 81.6% |
| HOLDs with unresolved ALT | 1 |
| HOLDs without ALT | 243 |
| Malicious corpus size | 37 fixtures |
| Curated malicious-set recall | 100.0% (37/37) |
| ALT sub-test wins | 1/5 |
| SetAuthority-AccountOwner recall | 100.0% (7/7) |
| System-Assign recall | 100.0% (5/5) |
| SPL-Approve recall | 100.0% (5/5) |
