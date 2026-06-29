# Real documented attacks — replayed offline

These are the **raw on-chain bytes of publicly-documented exploits**, decoded by sign-safe's deterministic offline core. Each row's transaction is captured once (`skill/corpus/capture-malicious.ts`) and frozen under `skill/corpus/malicious/`; the replay test (`skill/test/real-attacks.test.ts`) asserts each → **never SIGN**.

> **Honest scope:** this is "documented incidents whose real transactions sign-safe holds or rejects," **not** a claim that sign-safe catches every attack. A **HOLD** means sign-safe stops the signer and forces human review at signing time — it is **not** on-chain prevention. These are distinct from the curated *synthetic* attack pack (37 fixtures); this table is real on-chain traffic.

| Incident | Date | Loss | Transaction | Source | sign-safe verdict | What it flagged |
|---|---|---|---|---|:--:|---|
| Drift Protocol durable-nonce blind-signing | 2026-04-01 | ~$285M | [`2HvMSgDE…pc2C4H`](https://solscan.io/tx/2HvMSgDEfKhNryYZKhjowrBY55rUx5MWtcWkG9hqxZCFBaTiahPwfynP1dxBSRk9s5UTVc8LFeS4Btvkm9pc2C4H) | [QuillAudits](https://www.quillaudits.com/blog/hack-analysis/drift-protocol-multisig-exploit) · [Chainalysis](https://www.chainalysis.com/blog/lessons-from-the-drift-hack/) | **HOLD** | `durable-nonce-advance` (the Drift enabling vector) + 3× Squads v4 execution (unrecognized inner → review) |
| Drift Protocol durable-nonce blind-signing | 2026-04-01 | ~$285M | [`4BKBmAJn…B9RsN1`](https://solscan.io/tx/4BKBmAJn6TdsENij7CsVbyMVLJU1tX27nfrMM1zgKv1bs2KJy6Am2NqdA3nJm4g9C6eC64UAf5sNs974ygB9RsN1) | [QuillAudits](https://www.quillaudits.com/blog/hack-analysis/drift-protocol-multisig-exploit) | **HOLD** | `durable-nonce-advance` + `squads-execute-unverified` (Squads execute can never be SIGN) |

**Why these are held, not blind-signed:** both transactions are durable-nonce-backed (non-expiring; can be pre-signed and replayed later — the exact mechanism of the Drift incident) and execute via Squads v4 with inner instructions sign-safe cannot bound offline. sign-safe surfaces both as HOLD-class, so a human or agent is forced to review the hidden effects before the signature happens. With the Squads/Drift inner instructions decoded (clear-signing registry, workstream C), these can escalate from HOLD to REJECT.

## Reproduce

```bash
# Capture (one-time; needs an archival RPC with getTransaction base64):
SIGN_SAFE_RPC="https://mainnet.helius-rpc.com/?api-key=YOUR_KEY" \
  node --import tsx skill/corpus/capture-malicious.ts

# Replay offline (no network, no key):
npx vitest run skill/test/real-attacks.test.ts
```

## Documented incidents without retrievable bytes

(None yet.) Any documented incident whose raw on-chain bytes cannot be retrieved would be listed here and, if useful, added to the **synthetic** pack as a clearly-labeled "modeled-on" fixture — never relabeled as real.
