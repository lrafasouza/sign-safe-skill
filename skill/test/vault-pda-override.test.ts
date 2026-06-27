/**
 * vault-pda-override.test.ts -- Tests for the --vault-pda override logic in cli.ts.
 *
 * The CLI's --vault-pda feature redirects the auto-extracted vtAddr from a
 * Squads vaultTransactionExecute message to an operator-supplied PDA whose bytes
 * may differ from (or supplement) what's auto-extracted.
 *
 * We test the exported `buildVaultPdaFetcher` helper which was refactored out of
 * main() for testability. All tests use FROZEN injected fetchers (no real network).
 *
 * Test groups:
 *   VP1  Basic redirect: a fetcher built with a matching vtAddr+PDA returns the
 *        override bytes when queried for vtAddr, and delegates all other queries.
 *   VP2  No-op when vtAddr is null (no Squads ix in message).
 *   VP3  No-op when vaultPdaAccount is null (PDA account not found).
 *   VP4  End-to-end: a Squads vaultTransactionExecute message + --vault-pda pointing
 *        at a PDA whose inner bytes contain an authority change → REJECT/HOLD
 *        (not SIGN), confirming the override wires through to the verdict.
 *   VP5  End-to-end: without a Squads ix, --vault-pda override is a no-op
 *        (does not affect verdict of a non-Squads message).
 */

import { describe, it, expect } from "vitest";
import { buildVaultPdaFetcher } from "../src/cli.ts";
import { reviewWithEnrichment } from "../src/review-online.ts";
import { toB64 } from "./helpers.ts";
import type { AccountFetcher } from "../src/enrich.ts";
import type { VerdictContext } from "../src/types.ts";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const SQUADS_V4 = "SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf";

/** sha256("global:vault_transaction_execute")[0..8] */
const VAULT_TX_EXECUTE_DISC = [0xc2, 0x08, 0xa1, 0x57, 0x99, 0xa4, 0x19, 0xab];
/** VaultTransaction account discriminator */
const VAULT_TX_ACCOUNT_DISC = [0xa8, 0xfa, 0xa2, 0x64, 0x51, 0x0e, 0xa2, 0xcf];
/** update_admin discriminator */
const UPDATE_ADMIN_DISC = [0xa1, 0xb0, 0x28, 0xd5, 0x3c, 0xb8, 0xb3, 0xe4];

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function u32le(n: number): number[] {
  return [n & 0xff, (n >>> 8) & 0xff, (n >>> 16) & 0xff, (n >>> 24) & 0xff];
}

function base58ToBytes32(b58: string): Uint8Array {
  const A = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  const m: Record<string, number> = {};
  for (let i = 0; i < A.length; i++) m[A[i]!] = i;
  let bytes: number[] = [];
  for (const ch of b58) {
    let c = m[ch]!;
    for (let j = 0; j < bytes.length; j++) {
      c += bytes[j]! * 58;
      bytes[j] = c & 0xff;
      c >>= 8;
    }
    while (c > 0) {
      bytes.push(c & 0xff);
      c >>= 8;
    }
  }
  let lz = 0;
  for (const ch of b58) {
    if (ch === "1") lz++;
    else break;
  }
  const out = new Uint8Array(32);
  const body = bytes.reverse();
  const off = 32 - body.length - lz;
  for (let i = 0; i < body.length; i++) out[off + i] = body[i]!;
  return out;
}

/**
 * Build a VaultTransaction with a single inner instruction.
 * instrProgramIdIndex < numKeys → programId is resolved from accountKeys.
 */
function buildVaultTxBytes(opts: {
  instrProgramIdIndex: number;
  instrData: number[];
  numKeys?: number;
}): Uint8Array {
  const numKeys = opts.numKeys ?? 3;
  const bytes: number[] = [];
  bytes.push(...VAULT_TX_ACCOUNT_DISC);
  bytes.push(...new Array(32).fill(0x01)); // multisig
  bytes.push(...new Array(32).fill(0x02)); // creator
  bytes.push(1, 0, 0, 0, 0, 0, 0, 0); // index u64-LE
  bytes.push(255, 0, 254); // bump, vault_index, vault_bump
  bytes.push(0, 0, 0, 0); // ephemeral_signer_bumps Vec<u8> len=0
  bytes.push(1, 1, 1); // num_signers, num_writable_signers, num_writable_non_signers
  bytes.push(...u32le(numKeys));
  for (let i = 0; i < numKeys; i++) bytes.push(...new Array(32).fill(0x10 + i));
  bytes.push(...u32le(1)); // 1 instruction
  bytes.push(opts.instrProgramIdIndex);
  bytes.push(...u32le(0)); // accountIndexes: empty
  bytes.push(...u32le(opts.instrData.length));
  bytes.push(...opts.instrData);
  bytes.push(...u32le(0)); // address_table_lookups: empty
  return new Uint8Array(bytes);
}

/**
 * Build a Squads vaultTransactionExecute top-level message.
 * Static keys: [0]=feePayer(0x01), [1]=SquadsV4, [2]=VaultTxPDA(0xaa)
 * Ix: prog=1 (Squads), accounts=[0, 0, 2], data=VAULT_TX_EXECUTE_DISC
 *
 * Returns { rawBytes, pdaAddr } where pdaAddr is the base58 of the PDA key.
 */
function buildSquadsMessage(): { rawBytes: Uint8Array; pdaAddr: string } {
  const squadsKeyBytes = Array.from(base58ToBytes32(SQUADS_V4));
  const out: number[] = [];
  out.push(1, 0, 1); // header: 1 signer, 0 ro-signed, 1 ro-unsigned
  out.push(3); // 3 static keys
  out.push(...new Array(32).fill(0x01)); // [0] feePayer
  out.push(...squadsKeyBytes); // [1] SquadsV4
  out.push(...new Array(32).fill(0xaa)); // [2] VaultTxPDA
  out.push(...new Array(32).fill(0xfa)); // blockhash
  out.push(1); // 1 instruction
  out.push(1); // prog index = 1 (SquadsV4)
  out.push(3, 0, 0, 2); // 3 accounts: [0, 0, 2]
  out.push(8, ...VAULT_TX_EXECUTE_DISC);
  const rawBytes = Uint8Array.from(out);

  // The PDA is staticAccountKeys[2] (the 0xAA-filled key)
  // Compute the base58 of this 32-byte key
  const { decodeInput } = await_import_sync_workaround();
  // We use the inline approach — the PDA key is all-0xAA, 32 bytes.
  // base58 of that key can be computed inline.
  const pdaBytes = new Uint8Array(32).fill(0xaa);
  const pdaAddr = base58EncodeLocal(pdaBytes);

  return { rawBytes, pdaAddr };
}

// Inline base58 encoder (avoids importing decode.ts in tests)
function base58EncodeLocal(bytes: Uint8Array): string {
  const A = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  if (bytes.length === 0) return "";
  let zeros = 0;
  while (zeros < bytes.length && bytes[zeros] === 0) zeros++;
  const digits: number[] = [];
  for (let i = zeros; i < bytes.length; i++) {
    let carry = bytes[i] as number;
    for (let j = 0; j < digits.length; j++) {
      carry += (digits[j] as number) << 8;
      digits[j] = carry % 58;
      carry = (carry / 58) | 0;
    }
    while (carry > 0) {
      digits.push(carry % 58);
      carry = (carry / 58) | 0;
    }
  }
  let out = "1".repeat(zeros);
  for (let i = digits.length - 1; i >= 0; i--) out += A[digits[i] as number];
  return out;
}

// Workaround: we need a sync way to get pdaAddr. Use a helper.
function await_import_sync_workaround(): { decodeInput: unknown } {
  // Not actually used — we inline the computation above.
  return { decodeInput: null };
}

// Pre-compute the PDA address for the 0xAA-filled key
const PDA_ADDR = base58EncodeLocal(new Uint8Array(32).fill(0xaa));
// Pre-compute the auto-extracted vtAddr (same as PDA_ADDR in our test message,
// since accountIndexes[2]=2 and staticAccountKeys[2] is the 0xAA key)
const VT_ADDR = PDA_ADDR; // they coincide in this test

// A "different" PDA that the operator supplies via --vault-pda
const OPERATOR_PDA_ADDR = base58EncodeLocal(new Uint8Array(32).fill(0xbb));

// ---------------------------------------------------------------------------
// VP1: buildVaultPdaFetcher basic redirect
// ---------------------------------------------------------------------------

describe("VP1: buildVaultPdaFetcher redirects vtAddr queries to override bytes", () => {
  it("VP1.1 querying vtAddr returns the override account data", async () => {
    const overrideData = new Uint8Array([1, 2, 3, 4, 5]);
    const overrideAccount = { data: overrideData };
    const baseFetcher: AccountFetcher = async () => null; // never called for vtAddr

    const wrapped = buildVaultPdaFetcher(VT_ADDR, overrideAccount, baseFetcher);
    const result = await wrapped(VT_ADDR);

    expect(result).not.toBeNull();
    expect(result!.data).toEqual(overrideData);
  });

  it("VP1.2 querying a different pubkey delegates to baseFetcher", async () => {
    const baseData = new Uint8Array([9, 8, 7]);
    const overrideData = new Uint8Array([1, 2, 3]);
    const overrideAccount = { data: overrideData };

    const OTHER_ADDR = base58EncodeLocal(new Uint8Array(32).fill(0xcc));
    const baseFetcher: AccountFetcher = async (pubkey) => {
      if (pubkey === OTHER_ADDR) return { data: baseData };
      return null;
    };

    const wrapped = buildVaultPdaFetcher(VT_ADDR, overrideAccount, baseFetcher);

    // VT_ADDR → override
    const vtResult = await wrapped(VT_ADDR);
    expect(vtResult!.data).toEqual(overrideData);

    // OTHER_ADDR → base fetcher
    const otherResult = await wrapped(OTHER_ADDR);
    expect(otherResult!.data).toEqual(baseData);

    // Unknown addr → null (from base)
    const unknownAddr = base58EncodeLocal(new Uint8Array(32).fill(0xdd));
    const unknownResult = await wrapped(unknownAddr);
    expect(unknownResult).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// VP2: No-op when vtAddr is null
// ---------------------------------------------------------------------------

describe("VP2: buildVaultPdaFetcher is a no-op when vtAddr is null", () => {
  it("VP2.1 null vtAddr → returns baseFetcher unchanged (no redirect)", async () => {
    const overrideData = new Uint8Array([1, 2, 3]);
    const overrideAccount = { data: overrideData };
    let baseCalled = false;
    const baseFetcher: AccountFetcher = async () => {
      baseCalled = true;
      return null;
    };

    const wrapped = buildVaultPdaFetcher(null, overrideAccount, baseFetcher);

    // The wrapped fetcher IS the base fetcher (or equivalent)
    await wrapped(VT_ADDR);
    expect(baseCalled).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// VP3: No-op when vaultPdaAccount is null
// ---------------------------------------------------------------------------

describe("VP3: buildVaultPdaFetcher is a no-op when vaultPdaAccount is null", () => {
  it("VP3.1 null vaultPdaAccount → returns baseFetcher unchanged", async () => {
    let baseCalled = false;
    const baseFetcher: AccountFetcher = async () => {
      baseCalled = true;
      return null;
    };

    const wrapped = buildVaultPdaFetcher(VT_ADDR, null, baseFetcher);

    // Should delegate to baseFetcher, not apply any override
    await wrapped(VT_ADDR);
    expect(baseCalled).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// VP4: End-to-end via reviewWithEnrichment — Squads + vault-pda override with
//      inner authority change → REJECT/HOLD (not SIGN)
// ---------------------------------------------------------------------------

describe("VP4: end-to-end --vault-pda override with inner authority change", () => {
  it("VP4.1 Squads execute + vault-pda override with update_admin inner → not SIGN", async () => {
    // 1. Build the top-level Squads message (auto-vtAddr = PDA_ADDR).
    const squadsKeyBytes = Array.from(base58ToBytes32(SQUADS_V4));
    const rawMsg: number[] = [];
    rawMsg.push(1, 0, 1);
    rawMsg.push(3);
    rawMsg.push(...new Array(32).fill(0x01));
    rawMsg.push(...squadsKeyBytes);
    rawMsg.push(...new Array(32).fill(0xaa)); // PDA_ADDR
    rawMsg.push(...new Array(32).fill(0xfa));
    rawMsg.push(1);
    rawMsg.push(1);
    rawMsg.push(3, 0, 0, 2);
    rawMsg.push(8, ...VAULT_TX_EXECUTE_DISC);
    const rawBytes = Uint8Array.from(rawMsg);
    const b64 = toB64(rawBytes);

    // 2. Build a VaultTransaction with an inner update_admin discriminator.
    const vaultTxBytes = buildVaultTxBytes({
      instrProgramIdIndex: 0,
      instrData: UPDATE_ADMIN_DISC,
      numKeys: 3,
    });

    // 3. Build the wrapped fetcher that redirects PDA_ADDR → vaultTxBytes.
    //    This simulates what CLI does when --vault-pda is provided:
    //    vtAddr = auto-extracted from message = PDA_ADDR
    //    vaultPdaAccount = pre-fetched bytes from operator-supplied address
    const overrideAccount = { data: vaultTxBytes };
    const baseFetcher: AccountFetcher = async () => null;
    const wrappedFetcher = buildVaultPdaFetcher(
      PDA_ADDR,
      overrideAccount,
      baseFetcher,
    );

    // 4. Run reviewWithEnrichment with the wrapped fetcher.
    const ctx: VerdictContext = { lamportThreshold: 1_000_000_000 };
    const verdict = await reviewWithEnrichment(b64, ctx, wrappedFetcher);

    // Must not be SIGN — inner authority change is dangerous.
    expect(verdict.decision).not.toBe("SIGN");
    // Should find the inner update_admin finding.
    const innerFinding = verdict.findings.find(
      (f) => f.id === "anchor-inner-update_admin",
    );
    expect(innerFinding).toBeDefined();
  });

  it("VP4.2 Squads execute + null baseFetcher (no vault-pda override) → HOLD squads-execute-unverified", async () => {
    // Without the override, the fetcher returns null → falls back to HOLD unverified.
    const squadsKeyBytes = Array.from(base58ToBytes32(SQUADS_V4));
    const rawMsg: number[] = [];
    rawMsg.push(1, 0, 1);
    rawMsg.push(3);
    rawMsg.push(...new Array(32).fill(0x01));
    rawMsg.push(...squadsKeyBytes);
    rawMsg.push(...new Array(32).fill(0xaa));
    rawMsg.push(...new Array(32).fill(0xfa));
    rawMsg.push(1);
    rawMsg.push(1);
    rawMsg.push(3, 0, 0, 2);
    rawMsg.push(8, ...VAULT_TX_EXECUTE_DISC);
    const b64 = toB64(Uint8Array.from(rawMsg));

    const nullFetcher: AccountFetcher = async () => null;
    const ctx: VerdictContext = { lamportThreshold: 1_000_000_000 };
    const verdict = await reviewWithEnrichment(b64, ctx, nullFetcher);

    expect(verdict.decision).toBe("HOLD");
    expect(
      verdict.findings.some((f) => f.id === "squads-execute-unverified"),
    ).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// VP5: End-to-end — no Squads ix → --vault-pda override is a no-op
// ---------------------------------------------------------------------------

describe("VP5: vault-pda override is a no-op when there is no Squads ix", () => {
  it("VP5.1 plain System Transfer message + vault-pda override → verdict unaffected", async () => {
    // Build a plain system transfer: [0]=feePayer(0x01), [1]=System(0x00), [2]=dest(0x02)
    // The vtAddr extracted from this message is null (no Squads ix).
    const plainMsg: number[] = [];
    plainMsg.push(1, 0, 1); // header
    plainMsg.push(3); // 3 static keys
    plainMsg.push(...new Array(32).fill(0x01)); // [0] feePayer
    plainMsg.push(...new Array(32).fill(0x00)); // [1] SystemProgram (all zeros)
    plainMsg.push(...new Array(32).fill(0x02)); // [2] dest
    plainMsg.push(...new Array(32).fill(0xfa)); // blockhash
    plainMsg.push(1); // 1 instruction
    plainMsg.push(1); // prog = SystemProgram (index 1)
    plainMsg.push(2, 0, 2); // 2 accounts: [0, 2]
    // System Transfer: tag=2 u32-LE, lamports=100 u64-LE
    plainMsg.push(12, 2, 0, 0, 0, 100, 0, 0, 0, 0, 0, 0, 0);
    const b64 = toB64(Uint8Array.from(plainMsg));

    // vtAddr = null (no Squads ix) → buildVaultPdaFetcher is a no-op
    const overrideData = new Uint8Array([0xff, 0xfe]);
    const overrideAccount = { data: overrideData };
    const nullFetcher: AccountFetcher = async () => null;
    const wrappedFetcher = buildVaultPdaFetcher(
      null, // vtAddr = null → no-op
      overrideAccount,
      nullFetcher,
    );

    const ctx: VerdictContext = { lamportThreshold: 1_000_000_000 };
    const verdict = await reviewWithEnrichment(b64, ctx, wrappedFetcher);

    // No Squads findings — it's a plain transfer
    expect(
      verdict.findings.some((f) => f.id === "squads-execute-unverified"),
    ).toBe(false);
    expect(
      verdict.findings.some((f) => f.id === "anchor-inner-update_admin"),
    ).toBe(false);
    // Should be SIGN (benign transfer below threshold)
    expect(verdict.decision).toBe("SIGN");
  });
});
