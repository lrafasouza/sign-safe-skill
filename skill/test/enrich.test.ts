/**
 * enrich.test.ts -- Tests for enrichAlt and confirmMintExtensions in enrich.ts.
 *
 * All tests use FROZEN injected fetchers (no real network, no RPC).
 * This file tests the host-layer thin wrappers that delegate to pure decoders.
 *
 * E1  enrichAlt with a valid ALT account → resolves writable/readonly indexes
 * E2  enrichAlt with null fetcher response → throws (account not found)
 * E3  enrichAlt with partial indexes (out-of-range) → resolves available, drops OOR
 * E4  confirmMintExtensions with a Token-2022 mint + PermanentDelegate → correct result
 * E5  confirmMintExtensions with a plain 82-byte SPL mint → no extensions
 * E6  confirmMintExtensions with null fetcher → throws (account not found)
 * E7  confirmMintExtensions with TransferHook extension → detected
 */

import { describe, it, expect } from "vitest";
import { enrichAlt, confirmMintExtensions } from "../src/enrich.ts";
import type {
  AccountFetcher,
  AltResolution,
  MintExtensionInfo,
} from "../src/enrich.ts";
import type { AddressTableLookup } from "../src/types.ts";

// ---------------------------------------------------------------------------
// ALT account byte builder (matches the layout in alt.ts)
// ---------------------------------------------------------------------------

/**
 * Build a synthetic ALT account buffer containing the given addresses.
 *
 * ALT layout (from alt.ts):
 *   [0..4)   discriminator u32-LE = 1 (LookupTable)
 *   [4..12)  deactivation_slot u64-LE = u64::MAX
 *   [12..20) last_extended_slot u64-LE = 0
 *   [20]     last_extended_slot_start_index u8 = 0
 *   [21]     authority option tag = 0x00 (None)
 *   [22..54) authority bytes (zero-padded, ignored when tag=0x00)
 *   [54..56) padding u16 = 0
 *   [56..)   32-byte packed addresses
 */
function buildAltBytes(addresses: Uint8Array[]): Uint8Array {
  const out: number[] = [];
  // discriminator = 1 (LookupTable)
  out.push(1, 0, 0, 0);
  // deactivation_slot = u64::MAX (0xFFFF...FF)
  out.push(0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff);
  // last_extended_slot = 0
  out.push(0, 0, 0, 0, 0, 0, 0, 0);
  // last_extended_slot_start_index = 0
  out.push(0);
  // authority option = None (0x00)
  out.push(0x00);
  // authority bytes (32 zeros, ignored)
  out.push(...new Array(32).fill(0x00));
  // padding u16
  out.push(0, 0);
  // addresses
  for (const addr of addresses) {
    out.push(...Array.from(addr));
  }
  return Uint8Array.from(out);
}

/**
 * Build a Token-2022 mint account with a PermanentDelegate extension.
 *
 * Layout (from tlv.ts):
 *   [0..82)  base SPL Mint (82 bytes, zeroed)
 *   [82..165) padding to reach 165 bytes
 *   [165]    account_type byte = 0x01 (Mint)
 *   [166..)  TLV: PermanentDelegate (type=12 u16-LE, length=32 u16-LE, 32-byte delegate)
 */
function buildMintWithPermanentDelegate(delegateFill: number): Uint8Array {
  const out = new Array(166).fill(0);
  out[165] = 0x01; // account_type = Mint
  // TLV: type=12, length=32, value=delegateFill repeated 32 times
  out.push(12, 0); // u16-LE type
  out.push(32, 0); // u16-LE length
  out.push(...new Array(32).fill(delegateFill));
  return Uint8Array.from(out);
}

/**
 * Build a Token-2022 mint account with a TransferHook extension.
 *
 * TLV entry: type=14 (TransferHook), length=64,
 *   value=[authority(32)][programId(32)]
 */
function buildMintWithTransferHook(programIdFill: number): Uint8Array {
  const out = new Array(166).fill(0);
  out[165] = 0x01; // account_type = Mint
  // TLV: type=14, length=64
  out.push(14, 0); // u16-LE type
  out.push(64, 0); // u16-LE length
  // authority (32 bytes zeroed = OptionalNonZeroPubkey None)
  out.push(...new Array(32).fill(0x00));
  // programId (32 bytes filled with programIdFill)
  out.push(...new Array(32).fill(programIdFill));
  return Uint8Array.from(out);
}

// ---------------------------------------------------------------------------
// base58 encode helper (inline, no dep)
// ---------------------------------------------------------------------------

function base58EncodeTest(bytes: Uint8Array): string {
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

// ---------------------------------------------------------------------------
// Test keys
// ---------------------------------------------------------------------------

const TABLE_ADDR = "EnrichTestTable1111111111111111111111111111";
const ADDR_0 = base58EncodeTest(new Uint8Array(32).fill(0x10));
const ADDR_1 = base58EncodeTest(new Uint8Array(32).fill(0x20));
const ADDR_2 = base58EncodeTest(new Uint8Array(32).fill(0x30));

// ---------------------------------------------------------------------------
// E1: enrichAlt with valid ALT account
// ---------------------------------------------------------------------------

describe("E1: enrichAlt resolves writable and readonly indexes", () => {
  it("E1.1 writable[0] and readonly[1] are resolved to the correct addresses", async () => {
    const altBytes = buildAltBytes([
      new Uint8Array(32).fill(0x10), // slot 0 → ADDR_0
      new Uint8Array(32).fill(0x20), // slot 1 → ADDR_1
      new Uint8Array(32).fill(0x30), // slot 2 → ADDR_2
    ]);

    const lookup: AddressTableLookup = {
      accountKey: TABLE_ADDR,
      writableIndexes: [0, 2],
      readonlyIndexes: [1],
    };

    const frozenFetcher: AccountFetcher = async (pubkey) => {
      if (pubkey === TABLE_ADDR) return { data: altBytes };
      return null;
    };

    const result: AltResolution = await enrichAlt(lookup, frozenFetcher);

    expect(result.table).toBe(TABLE_ADDR);
    expect(result.writable).toHaveLength(2);
    expect(result.writable[0]).toBe(ADDR_0);
    expect(result.writable[1]).toBe(ADDR_2);
    expect(result.readonly).toHaveLength(1);
    expect(result.readonly[0]).toBe(ADDR_1);
  });

  it("E1.2 empty writable and readonly indexes → empty arrays", async () => {
    const altBytes = buildAltBytes([new Uint8Array(32).fill(0x10)]);
    const lookup: AddressTableLookup = {
      accountKey: TABLE_ADDR,
      writableIndexes: [],
      readonlyIndexes: [],
    };
    const frozenFetcher: AccountFetcher = async (pubkey) => {
      if (pubkey === TABLE_ADDR) return { data: altBytes };
      return null;
    };
    const result = await enrichAlt(lookup, frozenFetcher);
    expect(result.writable).toHaveLength(0);
    expect(result.readonly).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// E2: enrichAlt throws when account not found
// ---------------------------------------------------------------------------

describe("E2: enrichAlt throws on null fetcher response", () => {
  it("E2.1 null account → throws with account-not-found message", async () => {
    const lookup: AddressTableLookup = {
      accountKey: TABLE_ADDR,
      writableIndexes: [0],
      readonlyIndexes: [],
    };
    const nullFetcher: AccountFetcher = async () => null;
    await expect(enrichAlt(lookup, nullFetcher)).rejects.toThrow(TABLE_ADDR);
  });
});

// ---------------------------------------------------------------------------
// E3: enrichAlt with partial/out-of-range indexes
// ---------------------------------------------------------------------------

describe("E3: enrichAlt with out-of-range indexes drops those slots", () => {
  it("E3.1 index 0 is in-range, index 5 is OOR → writable has 1 result", async () => {
    const altBytes = buildAltBytes([
      new Uint8Array(32).fill(0x10), // only slot 0
    ]);
    const lookup: AddressTableLookup = {
      accountKey: TABLE_ADDR,
      writableIndexes: [0, 5], // slot 5 is OOR
      readonlyIndexes: [],
    };
    const frozenFetcher: AccountFetcher = async (pubkey) => {
      if (pubkey === TABLE_ADDR) return { data: altBytes };
      return null;
    };
    const result = await enrichAlt(lookup, frozenFetcher);
    // OOR indexes produce null entries which are filtered out
    expect(result.writable).toHaveLength(1);
    expect(result.writable[0]).toBe(ADDR_0);
  });
});

// ---------------------------------------------------------------------------
// E4: confirmMintExtensions with PermanentDelegate
// ---------------------------------------------------------------------------

describe("E4: confirmMintExtensions with PermanentDelegate extension", () => {
  it("E4.1 mint with permanent-delegate extension → hasPermanentDelegate=true, correct delegate", async () => {
    const mintBytes = buildMintWithPermanentDelegate(0xde);
    const expectedDelegate = base58EncodeTest(new Uint8Array(32).fill(0xde));
    const mintAddr = "MintWithDelegateTest111111111111111111111111";

    const frozenFetcher: AccountFetcher = async (pubkey) => {
      if (pubkey === mintAddr) return { data: mintBytes };
      return null;
    };

    const result: MintExtensionInfo = await confirmMintExtensions(
      mintAddr,
      frozenFetcher,
    );

    expect(result.mint).toBe(mintAddr);
    expect(result.isToken2022).toBe(true);
    expect(result.hasPermanentDelegate).toBe(true);
    expect(result.permanentDelegate).toBe(expectedDelegate);
    expect(result.hasTransferHook).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// E5: confirmMintExtensions with plain 82-byte SPL mint
// ---------------------------------------------------------------------------

describe("E5: confirmMintExtensions with plain SPL mint → no extensions", () => {
  it("E5.1 82-byte plain mint → no delegate, no hook, isToken2022=false", async () => {
    // A plain 82-byte SPL mint (no extensions)
    const mintBytes = new Uint8Array(82).fill(0);
    const mintAddr = "PlainSPLMintTest11111111111111111111111111111";

    const frozenFetcher: AccountFetcher = async (pubkey) => {
      if (pubkey === mintAddr) return { data: mintBytes };
      return null;
    };

    const result = await confirmMintExtensions(mintAddr, frozenFetcher);

    expect(result.mint).toBe(mintAddr);
    expect(result.isToken2022).toBe(false);
    expect(result.hasPermanentDelegate).toBe(false);
    expect(result.hasTransferHook).toBe(false);
    expect(result.permanentDelegate).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// E6: confirmMintExtensions throws when account not found
// ---------------------------------------------------------------------------

describe("E6: confirmMintExtensions throws on null fetcher response", () => {
  it("E6.1 null account → throws with mint address in message", async () => {
    const mintAddr = "MissingMintAddr111111111111111111111111111111";
    const nullFetcher: AccountFetcher = async () => null;
    await expect(confirmMintExtensions(mintAddr, nullFetcher)).rejects.toThrow(
      mintAddr,
    );
  });
});

// ---------------------------------------------------------------------------
// E7: confirmMintExtensions with TransferHook
// ---------------------------------------------------------------------------

describe("E7: confirmMintExtensions with TransferHook extension", () => {
  it("E7.1 mint with transfer-hook extension → hasTransferHook=true", async () => {
    const mintBytes = buildMintWithTransferHook(0xf0);
    const mintAddr = "MintWithTransferHook11111111111111111111111111";

    const frozenFetcher: AccountFetcher = async (pubkey) => {
      if (pubkey === mintAddr) return { data: mintBytes };
      return null;
    };

    const result = await confirmMintExtensions(mintAddr, frozenFetcher);

    expect(result.mint).toBe(mintAddr);
    expect(result.isToken2022).toBe(true);
    expect(result.hasTransferHook).toBe(true);
    expect(result.hasPermanentDelegate).toBe(false);
  });
});
