/**
 * alt.test.ts -- T_ALT: pure offline decoder for Address Lookup Table accounts.
 *
 * Tests the canonical bincode layout verified against solana-program/address-lookup-table.
 * All tests are OFFLINE: no network, synthetic byte buffers only.
 */

import { describe, it, expect } from "vitest";
import {
  decodeAddressLookupTable,
  resolveAltIndexes,
  AltDecodeError,
} from "../src/alt.ts";
import { base58Encode, base58DecodeFixed } from "../src/decode.ts";

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

/** Write u32 LE at offset into buf. */
function writeU32LE(buf: Uint8Array, offset: number, value: number): void {
  buf[offset] = value & 0xff;
  buf[offset + 1] = (value >>> 8) & 0xff;
  buf[offset + 2] = (value >>> 16) & 0xff;
  buf[offset + 3] = (value >>> 24) & 0xff;
}

/** Write u64 LE at offset (BigInt). */
function writeU64LE(buf: Uint8Array, offset: number, value: bigint): void {
  let v = value;
  for (let i = 0; i < 8; i++) {
    buf[offset + i] = Number(v & 0xffn);
    v >>= 8n;
  }
}

/**
 * Build a synthetic ALT account buffer.
 *   - discriminator = 1 (LookupTable)
 *   - deactivationSlot
 *   - lastExtendedSlot
 *   - lastExtendedSlotStartIndex
 *   - authority: null | 32-byte pubkey
 *   - padding (2 bytes) = 0x0000
 *   - addresses: array of 32-byte pubkeys (packed, no length prefix)
 *
 * Layout (56-byte metadata header):
 *   [0..4)   discriminator u32 LE = 1
 *   [4..12)  deactivationSlot u64 LE
 *   [12..20) lastExtendedSlot u64 LE
 *   [20]     lastExtendedSlotStartIndex u8
 *   [21]     authority option tag: 0x00 or 0x01
 *   [22..54) authority pubkey (only if tag=0x01, else bytes are zero / ignored)
 *   [54..56) padding u16 = 0
 *   [56..)   packed 32*N pubkeys
 */
function buildAltBytes(opts: {
  disc?: number; // default 1
  deactivationSlot?: bigint;
  lastExtendedSlot?: bigint;
  lastExtendedSlotStartIndex?: number;
  authority?: Uint8Array | null; // null = tag 0x00
  addresses?: Uint8Array[];
}): Uint8Array {
  const disc = opts.disc ?? 1;
  const deactivationSlot = opts.deactivationSlot ?? 0xffffffffffffffffn;
  const lastExtendedSlot = opts.lastExtendedSlot ?? 100n;
  const lastExtendedSlotStartIndex = opts.lastExtendedSlotStartIndex ?? 0;
  const authority = opts.authority ?? null;
  const addresses = opts.addresses ?? [];

  // Fixed metadata size = 56 bytes (LOOKUP_TABLE_META_SIZE)
  const totalSize = 56 + addresses.length * 32;
  const buf = new Uint8Array(totalSize);

  writeU32LE(buf, 0, disc);
  writeU64LE(buf, 4, deactivationSlot);
  writeU64LE(buf, 12, lastExtendedSlot);
  buf[20] = lastExtendedSlotStartIndex & 0xff;

  if (authority !== null) {
    buf[21] = 0x01; // Some
    buf.set(authority.subarray(0, 32), 22);
  } else {
    buf[21] = 0x00; // None
    // bytes [22..54) remain zero (but the spec says we ignore them when tag=0)
  }
  // [54..56) padding = 0x0000 (already zero)

  // Write addresses starting at offset 56
  for (let i = 0; i < addresses.length; i++) {
    buf.set(addresses[i]!.subarray(0, 32), 56 + i * 32);
  }

  return buf;
}

// ---------------------------------------------------------------------------
// Synthetic test keys
// ---------------------------------------------------------------------------

/** A 32-byte key filled with a single byte value. */
function testKey(byte: number): Uint8Array {
  return new Uint8Array(32).fill(byte);
}

// Pre-built authority and address keys using real base58 round-trips.
const AUTHORITY_BYTES = testKey(0xaa);
const AUTHORITY_B58 = base58Encode(AUTHORITY_BYTES);

const ADDR0_BYTES = testKey(0x11);
const ADDR0_B58 = base58Encode(ADDR0_BYTES);

const ADDR1_BYTES = testKey(0x22);
const ADDR1_B58 = base58Encode(ADDR1_BYTES);

// ---------------------------------------------------------------------------
// T_ALT.1 — decode with authority tag=01 + 2 addresses
// ---------------------------------------------------------------------------

describe("T_ALT.1 decode with authority (tag=0x01) and 2 addresses", () => {
  const bytes = buildAltBytes({
    deactivationSlot: 0xffffffffffffffffn,
    lastExtendedSlot: 100n,
    lastExtendedSlotStartIndex: 5,
    authority: AUTHORITY_BYTES,
    addresses: [ADDR0_BYTES, ADDR1_BYTES],
  });

  const result = decodeAddressLookupTable(bytes);

  it("deactivationSlot decoded correctly", () => {
    expect(result.deactivationSlot).toBe(0xffffffffffffffffn);
  });

  it("lastExtendedSlot decoded correctly", () => {
    expect(result.lastExtendedSlot).toBe(100n);
  });

  it("lastExtendedSlotStartIndex decoded correctly", () => {
    expect(result.lastExtendedSlotStartIndex).toBe(5);
  });

  it("authority base58 round-trips via AUTHORITY_BYTES", () => {
    expect(result.authority).toBe(AUTHORITY_B58);
    // Verify the round-trip: decode the authority back to bytes
    const decoded = base58DecodeFixed(result.authority!, 32);
    expect(decoded).toEqual(AUTHORITY_BYTES);
  });

  it("addresses array has 2 entries", () => {
    expect(result.addresses.length).toBe(2);
  });

  it("address[0] matches ADDR0_B58 (real base58 round-trip)", () => {
    expect(result.addresses[0]).toBe(ADDR0_B58);
    const decoded = base58DecodeFixed(result.addresses[0]!, 32);
    expect(decoded).toEqual(ADDR0_BYTES);
  });

  it("address[1] matches ADDR1_B58 (real base58 round-trip)", () => {
    expect(result.addresses[1]).toBe(ADDR1_B58);
    const decoded = base58DecodeFixed(result.addresses[1]!, 32);
    expect(decoded).toEqual(ADDR1_BYTES);
  });
});

// ---------------------------------------------------------------------------
// T_ALT.2 — authority tag=00 -> authority null, addresses still from offset 56
// ---------------------------------------------------------------------------

describe("T_ALT.2 authority tag=0x00 -> authority null, addresses still at offset 56", () => {
  const bytes = buildAltBytes({
    deactivationSlot: 42n,
    lastExtendedSlot: 7n,
    lastExtendedSlotStartIndex: 0,
    authority: null, // tag=0x00
    addresses: [ADDR0_BYTES, ADDR1_BYTES],
  });

  const result = decodeAddressLookupTable(bytes);

  it("authority is null when tag=0x00", () => {
    expect(result.authority).toBeNull();
  });

  it("addresses still correctly read from offset 56", () => {
    expect(result.addresses.length).toBe(2);
    expect(result.addresses[0]).toBe(ADDR0_B58);
    expect(result.addresses[1]).toBe(ADDR1_B58);
  });

  it("slots decoded correctly", () => {
    expect(result.deactivationSlot).toBe(42n);
    expect(result.lastExtendedSlot).toBe(7n);
  });
});

// ---------------------------------------------------------------------------
// T_ALT.3 — discriminator != 1 -> throws AltDecodeError
// ---------------------------------------------------------------------------

describe("T_ALT.3 discriminator=0 (Uninitialized) throws AltDecodeError", () => {
  it("disc=0 throws AltDecodeError", () => {
    const bytes = buildAltBytes({ disc: 0 });
    expect(() => decodeAddressLookupTable(bytes)).toThrowError(AltDecodeError);
  });

  it("disc=2 throws AltDecodeError", () => {
    const bytes = buildAltBytes({ disc: 2 });
    expect(() => decodeAddressLookupTable(bytes)).toThrowError(AltDecodeError);
  });
});

// ---------------------------------------------------------------------------
// T_ALT.4 — buffer shorter than 56 bytes -> throws AltDecodeError
// ---------------------------------------------------------------------------

describe("T_ALT.4 buffer length < 56 -> throws AltDecodeError", () => {
  it("length=0 throws", () => {
    expect(() => decodeAddressLookupTable(new Uint8Array(0))).toThrowError(
      AltDecodeError,
    );
  });

  it("length=55 throws", () => {
    const short = new Uint8Array(55);
    // put a valid discriminator so the error is not about disc
    short[0] = 1; // disc LE = 1
    expect(() => decodeAddressLookupTable(short)).toThrowError(AltDecodeError);
  });
});

// ---------------------------------------------------------------------------
// T_ALT.5 — address region not multiple of 32 -> throws AltDecodeError
// ---------------------------------------------------------------------------

describe("T_ALT.5 (len-56) % 32 != 0 -> throws AltDecodeError", () => {
  it("57 bytes (56 metadata + 1 extra) throws", () => {
    const bytes = new Uint8Array(57);
    bytes[0] = 1; // valid disc
    bytes[21] = 0x00; // tag None
    expect(() => decodeAddressLookupTable(bytes)).toThrowError(AltDecodeError);
  });

  it("87 bytes (56 + 31) throws", () => {
    const bytes = new Uint8Array(87);
    bytes[0] = 1;
    bytes[21] = 0x00;
    expect(() => decodeAddressLookupTable(bytes)).toThrowError(AltDecodeError);
  });
});

// ---------------------------------------------------------------------------
// T_ALT.6 — N > 256 addresses -> throws AltDecodeError
// ---------------------------------------------------------------------------

describe("T_ALT.6 more than 256 addresses -> throws AltDecodeError", () => {
  it("257 addresses throws", () => {
    const bytes = new Uint8Array(56 + 257 * 32);
    bytes[0] = 1; // disc
    bytes[21] = 0x00; // tag None
    expect(() => decodeAddressLookupTable(bytes)).toThrowError(AltDecodeError);
  });
});

// ---------------------------------------------------------------------------
// T_ALT.7 — resolveAltIndexes helper
// ---------------------------------------------------------------------------

describe("T_ALT.7 resolveAltIndexes", () => {
  const addresses = [ADDR0_B58, ADDR1_B58];

  it("valid index 0 returns the address", () => {
    const result = resolveAltIndexes(addresses, [0]);
    expect(result[0]).toBe(ADDR0_B58);
  });

  it("valid index 1 returns the address", () => {
    const result = resolveAltIndexes(addresses, [1]);
    expect(result[0]).toBe(ADDR1_B58);
  });

  it("out-of-range index returns null (fail-closed, never throws)", () => {
    const result = resolveAltIndexes(addresses, [2]);
    expect(result[0]).toBeNull();
  });

  it("mixed valid and out-of-range", () => {
    const result = resolveAltIndexes(addresses, [0, 99, 1]);
    expect(result).toEqual([ADDR0_B58, null, ADDR1_B58]);
  });

  it("empty indexes array returns empty array", () => {
    expect(resolveAltIndexes(addresses, [])).toEqual([]);
  });

  it("empty address table, any index returns null", () => {
    expect(resolveAltIndexes([], [0])).toEqual([null]);
  });
});
