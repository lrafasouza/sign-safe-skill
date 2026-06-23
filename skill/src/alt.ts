/**
 * alt.ts -- PURE offline decoder for on-chain Address Lookup Table (ALT) accounts.
 *
 * Offline core: no network, no RPC, no fetch, no enrich.ts imports.
 * Same bytes in => same result out, deterministic and dependency-free.
 *
 * Implements the canonical bincode layout verified against:
 *   solana-program/address-lookup-table / solana/sdk/src/address_lookup_table/state.rs
 *
 * LOOKUP_TABLE_META_SIZE = 56 bytes (the fixed-size metadata header):
 *
 *   [0..4)   discriminator  u32 LE: 0=Uninitialized, 1=LookupTable (must be 1)
 *   [4..12)  deactivation_slot  u64 LE
 *   [12..20) last_extended_slot  u64 LE
 *   [20]     last_extended_slot_start_index  u8
 *   [21]     authority option tag: 0x00=None, 0x01=Some
 *   [22..54) authority pubkey  present only when tag==0x01 (32 bytes)
 *   [54..56) _padding u16  ignored
 *   [56..)   packed 32-byte pubkeys, NO length prefix. N = (len-56)/32
 *
 * FAIL-CLOSED: throws AltDecodeError on any structural violation:
 *   - discriminator != 1
 *   - buffer length < 56 (cannot contain full metadata)
 *   - (len-56) % 32 != 0 (address region not aligned)
 *   - N > 256 (Solana cap on ALT entries)
 *
 * The authority option tag at byte 21 is read explicitly. There is NO fixed
 * 32-byte authority slot: when tag=0x00, the bytes at [22..54) are ignored
 * (they may be zero-padded or carry arbitrary data). Addresses ALWAYS start
 * at offset 56 regardless of authority presence.
 */

import { base58Encode } from "./decode.ts";

/** Typed error for all ALT decode failures. Fail-closed. */
export class AltDecodeError extends Error {
  override name = "AltDecodeError";
}

/** Decoded Address Lookup Table account state. */
export interface DecodedAddressLookupTable {
  /** The slot at which this table was deactivated, or u64::MAX if still active. */
  deactivationSlot: bigint;
  /** The last slot that an extend was applied to this table. */
  lastExtendedSlot: bigint;
  /** The starting index of account addresses in the last extend. */
  lastExtendedSlotStartIndex: number;
  /** Base58 authority pubkey, or null if None (no authority / frozen). */
  authority: string | null;
  /** Ordered list of base58-encoded account addresses stored in the table. */
  addresses: string[];
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Decode a raw Address Lookup Table account buffer (the `data` field from
 * `getAccountInfo`). FAIL-CLOSED: throws AltDecodeError on any structural problem.
 * Never returns a partial result.
 */
export function decodeAddressLookupTable(
  bytes: Uint8Array,
): DecodedAddressLookupTable {
  // Minimum: 56 bytes for the full metadata header.
  if (bytes.length < 56) {
    throw new AltDecodeError(
      `ALT account too short: need at least 56 bytes (metadata), got ${bytes.length}`,
    );
  }

  // Read discriminator u32 LE at [0..4). Must be 1 (LookupTable).
  const disc =
    ((bytes[0] as number) |
      ((bytes[1] as number) << 8) |
      ((bytes[2] as number) << 16) |
      ((bytes[3] as number) << 24)) >>>
    0;
  if (disc !== 1) {
    throw new AltDecodeError(
      `ALT discriminator mismatch: expected 1 (LookupTable), got ${disc}`,
    );
  }

  // deactivation_slot u64 LE at [4..12)
  const deactivationSlot = readU64LE(bytes, 4);

  // last_extended_slot u64 LE at [12..20)
  const lastExtendedSlot = readU64LE(bytes, 12);

  // last_extended_slot_start_index u8 at [20]
  const lastExtendedSlotStartIndex = bytes[20] as number;

  // authority option tag u8 at [21]
  const authorityTag = bytes[21] as number;
  let authority: string | null;
  if (authorityTag === 0x01) {
    // Some: read the 32-byte authority pubkey at [22..54)
    const authorityBytes = bytes.subarray(22, 54);
    authority = base58Encode(authorityBytes);
  } else if (authorityTag === 0x00) {
    // None
    authority = null;
  } else {
    // Unknown option tag — fail-closed.
    throw new AltDecodeError(
      `ALT authority option tag invalid: expected 0x00 or 0x01, got 0x${authorityTag.toString(16).padStart(2, "0")}`,
    );
  }
  // bytes [54..56) are u16 padding — always ignored.

  // Address region starts at byte 56 (LOOKUP_TABLE_META_SIZE).
  const addrRegionLen = bytes.length - 56;
  if (addrRegionLen % 32 !== 0) {
    throw new AltDecodeError(
      `ALT address region length ${addrRegionLen} is not a multiple of 32 (each address is 32 bytes)`,
    );
  }
  const N = addrRegionLen / 32;
  if (N > 256) {
    throw new AltDecodeError(
      `ALT contains ${N} addresses; maximum is 256 (Solana protocol cap)`,
    );
  }

  const addresses: string[] = [];
  for (let i = 0; i < N; i++) {
    const start = 56 + i * 32;
    addresses.push(base58Encode(bytes.subarray(start, start + 32)));
  }

  return {
    deactivationSlot,
    lastExtendedSlot,
    lastExtendedSlotStartIndex,
    authority,
    addresses,
  };
}

/**
 * Resolve a list of ALT slot indexes to concrete base58 addresses.
 *
 * FAIL-CLOSED: if any index is out of range (>= addresses.length), returns null
 * for that slot. NEVER throws on bad input -- callers must treat null as
 * unresolved (same HOLD-forcing behavior as a missing ALT).
 *
 * @param addresses  The full ordered address list from a decoded ALT account.
 * @param indexes    The ALT slot indexes to look up (e.g. writableIndexes/readonlyIndexes).
 * @returns          Array parallel to `indexes`; each element is the resolved
 *                   base58 address or null when the index is out of range.
 */
export function resolveAltIndexes(
  addresses: readonly string[],
  indexes: readonly number[],
): (string | null)[] {
  return indexes.map((idx) => {
    if (idx < 0 || idx >= addresses.length) return null;
    return addresses[idx] ?? null;
  });
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/** Read u64 LE at a fixed offset. */
function readU64LE(buf: Uint8Array, offset: number): bigint {
  const lo =
    ((buf[offset] as number) |
      ((buf[offset + 1] as number) << 8) |
      ((buf[offset + 2] as number) << 16) |
      ((buf[offset + 3] as number) << 24)) >>>
    0;
  const hi =
    ((buf[offset + 4] as number) |
      ((buf[offset + 5] as number) << 8) |
      ((buf[offset + 6] as number) << 16) |
      ((buf[offset + 7] as number) << 24)) >>>
    0;
  return (BigInt(hi) << 32n) | BigInt(lo);
}
