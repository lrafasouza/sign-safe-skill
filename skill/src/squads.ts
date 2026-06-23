/**
 * squads.ts -- PURE offline decoder for Squads v4 VaultTransaction accounts.
 *
 * Offline core: no network, no RPC, no fetch, no enrich.ts imports.
 * Same bytes in => same result out, deterministic and dependency-free.
 *
 * Responsibilities:
 *   1. Validate the VaultTransaction account discriminator.
 *   2. Borsh-deserialize the stored VaultTransaction message per the Squads v4
 *      canonical layout (u32-LE Vec prefixes, raw 32-byte Pubkeys).
 *   3. Resolve inner instruction program IDs:
 *      - programIdIndex < accountKeys.length -> resolved (base58 key from the
 *        embedded account_keys array).
 *      - programIdIndex >= accountKeys.length -> falls into ALT space; CANNOT
 *        be resolved without fetching the on-chain address lookup table ->
 *        fail-closed: mark as unresolved, never SIGN.
 *   4. Expose isSquadsVaultExecute: detect a top-level vaultTransactionExecute
 *      instruction by program id + Anchor discriminator, so the enrichment
 *      layer knows WHEN to fetch the PDA.
 *
 * Error handling is FAIL-CLOSED: a typed SquadsDecodeError is thrown (never a
 * partial object) on discriminator mismatch, short input, or any structural
 * violation. Callers must catch and escalate to HOLD/REJECT.
 *
 * Layout (Squads v4, all ints LE, Vec<T> = u32-LE length + elements):
 *   [0..8)   discriminator  a8faa264510ea2cf
 *   [8..40)  multisig Pubkey (32)
 *   [40..72) creator  Pubkey (32)
 *   [72..80) index u64-LE
 *   [80]     bump u8
 *   [81]     vault_index u8
 *   [82]     vault_bump u8
 *   [83..87) ephemeral_signer_bumps Vec<u8> length (u32-LE)
 *   [87..87+L) ephemeral_signer_bumps elements
 *   message starts at 87+L:
 *     num_signers u8, num_writable_signers u8, num_writable_non_signers u8
 *     account_keys Vec<Pubkey>  (u32-LE count + 32*n bytes)
 *     instructions Vec<MultisigCompiledInstruction>
 *       each: program_id_index u8,
 *             account_indexes Vec<u8> (u32-LE count + count bytes),
 *             data Vec<u8> (u32-LE count + count bytes)
 *     address_table_lookups Vec<MultisigMessageAddressTableLookup>
 *       each: account_key Pubkey (32),
 *             writable_indexes Vec<u8> (u32-LE count + count bytes),
 *             readonly_indexes Vec<u8> (u32-LE count + count bytes)
 */

import { base58Encode } from "./decode.ts";
import type { DecodedMessage } from "./types.ts";

/** Squads v4 program id on mainnet-beta. */
export const SQUADS_V4_PROGRAM_ID =
  "SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf";

/**
 * VaultTransaction account discriminator:
 * sha256("account:VaultTransaction")[0..8] = a8faa264510ea2cf (LE hex).
 */
const VAULT_TRANSACTION_DISCRIMINATOR = new Uint8Array([
  0xa8, 0xfa, 0xa2, 0x64, 0x51, 0x0e, 0xa2, 0xcf,
]);

/**
 * vaultTransactionExecute instruction discriminator:
 * sha256("global:vault_transaction_execute")[0..8] = c208a15799a419ab.
 *
 * Verified: node -e "require('crypto').createHash('sha256')
 *   .update('global:vault_transaction_execute').digest().slice(0,8).toString('hex')"
 * => c208a15799a419ab
 */
const VAULT_TRANSACTION_EXECUTE_DISCRIMINATOR = new Uint8Array([
  0xc2, 0x08, 0xa1, 0x57, 0x99, 0xa4, 0x19, 0xab,
]);

/** Typed error for all VaultTransaction decode failures. Fail-closed. */
export class SquadsDecodeError extends Error {
  override name = "SquadsDecodeError";
}

/** One inner (compiled) instruction from the VaultTransaction message. */
export interface VaultInnerInstruction {
  /**
   * Program id as base58 string if resolved (programIdIndex < accountKeys.len),
   * or null if it falls into ALT lookup space (cannot resolve offline).
   */
  programId: string | null;
  /** Raw programIdIndex from the encoded message (for diagnostics). */
  programIdIndex: number;
  /** Account indexes into the embedded account_keys array. */
  accountIndexes: number[];
  /** Raw instruction data bytes. */
  data: Uint8Array;
}

/** One address-table-lookup entry from the VaultTransaction message. */
export interface VaultAddressTableLookup {
  /** Base58 address of the lookup table account. */
  accountKey: string;
  writableIndexes: number[];
  readonlyIndexes: number[];
}

/** The decoded result of a VaultTransaction account. */
export interface DecodedVaultTransaction {
  /** Base58 multisig address. */
  multisig: string;
  /** Base58 creator address. */
  creator: string;
  /** Transaction index. */
  index: bigint;
  bump: number;
  vaultIndex: number;
  vaultBump: number;
  ephemeralSignerBumps: number[];
  /** Embedded message fields. */
  numSigners: number;
  numWritableSigners: number;
  numWritableNonSigners: number;
  /** Static account keys embedded in the message (base58). */
  accountKeys: string[];
  /** Decoded inner instructions. */
  instructions: VaultInnerInstruction[];
  /** Address lookup tables referenced by the inner message. */
  addressTableLookups: VaultAddressTableLookup[];
  /**
   * True if ANY instruction has a programIdIndex that falls into ALT space
   * (i.e., programIdIndex >= accountKeys.length), meaning the inner program id
   * cannot be resolved offline. Callers MUST fail-closed when this is true.
   */
  hasUnresolvedPrograms: boolean;
}

// ---------------------------------------------------------------------------
// Borsh reader helpers (no external dependencies)
// ---------------------------------------------------------------------------

/** Stateful cursor over a Uint8Array for sequential borsh reads. */
class Reader {
  pos = 0;
  constructor(private readonly buf: Uint8Array) {}

  remaining(): number {
    return this.buf.length - this.pos;
  }

  readU8(label: string): number {
    if (this.pos >= this.buf.length) {
      throw new SquadsDecodeError(`truncated at ${label} (pos=${this.pos})`);
    }
    return this.buf[this.pos++] as number;
  }

  readU32LE(label: string): number {
    if (this.pos + 4 > this.buf.length) {
      throw new SquadsDecodeError(`truncated at ${label} (pos=${this.pos})`);
    }
    const v =
      ((this.buf[this.pos] as number) |
        ((this.buf[this.pos + 1] as number) << 8) |
        ((this.buf[this.pos + 2] as number) << 16) |
        ((this.buf[this.pos + 3] as number) << 24)) >>>
      0;
    this.pos += 4;
    return v;
  }

  readU64LE(label: string): bigint {
    if (this.pos + 8 > this.buf.length) {
      throw new SquadsDecodeError(`truncated at ${label} (pos=${this.pos})`);
    }
    const lo =
      ((this.buf[this.pos] as number) |
        ((this.buf[this.pos + 1] as number) << 8) |
        ((this.buf[this.pos + 2] as number) << 16) |
        ((this.buf[this.pos + 3] as number) << 24)) >>>
      0;
    const hi =
      ((this.buf[this.pos + 4] as number) |
        ((this.buf[this.pos + 5] as number) << 8) |
        ((this.buf[this.pos + 6] as number) << 16) |
        ((this.buf[this.pos + 7] as number) << 24)) >>>
      0;
    this.pos += 8;
    return (BigInt(hi) << 32n) | BigInt(lo);
  }

  readBytes(n: number, label: string): Uint8Array {
    if (n < 0 || this.pos + n > this.buf.length) {
      throw new SquadsDecodeError(
        `truncated at ${label}: need ${n} bytes at pos=${this.pos}, have ${this.buf.length - this.pos}`,
      );
    }
    const slice = this.buf.subarray(this.pos, this.pos + n);
    this.pos += n;
    return slice;
  }

  /**
   * Read a Vec<u8> (u32-LE length prefix + length bytes).
   * Guarded: rejects unreasonably large lengths to prevent OOM on corrupt input.
   */
  readVecU8(label: string, maxLen = 65536): number[] {
    const len = this.readU32LE(`${label}.len`);
    if (len > maxLen) {
      throw new SquadsDecodeError(
        `${label}: Vec<u8> length ${len} exceeds guard limit ${maxLen}`,
      );
    }
    const bytes = this.readBytes(len, label);
    return Array.from(bytes);
  }

  /**
   * Read a Vec<Pubkey> (u32-LE length prefix + 32*len bytes).
   * Returns array of base58-encoded public keys.
   */
  readVecPubkey(label: string, maxLen = 256): string[] {
    const len = this.readU32LE(`${label}.len`);
    if (len > maxLen) {
      throw new SquadsDecodeError(
        `${label}: Vec<Pubkey> length ${len} exceeds guard limit ${maxLen}`,
      );
    }
    const keys: string[] = [];
    for (let i = 0; i < len; i++) {
      const keyBytes = this.readBytes(32, `${label}[${i}]`);
      keys.push(base58Encode(keyBytes));
    }
    return keys;
  }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Decode a Squads v4 VaultTransaction account from its raw bytes.
 *
 * FAIL-CLOSED: throws SquadsDecodeError on any structural problem (bad
 * discriminator, truncation, over-long Vec, trailing bytes). Never returns a
 * partial result. Callers must treat any thrown error as HOLD/REJECT.
 *
 * @param accountBytes Raw account data (without the 8-byte rent-discriminator
 *   that some account-info APIs prepend; pass the raw `data` field as returned
 *   by `getAccountInfo`).
 */
export function decodeVaultTransaction(
  accountBytes: Uint8Array,
): DecodedVaultTransaction {
  if (accountBytes.length < 8) {
    throw new SquadsDecodeError(
      `account too short to contain discriminator: ${accountBytes.length} bytes`,
    );
  }

  // Validate discriminator.
  for (let i = 0; i < 8; i++) {
    if (accountBytes[i] !== VAULT_TRANSACTION_DISCRIMINATOR[i]) {
      throw new SquadsDecodeError(
        `VaultTransaction discriminator mismatch at byte ${i}: ` +
          `expected ${VAULT_TRANSACTION_DISCRIMINATOR[i]?.toString(16).padStart(2, "0")} ` +
          `got ${accountBytes[i]?.toString(16).padStart(2, "0")}`,
      );
    }
  }

  const r = new Reader(accountBytes);
  r.pos = 8; // skip discriminator

  // multisig Pubkey [8..40)
  const multisigBytes = r.readBytes(32, "multisig");
  const multisig = base58Encode(multisigBytes);

  // creator Pubkey [40..72)
  const creatorBytes = r.readBytes(32, "creator");
  const creator = base58Encode(creatorBytes);

  // index u64-LE [72..80)
  const index = r.readU64LE("index");

  // bump, vault_index, vault_bump [80..83)
  const bump = r.readU8("bump");
  const vaultIndex = r.readU8("vault_index");
  const vaultBump = r.readU8("vault_bump");

  // ephemeral_signer_bumps Vec<u8> [83..87+L)
  const ephemeralSignerBumps = r.readVecU8("ephemeral_signer_bumps", 32);

  // -- VaultTransactionMessage --
  // num_signers, num_writable_signers, num_writable_non_signers
  const numSigners = r.readU8("num_signers");
  const numWritableSigners = r.readU8("num_writable_signers");
  const numWritableNonSigners = r.readU8("num_writable_non_signers");

  // account_keys Vec<Pubkey>
  const accountKeys = r.readVecPubkey("account_keys");
  const nKeys = accountKeys.length;

  // instructions Vec<MultisigCompiledInstruction>
  const nInstructions = r.readU32LE("instructions.len");
  if (nInstructions > 256) {
    throw new SquadsDecodeError(
      `instructions: Vec length ${nInstructions} exceeds guard limit 256`,
    );
  }

  const instructions: VaultInnerInstruction[] = [];
  let hasUnresolvedPrograms = false;

  for (let i = 0; i < nInstructions; i++) {
    const programIdIndex = r.readU8(`instructions[${i}].program_id_index`);
    const accountIndexes = r.readVecU8(`instructions[${i}].account_indexes`, 256);
    const data = new Uint8Array(r.readVecU8(`instructions[${i}].data`, 65536));

    let programId: string | null;
    if (programIdIndex < nKeys) {
      programId = accountKeys[programIdIndex] as string;
    } else {
      // Falls into ALT space: cannot resolve offline.
      programId = null;
      hasUnresolvedPrograms = true;
    }

    instructions.push({ programId, programIdIndex, accountIndexes, data });
  }

  // address_table_lookups Vec<MultisigMessageAddressTableLookup>
  const nAtl = r.readU32LE("address_table_lookups.len");
  if (nAtl > 64) {
    throw new SquadsDecodeError(
      `address_table_lookups: Vec length ${nAtl} exceeds guard limit 64`,
    );
  }

  const addressTableLookups: VaultAddressTableLookup[] = [];
  for (let i = 0; i < nAtl; i++) {
    const keyBytes = r.readBytes(32, `address_table_lookups[${i}].account_key`);
    const accountKey = base58Encode(keyBytes);
    const writableIndexes = r.readVecU8(
      `address_table_lookups[${i}].writable_indexes`,
      256,
    );
    const readonlyIndexes = r.readVecU8(
      `address_table_lookups[${i}].readonly_indexes`,
      256,
    );
    addressTableLookups.push({ accountKey, writableIndexes, readonlyIndexes });
  }

  // Fail-closed: reject trailing bytes (they indicate format mismatch).
  if (r.remaining() !== 0) {
    throw new SquadsDecodeError(
      `trailing bytes after VaultTransaction: ${r.remaining()} bytes remain at pos=${r.pos}`,
    );
  }

  return {
    multisig,
    creator,
    index,
    bump,
    vaultIndex,
    vaultBump,
    ephemeralSignerBumps,
    numSigners,
    numWritableSigners,
    numWritableNonSigners,
    accountKeys,
    instructions,
    addressTableLookups,
    hasUnresolvedPrograms,
  };
}

/**
 * Extract the VaultTransaction PDA address from a top-level decoded message.
 *
 * Finds the first instruction where `isSquadsVaultExecute` is true and returns
 * the base58 address at account index 2 of that instruction.
 *
 * Resolution rules (fail-closed):
 *   - If `ix.accountIndexes[2]` is within the static account key array, return
 *     that static key.
 *   - If it is >= staticAccountKeys.length (ALT-sourced), return null (the
 *     concrete address cannot be resolved offline -- fail-closed).
 *   - If no vaultTransactionExecute instruction is found, return null.
 *   - If the instruction has fewer than 3 account indexes, return null.
 *
 * PURE and offline: no network, no RPC. Used by review-online.ts (host layer)
 * to know which PDA to fetch; the fetch itself lives in the host layer only.
 */
export function extractVaultTransactionAddress(msg: DecodedMessage): string | null {
  for (const ix of msg.instructions) {
    if (!isSquadsVaultExecute(ix.programId, ix.data)) continue;
    // Found a vaultTransactionExecute instruction.
    if (ix.accountIndexes.length < 3) return null; // not enough accounts
    const idx = ix.accountIndexes[2] as number;
    if (idx >= msg.staticAccountKeys.length) {
      // ALT-sourced: cannot resolve offline. Fail-closed.
      return null;
    }
    return msg.staticAccountKeys[idx] ?? null;
  }
  return null;
}

/**
 * Return true if a top-level instruction is a Squads v4 vaultTransactionExecute
 * call: program id matches SQUADS_V4_PROGRAM_ID and the first 8 bytes of
 * instruction data match the Anchor `global:vault_transaction_execute`
 * discriminator (c208a15799a419ab).
 *
 * PURE and offline -- used by the verdict layer to know WHEN to fetch the PDA
 * for inner-instruction analysis (actual fetch lives in enrich.ts, never here).
 *
 * NOTE: If the data is shorter than 8 bytes the instruction cannot carry a
 * valid Anchor discriminator, so we return false (fail-closed: do not assume
 * it is a vault execute).
 */
export function isSquadsVaultExecute(
  programId: string,
  data: Uint8Array,
): boolean {
  if (programId !== SQUADS_V4_PROGRAM_ID) return false;
  if (data.length < 8) return false;
  for (let i = 0; i < 8; i++) {
    if (data[i] !== VAULT_TRANSACTION_EXECUTE_DISCRIMINATOR[i]) return false;
  }
  return true;
}
