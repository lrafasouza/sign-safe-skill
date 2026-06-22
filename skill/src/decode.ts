/**
 * decode.ts -- PURE Solana message wire-format parser.
 *
 * Independent of @solana/web3.js by design: the test suite cross-checks THIS
 * parser against web3.js on the same bytes, so the two must be separate
 * implementations for the cross-check to mean anything.
 *
 * Handles both legacy and v0 (versioned) messages:
 *
 *   legacy message:
 *     [header(3)] [compact-u16 numKeys] [keys * 32]
 *     [blockhash(32)]
 *     [compact-u16 numIx] ( [progIdIdx(1)] [compact-u16 nAcct] [acctIdx*1]
 *                           [compact-u16 dataLen] [data] )*
 *
 *   v0 message:
 *     [0x80 | version] then the same as legacy, then
 *     [compact-u16 numLookups] ( [tableKey(32)]
 *       [compact-u16 nWritable] [writableIdx*1]
 *       [compact-u16 nReadonly] [readonlyIdx*1] )*
 *
 * The high bit of the FIRST byte distinguishes the two: if set, it is a
 * versioned message and the low 7 bits are the version number (only 0 is
 * currently defined). Otherwise it is legacy and that byte is the first
 * header byte (numRequiredSignatures).
 *
 * Fail-closed: any structural problem (truncation, impossible length,
 * trailing bytes, unsupported version) throws DecodeError. Callers in the
 * core translate that into a REJECT verdict; nothing is ever assumed valid.
 */

import type {
  AddressTableLookup,
  DecodedInstruction,
  DecodedMessage,
} from "./types.ts";

export class DecodeError extends Error {
  override name = "DecodeError";
}

/** Minimal, dependency-free base58 (Bitcoin alphabet) encoder. */
const BASE58_ALPHABET =
  "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

export function base58Encode(bytes: Uint8Array): string {
  if (bytes.length === 0) return "";
  // Count leading zero bytes -> leading '1's.
  let zeros = 0;
  while (zeros < bytes.length && bytes[zeros] === 0) zeros++;

  // Convert base-256 to base-58 via repeated big-number division.
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
  for (let i = digits.length - 1; i >= 0; i--) {
    out += BASE58_ALPHABET[digits[i] as number];
  }
  return out;
}

/** A forward-only byte cursor that throws on any over-read. */
class Reader {
  private offset = 0;
  constructor(private readonly buf: Uint8Array) {}

  get position(): number {
    return this.offset;
  }

  get remaining(): number {
    return this.buf.length - this.offset;
  }

  u8(): number {
    if (this.offset >= this.buf.length) {
      throw new DecodeError("unexpected end of input reading u8");
    }
    return this.buf[this.offset++] as number;
  }

  bytes(n: number): Uint8Array {
    if (n < 0) throw new DecodeError("negative length");
    if (this.offset + n > this.buf.length) {
      throw new DecodeError(
        `unexpected end of input: need ${n} bytes, have ${this.remaining}`,
      );
    }
    const out = this.buf.subarray(this.offset, this.offset + n);
    this.offset += n;
    return out;
  }

  /**
   * compact-u16 (a.k.a. "ShortVec"): little-endian base-128 varint capped at
   * 3 bytes / 16 bits. This is the array-length prefix used throughout the
   * Solana message format. Rejects non-canonical and overlong encodings.
   */
  compactU16(): number {
    let value = 0;
    for (let i = 0; i < 3; i++) {
      const byte = this.u8();
      value |= (byte & 0x7f) << (i * 7);
      if ((byte & 0x80) === 0) {
        // No continuation bit -> done. Guard the 16-bit ceiling.
        if (value > 0xffff) {
          throw new DecodeError("compact-u16 exceeds 16 bits");
        }
        // Reject non-minimal encodings (a trailing zero continuation byte).
        if (i > 0 && byte === 0) {
          throw new DecodeError("non-canonical compact-u16");
        }
        return value;
      }
    }
    throw new DecodeError("compact-u16 too long (>3 bytes)");
  }
}

/** Decode a base64-encoded serialized message into a DecodedMessage. */
export function decodeBase64Message(b64: string): DecodedMessage {
  let raw: Uint8Array;
  try {
    raw = new Uint8Array(Buffer.from(b64.trim(), "base64"));
  } catch {
    throw new DecodeError("input is not valid base64");
  }
  if (raw.length === 0) {
    throw new DecodeError("empty input");
  }
  return decodeMessageBytes(raw);
}

/** Decode raw serialized message bytes into a DecodedMessage. PURE. */
export function decodeMessageBytes(raw: Uint8Array): DecodedMessage {
  const reader = new Reader(raw);

  // Detect version from the high bit of the first byte (peek by reading it).
  const first = reader.u8();
  let version: "legacy" | 0;
  let numRequiredSignatures: number;

  if ((first & 0x80) !== 0) {
    const v = first & 0x7f;
    if (v !== 0) {
      throw new DecodeError(`unsupported message version ${v}`);
    }
    version = 0;
    numRequiredSignatures = reader.u8();
  } else {
    version = "legacy";
    numRequiredSignatures = first;
  }

  const numReadonlySignedAccounts = reader.u8();
  const numReadonlyUnsignedAccounts = reader.u8();

  // Static account keys.
  const numKeys = reader.compactU16();
  const staticAccountKeys: string[] = [];
  for (let i = 0; i < numKeys; i++) {
    staticAccountKeys.push(base58Encode(reader.bytes(32)));
  }

  // Sanity: header counts cannot exceed the number of static keys.
  if (
    numRequiredSignatures > numKeys ||
    numReadonlySignedAccounts > numRequiredSignatures ||
    numReadonlyUnsignedAccounts > numKeys - numRequiredSignatures
  ) {
    throw new DecodeError("message header counts are inconsistent with key count");
  }

  const recentBlockhash = base58Encode(reader.bytes(32));

  // Compiled instructions.
  const numInstructions = reader.compactU16();
  const instructions: DecodedInstruction[] = [];
  for (let i = 0; i < numInstructions; i++) {
    const programIdIndex = reader.u8();
    const numAccounts = reader.compactU16();
    const accountIndexes: number[] = [];
    for (let a = 0; a < numAccounts; a++) {
      accountIndexes.push(reader.u8());
    }
    const dataLen = reader.compactU16();
    const data = new Uint8Array(reader.bytes(dataLen)); // copy out of the buffer
    instructions.push({
      programIdIndex,
      programId: indexToKey(staticAccountKeys, programIdIndex),
      accountIndexes,
      data,
    });
  }

  // v0 address-table lookups.
  const addressTableLookups: AddressTableLookup[] = [];
  if (version === 0) {
    const numLookups = reader.compactU16();
    for (let i = 0; i < numLookups; i++) {
      const accountKey = base58Encode(reader.bytes(32));
      const nWritable = reader.compactU16();
      const writableIndexes: number[] = [];
      for (let w = 0; w < nWritable; w++) writableIndexes.push(reader.u8());
      const nReadonly = reader.compactU16();
      const readonlyIndexes: number[] = [];
      for (let r = 0; r < nReadonly; r++) readonlyIndexes.push(reader.u8());
      addressTableLookups.push({ accountKey, writableIndexes, readonlyIndexes });
    }
  }

  // Fail-closed: every instruction account index must resolve to an account
  // that actually exists. The resolvable account list is the static keys
  // followed by all ALT-sourced entries (writable across tables, then readonly
  // across tables). An index beyond that range cannot be mapped to any concrete
  // account, so the message is malformed (or adversarial) -> reject. (programId
  // indexes are already validated above via indexToKey, which is stricter: they
  // must be in the STATIC set, since program ids may not be ALT-sourced.)
  let totalAltAccounts = 0;
  for (const lut of addressTableLookups) {
    totalAltAccounts += lut.writableIndexes.length + lut.readonlyIndexes.length;
  }
  const totalAccounts = staticAccountKeys.length + totalAltAccounts;
  for (const ix of instructions) {
    for (const accIdx of ix.accountIndexes) {
      if (accIdx >= totalAccounts) {
        throw new DecodeError(
          `instruction account index ${accIdx} is outside the resolvable account set (have ${totalAccounts})`,
        );
      }
    }
  }

  // Fail-closed: a well-formed message consumes ALL of its bytes. Trailing
  // bytes mean we mis-parsed (or the input is adversarial) -> reject.
  if (reader.remaining !== 0) {
    throw new DecodeError(
      `trailing ${reader.remaining} byte(s) after message; refusing to trust partial parse`,
    );
  }

  return {
    version,
    header: {
      numRequiredSignatures,
      numReadonlySignedAccounts,
      numReadonlyUnsignedAccounts,
    },
    staticAccountKeys,
    recentBlockhash,
    instructions,
    addressTableLookups,
    altLookupsPresent: addressTableLookups.length > 0,
  };
}

/**
 * Resolve a program-id index to a base58 key. With ALTs, a program id could in
 * principle live in a lookup table, but Solana requires program ids to be in
 * the static key set, so an out-of-range index is a hard error.
 */
function indexToKey(staticKeys: string[], index: number): string {
  if (index < staticKeys.length) {
    return staticKeys[index] as string;
  }
  throw new DecodeError(
    `program id index ${index} is outside the static key set (programs cannot be ALT-sourced)`,
  );
}
