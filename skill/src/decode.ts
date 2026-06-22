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

const BASE58_MAP: Record<string, number> = (() => {
  const m: Record<string, number> = {};
  for (let i = 0; i < BASE58_ALPHABET.length; i++) m[BASE58_ALPHABET[i] as string] = i;
  return m;
})();

/**
 * Decode base58 to bytes, left-padded/truncated to exactly `size` bytes (the
 * keys we round-trip are always 32-byte pubkeys / blockhashes). Used by the
 * pure re-encoder for property-based round-trip tests. Throws on a bad char.
 */
export function base58DecodeFixed(b58: string, size: number): Uint8Array {
  let bytes: number[] = [];
  for (const ch of b58) {
    const v = BASE58_MAP[ch];
    if (v === undefined) throw new DecodeError(`invalid base58 char '${ch}'`);
    let carry = v;
    for (let j = 0; j < bytes.length; j++) {
      carry += (bytes[j] as number) * 58;
      bytes[j] = carry & 0xff;
      carry >>= 8;
    }
    while (carry > 0) {
      bytes.push(carry & 0xff);
      carry >>= 8;
    }
  }
  let leadingZeros = 0;
  for (const ch of b58) {
    if (ch === "1") leadingZeros++;
    else break;
  }
  const body = bytes.reverse();
  const total = body.length + leadingZeros;
  if (total > size) throw new DecodeError(`base58 value larger than ${size} bytes`);
  const out = new Uint8Array(size);
  out.set(body, size - body.length);
  return out;
}

/** Encode a length as canonical compact-u16 bytes (1-3 bytes). */
export function encodeCompactU16(value: number): number[] {
  if (value < 0 || value > 0xffff) {
    throw new DecodeError(`compact-u16 out of range: ${value}`);
  }
  const out: number[] = [];
  let rem = value;
  for (;;) {
    let byte = rem & 0x7f;
    rem >>= 7;
    if (rem === 0) {
      out.push(byte);
      break;
    }
    out.push(byte | 0x80);
  }
  return out;
}

/**
 * Re-encode a DecodedMessage to its exact wire bytes. PURE. Inverse of
 * decodeMessageBytes for any well-formed message, which is the basis of the
 * property-based round-trip identity test (T2.1). Produces canonical
 * compact-u16 lengths, so `encode(decode(b)) === b` for canonically-encoded
 * inputs (the only inputs the decoder accepts).
 */
export function encodeMessageBytes(msg: DecodedMessage): Uint8Array {
  const out: number[] = [];
  if (msg.version === 0) out.push(0x80);
  out.push(
    msg.header.numRequiredSignatures,
    msg.header.numReadonlySignedAccounts,
    msg.header.numReadonlyUnsignedAccounts,
  );
  out.push(...encodeCompactU16(msg.staticAccountKeys.length));
  for (const k of msg.staticAccountKeys) {
    out.push(...base58DecodeFixed(k, 32));
  }
  out.push(...base58DecodeFixed(msg.recentBlockhash, 32));
  out.push(...encodeCompactU16(msg.instructions.length));
  for (const ix of msg.instructions) {
    out.push(ix.programIdIndex);
    out.push(...encodeCompactU16(ix.accountIndexes.length));
    out.push(...ix.accountIndexes);
    out.push(...encodeCompactU16(ix.data.length));
    out.push(...ix.data);
  }
  if (msg.version === 0) {
    out.push(...encodeCompactU16(msg.addressTableLookups.length));
    for (const lut of msg.addressTableLookups) {
      out.push(...base58DecodeFixed(lut.accountKey, 32));
      out.push(...encodeCompactU16(lut.writableIndexes.length));
      out.push(...lut.writableIndexes);
      out.push(...encodeCompactU16(lut.readonlyIndexes.length));
      out.push(...lut.readonlyIndexes);
    }
  }
  return Uint8Array.from(out);
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

  // Sanitization invariants (D19). These are the runtime/Squads sanitize rules;
  // a message that violates them is rejected by the cluster, so a "benign"
  // decode of one would be a lie.
  //   - numRequiredSignatures >= 1: there is always a fee payer / signer.
  //   - numReadonlySignedAccounts < numRequiredSignatures (STRICT): index 0 is
  //     always a WRITABLE signer (the fee payer). Allowing equality would mean
  //     zero writable signers / no writable fee payer, which is invalid (breaks
  //     R12) -- the previous `>` check wrongly permitted it.
  //   - numRequiredSignatures + numReadonlyUnsignedAccounts <= numKeys: the
  //     readonly-unsigned tail must fit after the signers.
  if (numRequiredSignatures < 1) {
    throw new DecodeError("numRequiredSignatures must be >= 1 (no fee payer)");
  }
  if (numRequiredSignatures > numKeys) {
    throw new DecodeError("numRequiredSignatures exceeds account-key count");
  }
  if (numReadonlySignedAccounts >= numRequiredSignatures) {
    throw new DecodeError(
      "numReadonlySignedAccounts must be < numRequiredSignatures (no writable fee payer at index 0)",
    );
  }
  if (numRequiredSignatures + numReadonlyUnsignedAccounts > numKeys) {
    throw new DecodeError(
      "numRequiredSignatures + numReadonlyUnsignedAccounts exceeds account-key count",
    );
  }

  // No duplicate keys in the static account list (D19 sanitize invariant). The
  // FULL combined-list duplicate check (including ALT-resolved addresses) is
  // inherently online-only -- ALT addresses are unknown offline -- so it MUST be
  // enforced by the online resolver after fetching the tables. Offline we reject
  // any duplicate among the static keys, which the runtime also rejects.
  if (new Set(staticAccountKeys).size !== staticAccountKeys.length) {
    throw new DecodeError("duplicate keys in static account list");
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
  //
  // D18 DEFERRED CHECK (documented, not silently skipped): each ALT
  // writable_indexes/readonly_indexes entry is a u8 index INTO the lookup
  // table's address array (D15). We validate instruction indexes against the
  // COMBINED count below, but we CANNOT validate that each ALT table index is
  // < that table's resolved address count, because the table length is only
  // known after an on-chain fetch. The online ALT resolver MUST enforce
  // "ALT index < table length" and treat any out-of-range index as fail-closed
  // (matching Squads InvalidTransactionMessage). See src/enrich.ts.
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
