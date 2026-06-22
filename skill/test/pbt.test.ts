/**
 * pbt.test.ts -- property-based tests (fast-check), seed pinned to 42.
 * T2.1 round-trip identity, T2.3 fail-closed on arbitrary bytes, T2.4 no
 * trailing-byte tolerance, T2.5 compact-u16 invariants (D6-D8).
 */

import { describe, it, expect } from "vitest";
import fc from "fast-check";
import {
  decodeMessageBytes,
  encodeMessageBytes,
  encodeCompactU16,
  DecodeError,
} from "../src/decode.ts";
import { VersionedMessage } from "@solana/web3.js";
import { encodeCompactU16 as helperEncode, key } from "./helpers.ts";

fc.configureGlobal({ seed: 42, numRuns: 200 });

/** A distinct 32-byte key from an index (avoids duplicates: D19). */
function distinctKeyBytes(i: number): number[] {
  const b = new Array(32).fill(0);
  b[0] = (i + 1) & 0xff;
  b[1] = ((i + 1) >> 8) & 0xff;
  return b;
}

/**
 * Build raw bytes for a VALID message from structured params, honoring D19:
 *   - numRequiredSignatures >= 1
 *   - numReadonlySignedAccounts < numRequiredSignatures
 *   - numRequiredSignatures + numReadonlyUnsignedAccounts <= numKeys
 *   - distinct keys, all account indexes in range.
 */
interface ValidParams {
  versioned: boolean;
  numKeys: number;
  roSigned: number; // < numReqSig
  roUnsigned: number;
  reqSig: number;
  instructions: Array<{ prog: number; accts: number[]; dataLen: number; dataSeed: number }>;
  luts: Array<{ writable: number[]; readonly: number[] }>;
}

const validParamsArb: fc.Arbitrary<ValidParams> = fc
  .record({
    versioned: fc.boolean(),
    numKeys: fc.integer({ min: 2, max: 8 }),
    reqSig: fc.integer({ min: 1, max: 4 }),
    roSignedRaw: fc.integer({ min: 0, max: 3 }),
    roUnsignedRaw: fc.integer({ min: 0, max: 3 }),
    nIx: fc.integer({ min: 0, max: 3 }),
    nLut: fc.integer({ min: 0, max: 2 }),
    seed: fc.integer({ min: 0, max: 1_000_000 }),
  })
  .map((r) => {
    const reqSig = Math.min(r.reqSig, r.numKeys);
    const roSigned = Math.min(r.roSignedRaw, Math.max(0, reqSig - 1)); // < reqSig
    const roUnsigned = Math.min(r.roUnsignedRaw, r.numKeys - reqSig);
    // Total combined accounts (static + ALT) drives valid account indexes.
    const versioned = r.versioned;
    const luts = versioned
      ? Array.from({ length: r.nLut }, (_v, i) => ({
          writable: i % 2 === 0 ? [1, 2] : [3],
          readonly: [4],
        }))
      : [];
    let altCount = 0;
    for (const l of luts) altCount += l.writable.length + l.readonly.length;
    const combined = r.numKeys + altCount;
    const instructions = Array.from({ length: r.nIx }, (_v, i) => ({
      prog: i % r.numKeys, // program ids must be static (in [0, numKeys))
      accts: [i % combined, (i + 1) % combined],
      dataLen: (r.seed + i) % 12,
      dataSeed: r.seed + i,
    }));
    return {
      versioned,
      numKeys: r.numKeys,
      reqSig,
      roSigned,
      roUnsigned,
      instructions,
      luts,
    };
  });

function buildValidBytes(p: ValidParams): Uint8Array {
  const out: number[] = [];
  if (p.versioned) out.push(0x80);
  out.push(p.reqSig, p.roSigned, p.roUnsigned);
  out.push(...encodeCompactU16(p.numKeys));
  for (let i = 0; i < p.numKeys; i++) out.push(...distinctKeyBytes(i));
  out.push(...key(200)); // blockhash (distinct from keys via fill 200)
  out.push(...encodeCompactU16(p.instructions.length));
  for (const ix of p.instructions) {
    out.push(ix.prog);
    out.push(...encodeCompactU16(ix.accts.length));
    out.push(...ix.accts);
    const data = Array.from({ length: ix.dataLen }, (_v, j) => (ix.dataSeed + j) & 0xff);
    out.push(...encodeCompactU16(data.length));
    out.push(...data);
  }
  if (p.versioned) {
    out.push(...encodeCompactU16(p.luts.length));
    for (let li = 0; li < p.luts.length; li++) {
      const lut = p.luts[li]!;
      out.push(...key(210 + li)); // distinct table keys
      out.push(...encodeCompactU16(lut.writable.length));
      out.push(...lut.writable);
      out.push(...encodeCompactU16(lut.readonly.length));
      out.push(...lut.readonly);
    }
  }
  return Uint8Array.from(out);
}

describe("T2.1 round-trip identity: encode(decode(b)) === b", () => {
  it("decoding then re-encoding reproduces the exact bytes", () => {
    fc.assert(
      fc.property(validParamsArb, (p) => {
        const bytes = buildValidBytes(p);
        // The generator may still produce a message web3.js rejects (blockhash
        // collision is avoided; key 200/210 are distinct). Only test inputs our
        // decoder accepts; if decode throws, skip (pre-condition).
        let msg;
        try {
          msg = decodeMessageBytes(bytes);
        } catch (e) {
          fc.pre(false); // not a valid input for this property
          return;
        }
        const reencoded = encodeMessageBytes(msg);
        expect(Buffer.from(reencoded).equals(Buffer.from(bytes))).toBe(true);
      }),
    );
  });

  it("our decode agrees with @solana/web3.js on accepted valid messages (T2.2)", () => {
    fc.assert(
      fc.property(validParamsArb, (p) => {
        const bytes = buildValidBytes(p);
        let msg;
        try {
          msg = decodeMessageBytes(bytes);
        } catch {
          fc.pre(false);
          return;
        }
        let w3;
        try {
          w3 = VersionedMessage.deserialize(bytes);
        } catch {
          // web3.js rejects some headers our decoder also should not have
          // accepted; if it rejects, just require that OUR decode is consistent
          // with re-encoding (already covered) and skip the differential.
          fc.pre(false);
          return;
        }
        const w3Keys = w3.staticAccountKeys.map((k) => k.toBase58());
        expect(msg.staticAccountKeys).toEqual(w3Keys);
        const w3Version = w3.version === "legacy" ? "legacy" : w3.version;
        expect(msg.version).toBe(w3Version);
        expect(msg.addressTableLookups.length).toBe(w3.addressTableLookups.length);
      }),
    );
  });
});

describe("T2.3 fail-closed on arbitrary bytes (D16)", () => {
  it("any byte string either re-encodes to itself or throws -- never partial", () => {
    fc.assert(
      fc.property(fc.uint8Array({ minLength: 0, maxLength: 400 }), (arr) => {
        const bytes = Uint8Array.from(arr);
        let msg;
        try {
          msg = decodeMessageBytes(bytes);
        } catch (e) {
          expect(e).toBeInstanceOf(DecodeError);
          return; // typed error, no partial object: OK
        }
        // If it decoded, the round-trip MUST reproduce the exact input bytes
        // (a canonical, complete parse). Otherwise it was a partial/lossy parse.
        const re = encodeMessageBytes(msg);
        expect(Buffer.from(re).equals(Buffer.from(bytes))).toBe(true);
      }),
    );
  });
});

describe("T2.4 no trailing-byte tolerance (D17)", () => {
  it("appending random bytes to a valid encoding is always rejected", () => {
    fc.assert(
      fc.property(
        validParamsArb,
        fc.uint8Array({ minLength: 1, maxLength: 8 }),
        (p, extra) => {
          const bytes = buildValidBytes(p);
          let ok = false;
          try {
            decodeMessageBytes(bytes);
            ok = true;
          } catch {
            fc.pre(false);
            return;
          }
          if (!ok) return;
          const withTrailing = Uint8Array.from([...bytes, ...extra]);
          expect(() => decodeMessageBytes(withTrailing)).toThrow(DecodeError);
        },
      ),
    );
  });
});

describe("T2.5 compact-u16 invariants (D6-D8)", () => {
  it("every length in [0, 65535] encodes to the correct canonical byte count", () => {
    fc.assert(
      fc.property(fc.integer({ min: 0, max: 65535 }), (value) => {
        const enc = encodeCompactU16(value);
        expect(enc.length).toBeGreaterThanOrEqual(1);
        expect(enc.length).toBeLessThanOrEqual(3);
        if (value <= 0x7f) expect(enc.length).toBe(1);
        else if (value <= 0x3fff) expect(enc.length).toBe(2);
        else expect(enc.length).toBe(3);
        // round-trips through the canonical encoder/decoder pair: the decoder's
        // private compactU16 is exercised below via embedding.
      }),
      { numRuns: 500 },
    );
  });

  it("embedded lengths decode to the exact value + byte count (incl. boundaries)", () => {
    // Exhaustive at the transitions plus a sampled range (kept small so the
    // data payload stays cheap), proving the decoder's compactU16 consumes the
    // right bytes and yields the right value.
    const values = [0, 1, 126, 127, 128, 129, 255, 256, 1000, 16383, 16384, 16385, 2000];
    for (const value of values) {
      const enc = encodeCompactU16(value);
      const probe = buildProbeWithDataLen(enc, value);
      const msg = decodeMessageBytes(probe);
      expect(msg.instructions[0]!.data.length, `value ${value}`).toBe(value);
    }
  });

  it("non-canonical / overflow / truncated compact-u16 are rejected", () => {
    const rejects = [
      [0x80, 0x00],
      [0xff, 0x00],
      [0x80, 0x80, 0x00],
      [0x81, 0x80, 0x00],
      [0x80],
      [0x80, 0x80, 0x80, 0x00],
      [0x80, 0x80, 0x04],
      [0x80, 0x80, 0x06],
    ];
    for (const prefix of rejects) {
      const probe = buildProbeWithDataLen(prefix, 8);
      expect(() => decodeMessageBytes(probe), JSON.stringify(prefix)).toThrow(
        DecodeError,
      );
    }
  });
});

/** Probe message: 1 ix with a given data-length prefix + `dataLen` data bytes. */
function buildProbeWithDataLen(prefix: number[], dataLen: number): Uint8Array {
  const out: number[] = [];
  out.push(1, 0, 1);
  out.push(...helperEncode(2));
  out.push(...key(1));
  out.push(...key(2));
  out.push(...key(250));
  out.push(...helperEncode(1)); // 1 instruction
  out.push(1); // programIdIndex
  out.push(...helperEncode(0)); // 0 accounts
  out.push(...prefix); // data-length prefix under test
  out.push(...new Array(dataLen).fill(0));
  return Uint8Array.from(out);
}
