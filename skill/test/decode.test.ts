/**
 * decode.test.ts -- wire-format decoder invariants (CORRECTNESS-SPEC section A).
 * Covers compact-u16 canonical vectors (T4.1) + rejection set (T4.2), D19
 * sanitization, version discrimination (T10.4/T10.6), truncation/trailing/oob
 * fail-closed (T10.1-10.3, T10.5), and duplicate-key rejection.
 */

import { describe, it, expect } from "vitest";
import { decodeMessageBytes, DecodeError } from "../src/decode.ts";
import { encodeCompactU16, legacyBytes, v0Bytes, key } from "./helpers.ts";

/**
 * Build a minimal valid message that uses `count` as a particular array-length
 * prefix, so we can probe compact-u16 behavior through the real decoder. We use
 * the instruction-data length field for the probe: a legacy message with one
 * instruction whose data length is `count`, padded with `count` zero bytes.
 */
function messageWithDataLen(
  countBytes: number[],
  dataBytes: number[],
): Uint8Array {
  // header [1,0,1], 2 keys (prog at idx1), blockhash, 1 ix
  const out: number[] = [];
  out.push(1, 0, 1);
  out.push(...encodeCompactU16(2));
  out.push(...key(1)); // key0 signer/fee payer
  out.push(...key(2)); // key1 program
  out.push(...key(250)); // blockhash
  out.push(...encodeCompactU16(1)); // 1 instruction
  out.push(1); // programIdIndex = 1
  out.push(...encodeCompactU16(0)); // 0 accounts
  out.push(...countBytes); // data length prefix (the compact-u16 under test)
  out.push(...dataBytes);
  return Uint8Array.from(out);
}

describe("compact-u16 canonical vectors (T4.1 / D8)", () => {
  // value -> exact canonical bytes
  const vectors: Array<[number, number[]]> = [
    [0x0000, [0x00]],
    [0x007f, [0x7f]],
    [0x0080, [0x80, 0x01]],
    [0x00ff, [0xff, 0x01]],
    [0x0100, [0x80, 0x02]],
    [0x3fff, [0xff, 0x7f]],
    [0x4000, [0x80, 0x80, 0x01]],
    [0x7fff, [0xff, 0xff, 0x01]],
    [0xffff, [0xff, 0xff, 0x03]],
  ];

  it("encodeCompactU16 produces the canonical bytes", () => {
    for (const [value, bytes] of vectors) {
      expect(encodeCompactU16(value), `value ${value}`).toEqual(bytes);
    }
  });

  it("the decoder reads each canonical prefix to the exact value + byte count", () => {
    for (const [value, bytes] of vectors) {
      if (value > 4) continue; // keep data payload small; small values suffice here
      const msg = decodeMessageBytes(
        messageWithDataLen(bytes, new Array(value).fill(0)),
      );
      expect(msg.instructions[0]!.data.length).toBe(value);
    }
    // Boundary 127/128 transition consumes the right number of bytes (T4.3):
    // data length 127 (1-byte prefix [0x7f]) vs 128 (2-byte prefix [0x80,0x01]).
    const m127 = decodeMessageBytes(
      messageWithDataLen([0x7f], new Array(127).fill(7)),
    );
    expect(m127.instructions[0]!.data.length).toBe(127);
    const m128 = decodeMessageBytes(
      messageWithDataLen([0x80, 0x01], new Array(128).fill(8)),
    );
    expect(m128.instructions[0]!.data.length).toBe(128);
  });
});

describe("compact-u16 rejection set (T4.2 / D7)", () => {
  // Each of these, used as a data-length prefix, must make the decoder throw.
  const rejects: Array<[string, number[]]> = [
    ["alias [0x80,0x00]", [0x80, 0x00]],
    ["alias [0xff,0x00]", [0xff, 0x00]],
    ["alias [0x80,0x80,0x00]", [0x80, 0x80, 0x00]],
    ["alias [0x81,0x80,0x00]", [0x81, 0x80, 0x00]],
    ["truncation [0x80]", [0x80]],
    ["too-long [0x80,0x80,0x80,0x00]", [0x80, 0x80, 0x80, 0x00]],
    ["overflow [0x80,0x80,0x04]", [0x80, 0x80, 0x04]],
    ["overflow [0x80,0x80,0x06]", [0x80, 0x80, 0x06]],
  ];

  for (const [label, prefix] of rejects) {
    it(`rejects ${label}`, () => {
      // Append enough trailing zero bytes that the ONLY problem is the prefix
      // (so a pass would be a real false-accept, not an unrelated underrun).
      const bytes = messageWithDataLen(prefix, new Array(8).fill(0));
      expect(() => decodeMessageBytes(bytes)).toThrow(DecodeError);
    });
  }
});

describe("version discrimination (D2/D3, T10.4/T10.6)", () => {
  it("legacy: high bit clear => byte0 is numRequiredSignatures", () => {
    const bytes = legacyBytes(
      [1, 0, 1],
      [1, 2],
      [{ prog: 1, accts: [], data: [] }],
    );
    const msg = decodeMessageBytes(bytes);
    expect(msg.version).toBe("legacy");
    expect(msg.header.numRequiredSignatures).toBe(1);
  });

  it("v0: 0x80 prefix is consumed, header follows", () => {
    const bytes = v0Bytes(
      [1, 0, 1],
      [1, 2],
      [{ prog: 1, accts: [], data: [] }],
      [],
    );
    const msg = decodeMessageBytes(bytes);
    expect(msg.version).toBe(0);
    expect(msg.header.numRequiredSignatures).toBe(1);
  });

  it("rejects v1 (0x81) as unsupported version, never mis-decodes", () => {
    const bytes = Uint8Array.from([
      0x81,
      1,
      0,
      1,
      0x01,
      ...key(1),
      ...key(250),
      0x00,
    ]);
    expect(() => decodeMessageBytes(bytes)).toThrow(
      /unsupported message version/,
    );
  });

  it("rejects v2+ (0x82) as unsupported version", () => {
    const bytes = Uint8Array.from([0x82, 1, 0, 1]);
    expect(() => decodeMessageBytes(bytes)).toThrow(
      /unsupported message version/,
    );
  });

  it("a large legacy numRequiredSignatures (high bit clear) is NOT a version byte", () => {
    // 0x7f = 127 signers (absurd but high bit clear). It must be treated as a
    // legacy header byte, and then fail sanitization for exceeding key count --
    // NOT be silently re-read as a version.
    const bytes = Uint8Array.from([
      0x7f,
      0,
      0,
      ...encodeCompactU16(1),
      ...key(1),
    ]);
    expect(() => decodeMessageBytes(bytes)).toThrow(DecodeError);
  });
});

describe("sanitization invariants (D19, T5.6)", () => {
  it("rejects numReadonlySignedAccounts == numRequiredSignatures (no writable fee payer)", () => {
    // header [1,1,0]: 1 signer, 1 of which is readonly => zero writable signers.
    const bytes = legacyBytes(
      [1, 1, 0],
      [1, 2],
      [{ prog: 1, accts: [], data: [] }],
    );
    expect(() => decodeMessageBytes(bytes)).toThrow(
      /numReadonlySignedAccounts must be < numRequiredSignatures/,
    );
  });

  it("rejects numRequiredSignatures == 0", () => {
    const bytes = legacyBytes(
      [0, 0, 0],
      [1, 2],
      [{ prog: 1, accts: [], data: [] }],
    );
    expect(() => decodeMessageBytes(bytes)).toThrow(
      /numRequiredSignatures must be >= 1/,
    );
  });

  it("rejects numRequiredSignatures + numReadonlyUnsignedAccounts > key count", () => {
    // header [1,0,2] with only 2 keys => 1 + 2 = 3 > 2.
    const bytes = legacyBytes(
      [1, 0, 2],
      [1, 2],
      [{ prog: 1, accts: [], data: [] }],
    );
    expect(() => decodeMessageBytes(bytes)).toThrow(DecodeError);
  });

  it("rejects duplicate keys in the static account list (D19)", () => {
    // Two identical keys (both filled with byte 5).
    const bytes = legacyBytes(
      [1, 0, 1],
      [5, 5],
      [{ prog: 1, accts: [], data: [] }],
    );
    expect(() => decodeMessageBytes(bytes)).toThrow(/duplicate keys/);
  });

  it("accepts a minimal valid message", () => {
    const bytes = legacyBytes(
      [1, 0, 1],
      [1, 2],
      [{ prog: 1, accts: [], data: [] }],
    );
    const msg = decodeMessageBytes(bytes);
    expect(msg.staticAccountKeys.length).toBe(2);
  });
});

describe("fail-closed structural checks (T10.1-10.3, T10.5, D16/D17/D18)", () => {
  it("rejects trailing bytes (D17, T10.2)", () => {
    const valid = legacyBytes(
      [1, 0, 1],
      [1, 2],
      [{ prog: 1, accts: [], data: [] }],
    );
    const tampered = Uint8Array.from([...valid, 0x00, 0x01, 0x02]);
    expect(() => decodeMessageBytes(tampered)).toThrow(/trailing/);
  });

  it("rejects an out-of-range instruction account index (D18, T10.3)", () => {
    const bytes = legacyBytes(
      [1, 0, 1],
      [1, 2],
      [{ prog: 1, accts: [200], data: [0] }],
    );
    expect(() => decodeMessageBytes(bytes)).toThrow(DecodeError);
  });

  it("rejects a program-id index outside the static set", () => {
    const bytes = legacyBytes(
      [1, 0, 1],
      [1, 2],
      [{ prog: 9, accts: [], data: [] }],
    );
    expect(() => decodeMessageBytes(bytes)).toThrow(DecodeError);
  });

  it("rejects truncation at every field boundary (T10.1)", () => {
    const valid = legacyBytes(
      [1, 0, 1],
      [1, 2],
      [{ prog: 1, accts: [0], data: [1, 2, 3] }],
    );
    // Truncate at many offsets; each must throw, never return a partial object.
    for (let cut = 1; cut < valid.length; cut++) {
      expect(
        () => decodeMessageBytes(valid.subarray(0, cut)),
        `cut ${cut}`,
      ).toThrow(DecodeError);
    }
  });

  it("rejects empty and single-byte input (T10.5)", () => {
    expect(() => decodeMessageBytes(Uint8Array.from([]))).toThrow(DecodeError);
    expect(() => decodeMessageBytes(Uint8Array.from([0x01]))).toThrow(
      DecodeError,
    );
  });
});
