/**
 * tlv-mint-danger.test.ts -- T_A4: decodeMintDangerExtensions + mintExtensions
 * channel in verdict.
 *
 * Tests decodeMintDangerExtensions() in tlv.ts and the end-to-end path where
 * ctx.mintExtensions causes HOLD findings for permanentDelegate / transferHook.
 *
 * All tests are OFFLINE: no network, synthetic byte buffers only.
 */

import { describe, it, expect } from "vitest";
import { decodeMintDangerExtensions } from "../src/tlv.ts";
import { reviewBase64 } from "../src/verdict.ts";
import { base58Encode } from "../src/decode.ts";
import { legacyBytes, toB64, key } from "./helpers.ts";

// ---------------------------------------------------------------------------
// TLV builder helpers
// ---------------------------------------------------------------------------

/** Write u16 LE into a buffer at offset. */
function writeU16LE(buf: number[], value: number): void {
  buf.push(value & 0xff, (value >> 8) & 0xff);
}

/**
 * Build a synthetic Token-2022 mint account buffer with the given TLV extensions.
 * Layout:
 *   [0..165)  base account data (zeros, at least 165 bytes for Account_type offset)
 *   [165]     account_type byte = 0x01 (Mint)
 *   [166..)   TLV entries: each = u16 type + u16 length + value bytes
 */
function buildMintWithExtensions(
  extensions: Array<{ type: number; value: Uint8Array }>,
): Uint8Array {
  const header = new Array(166).fill(0);
  header[165] = 0x01; // account_type = Mint

  const tlvBytes: number[] = [];
  for (const ext of extensions) {
    writeU16LE(tlvBytes, ext.type);
    writeU16LE(tlvBytes, ext.value.length);
    tlvBytes.push(...Array.from(ext.value));
  }

  return Uint8Array.from([...header, ...tlvBytes]);
}

// ---------------------------------------------------------------------------
// Synthetic pubkeys for tests
// ---------------------------------------------------------------------------

/** A 32-byte key filled with a single byte value. */
function testKey32(byte: number): Uint8Array {
  return new Uint8Array(32).fill(byte);
}

const DELEGATE_BYTES = testKey32(0xdd);
const DELEGATE_B58 = base58Encode(DELEGATE_BYTES);

const HOOK_AUTHORITY_BYTES = testKey32(0xaa);
const HOOK_PROGRAM_BYTES = testKey32(0xbb);
const HOOK_PROGRAM_B58 = base58Encode(HOOK_PROGRAM_BYTES);

const MINT_BYTES = testKey32(0x55);
const MINT_B58 = base58Encode(MINT_BYTES);

// ---------------------------------------------------------------------------
// T_A4.1 — decodeMintDangerExtensions on a mint with PermanentDelegate
// ---------------------------------------------------------------------------

describe("T_A4.1 decodeMintDangerExtensions: PermanentDelegate (type 12)", () => {
  const mint = buildMintWithExtensions([
    { type: 12, value: DELEGATE_BYTES }, // PermanentDelegate: 32-byte pubkey
  ]);

  const result = decodeMintDangerExtensions(mint);

  it("returns permanentDelegate base58 string", () => {
    expect(result.permanentDelegate).toBe(DELEGATE_B58);
  });

  it("does not set transferHook", () => {
    expect(result.transferHook).toBeUndefined();
  });

  it("does not set nonTransferable", () => {
    expect(result.nonTransferable).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// T_A4.2 — decodeMintDangerExtensions on a mint with TransferHook
// ---------------------------------------------------------------------------

describe("T_A4.2 decodeMintDangerExtensions: TransferHook (type 14)", () => {
  // TransferHook value layout: authority(32) + programId(32) = 64 bytes
  const hookValue = Uint8Array.from([
    ...Array.from(HOOK_AUTHORITY_BYTES),
    ...Array.from(HOOK_PROGRAM_BYTES),
  ]);

  const mint = buildMintWithExtensions([
    { type: 14, value: hookValue },
  ]);

  const result = decodeMintDangerExtensions(mint);

  it("returns transferHook programId base58 string", () => {
    expect(result.transferHook).toBe(HOOK_PROGRAM_B58);
  });

  it("does not set permanentDelegate", () => {
    expect(result.permanentDelegate).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// T_A4.3 — decodeMintDangerExtensions on a mint with NonTransferable
// ---------------------------------------------------------------------------

describe("T_A4.3 decodeMintDangerExtensions: NonTransferable (type 9)", () => {
  // NonTransferable has zero-length value (it's a marker extension)
  const mint = buildMintWithExtensions([
    { type: 9, value: new Uint8Array(0) },
  ]);

  const result = decodeMintDangerExtensions(mint);

  it("returns nonTransferable=true", () => {
    expect(result.nonTransferable).toBe(true);
  });

  it("does not set permanentDelegate", () => {
    expect(result.permanentDelegate).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// T_A4.4 — clean mint (no extensions) returns empty result
// ---------------------------------------------------------------------------

describe("T_A4.4 decodeMintDangerExtensions: clean mint returns empty", () => {
  // A plain 82-byte SPL mint (no account_type byte, no TLV)
  const plainMint = new Uint8Array(82);

  it("empty result for plain 82-byte mint", () => {
    const result = decodeMintDangerExtensions(plainMint);
    expect(result.permanentDelegate).toBeUndefined();
    expect(result.transferHook).toBeUndefined();
    expect(result.nonTransferable).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// T_A4.5 — multiple extensions in one mint
// ---------------------------------------------------------------------------

describe("T_A4.5 multiple extensions decoded together", () => {
  const hookValue = Uint8Array.from([
    ...Array.from(HOOK_AUTHORITY_BYTES),
    ...Array.from(HOOK_PROGRAM_BYTES),
  ]);
  const mint = buildMintWithExtensions([
    { type: 12, value: DELEGATE_BYTES },
    { type: 14, value: hookValue },
    { type: 9, value: new Uint8Array(0) },
  ]);

  const result = decodeMintDangerExtensions(mint);

  it("all three danger extensions decoded", () => {
    expect(result.permanentDelegate).toBe(DELEGATE_B58);
    expect(result.transferHook).toBe(HOOK_PROGRAM_B58);
    expect(result.nonTransferable).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// T_A4.6 — end-to-end reviewBase64: mintExtensions with permanentDelegate => HOLD
// ---------------------------------------------------------------------------

describe("T_A4.6 reviewBase64: mintExtensions permanentDelegate -> HOLD finding", () => {
  // Build a simple SPL TokenzQdBN transfer message with a mint account.
  // We embed the mint address as a static key so the verdict can look it up.
  // Token-2022 program id
  const TOKEN_2022 = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";

  /**
   * Build a v0 / legacy message that does a Token-2022 TransferChecked:
   *   ix: prog=TOKEN_2022, accounts=[source, mint, dest, authority], data=[12, amount(8), 6(dec)]
   * Static keys: [feePayer, TOKEN_2022, sourceATA, mintAddr, destATA]
   */
  function buildTransferCheckedMsg(): Uint8Array {
    // We need a real base58 decode of TOKEN_2022 for the key slot.
    // Use legacyBytes helper with a key spec.
    // Header: 1 signer (fee payer), 0 readonly signed, 2 readonly unsigned
    // Keys: [feePayer(key(1)), TOKEN_2022 program, sourceATA(key(2)), MINT(key(0x55)), destATA(key(3))]
    // But legacyBytes only takes fill bytes for keys, not real pubkeys.
    // We'll hand-build the message bytes directly.

    // base58 decode helper (copy from verdict.test.ts pattern)
    function b58ToBytes(b58: string): Uint8Array {
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

    const token2022Bytes = b58ToBytes(TOKEN_2022);
    const out: number[] = [];
    // Legacy message: header [1, 0, 2], 5 keys
    // S=1, Rs=0, Ru=2 => idx0 writable signer (feePayer), idx1 writable non-signer,
    //   idx2 writable non-signer, idx3 readonly, idx4 readonly
    out.push(1, 0, 2);
    out.push(5); // 5 static keys
    out.push(...Array.from(testKey32(1)));              // idx0: feePayer (signer-writable)
    out.push(...Array.from(testKey32(2)));              // idx1: sourceATA (writable)
    out.push(...Array.from(testKey32(3)));              // idx2: destATA (writable)
    out.push(...Array.from(MINT_BYTES));                // idx3: mint (readonly)
    out.push(...Array.from(token2022Bytes));            // idx4: TOKEN_2022 program (readonly)
    out.push(...Array.from(testKey32(250)));            // blockhash
    out.push(1); // 1 instruction
    // TransferChecked: prog=idx4(TOKEN_2022), accounts=[source=1, mint=3, dest=2, auth=0]
    out.push(4);  // programIdIndex = 4
    out.push(4);  // 4 account indexes
    out.push(1, 3, 2, 0); // [source, mint, dest, authority]
    // data: [disc=12][amount u64 LE = 1000][decimals=6]  = 10 bytes
    const amount = 1000n;
    const amountBytes: number[] = [];
    let v = amount;
    for (let i = 0; i < 8; i++) { amountBytes.push(Number(v & 0xffn)); v >>= 8n; }
    out.push(10); // data length
    out.push(12, ...amountBytes, 6);

    return Uint8Array.from(out);
  }

  const b64 = toB64(buildTransferCheckedMsg());

  it("without mintExtensions, no extra HOLD finding (base behavior)", () => {
    const v = reviewBase64(b64);
    const hasToken2022Finding = v.findings.some(
      (f) => f.id === "token2022-permanent-delegate" || f.id === "token2022-transfer-hook",
    );
    expect(hasToken2022Finding).toBe(false);
  });

  it("with mintExtensions permanentDelegate for the mint -> HOLD finding present", () => {
    const mintExtensions = new Map([
      [MINT_B58, { permanentDelegate: DELEGATE_B58 }],
    ]);
    const v = reviewBase64(b64, {
      lamportThreshold: 1_000_000_000,
      mintExtensions,
    });
    const f = v.findings.find((f) => f.id === "token2022-permanent-delegate");
    expect(f).toBeDefined();
    expect(f!.severity).toBe("HOLD");
    expect(f!.detail).toContain("permanent");
    expect(v.decision).toBe("HOLD");
  });

  it("with mintExtensions transferHook for the mint -> HOLD finding present", () => {
    const mintExtensions = new Map([
      [MINT_B58, { transferHook: HOOK_PROGRAM_B58 }],
    ]);
    const v = reviewBase64(b64, {
      lamportThreshold: 1_000_000_000,
      mintExtensions,
    });
    const f = v.findings.find((f) => f.id === "token2022-transfer-hook");
    expect(f).toBeDefined();
    expect(f!.severity).toBe("HOLD");
    expect(f!.detail).toContain("transfer hook");
    expect(v.decision).toBe("HOLD");
  });

  it("mintExtensions for a DIFFERENT mint -> no extra finding (unrelated mint)", () => {
    const otherMint = base58Encode(testKey32(0xff));
    const mintExtensions = new Map([
      [otherMint, { permanentDelegate: DELEGATE_B58 }],
    ]);
    const v = reviewBase64(b64, {
      lamportThreshold: 1_000_000_000,
      mintExtensions,
    });
    const f = v.findings.find((f) => f.id === "token2022-permanent-delegate");
    expect(f).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// T_A4.7 — FIX 1: OptionalNonZeroPubkey — all-zero means None
// ---------------------------------------------------------------------------

describe("T_A4.7 decodeMintDangerExtensions: OptionalNonZeroPubkey None handling", () => {
  const ZERO_32 = new Uint8Array(32).fill(0);

  it("PermanentDelegate with all-zero delegate -> permanentDelegate is undefined (None)", () => {
    // An all-zero 32-byte pubkey means None for OptionalNonZeroPubkey.
    // A mint with this extension set but delegate == None must NOT set permanentDelegate.
    const mint = buildMintWithExtensions([
      { type: 12, value: ZERO_32 },
    ]);
    const result = decodeMintDangerExtensions(mint);
    expect(result.permanentDelegate).toBeUndefined();
  });

  it("PermanentDelegate with non-zero delegate -> permanentDelegate is still set (regression)", () => {
    // Sanity check: a real delegate must still surface.
    const mint = buildMintWithExtensions([
      { type: 12, value: DELEGATE_BYTES },
    ]);
    const result = decodeMintDangerExtensions(mint);
    expect(result.permanentDelegate).toBe(DELEGATE_B58);
  });

  it("TransferHook with all-zero programId -> transferHook is undefined (None = no active hook)", () => {
    // authority(32) non-zero, programId(32) all-zero => hook not active.
    const hookValue = Uint8Array.from([
      ...Array.from(HOOK_AUTHORITY_BYTES), // authority = non-zero (irrelevant)
      ...Array.from(ZERO_32),              // programId = all-zero => None
    ]);
    const mint = buildMintWithExtensions([
      { type: 14, value: hookValue },
    ]);
    const result = decodeMintDangerExtensions(mint);
    expect(result.transferHook).toBeUndefined();
  });

  it("TransferHook with non-zero programId -> transferHook is set (regression)", () => {
    // A real hook program must still surface.
    const hookValue = Uint8Array.from([
      ...Array.from(HOOK_AUTHORITY_BYTES),
      ...Array.from(HOOK_PROGRAM_BYTES),
    ]);
    const mint = buildMintWithExtensions([
      { type: 14, value: hookValue },
    ]);
    const result = decodeMintDangerExtensions(mint);
    expect(result.transferHook).toBe(HOOK_PROGRAM_B58);
  });

  it("NonTransferable is unchanged by None logic (marker presence is enough)", () => {
    // NonTransferable has zero-length value — it remains true regardless.
    const mint = buildMintWithExtensions([
      { type: 9, value: new Uint8Array(0) },
    ]);
    const result = decodeMintDangerExtensions(mint);
    expect(result.nonTransferable).toBe(true);
  });
});
