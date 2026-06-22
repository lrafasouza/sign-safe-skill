/**
 * classify.test.ts -- instruction classification invariants (section C / V4-V5).
 * T6.1 Transfer vs TransferChecked, T6.2 SetAuthority None vs Some, T6.3 invalid
 * AuthorityType on Tokenkeg, T6.4 TLV PermanentDelegate on a plain Transfer,
 * T7.2 loader Upgrade CRITICAL, T7.4/7.5 ComputeBudget benign, T7.6 routing by
 * program id, plus the new catalog primitives (Close/SetAuthorityChecked/Assign).
 */

import { describe, it, expect } from "vitest";
import { decodeMessageBytes, base58Encode } from "../src/decode.ts";
import { deriveRoles, RESERVED_ACCOUNT_KEYS } from "../src/roles.ts";
import { classify } from "../src/classify.ts";
import { computeOutflow } from "../src/outflow.ts";
import { walkTlv } from "../src/tlv.ts";
import { DEFAULT_CONTEXT } from "../src/types.ts";
import { legacyBytes, u32le, u64le, key } from "./helpers.ts";

const SPL_TOKEN = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const TOKEN_2022 = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";
const BPF_LOADER = "BPFLoaderUpgradeab1e11111111111111111111111";
const COMPUTE_BUDGET = "ComputeBudget111111111111111111111111111111";

/** Decode a message and classify it with the runtime reserved set. */
function review(bytes: Uint8Array) {
  const msg = decodeMessageBytes(bytes);
  const roles = deriveRoles(msg, { reservedAccountKeys: RESERVED_ACCOUNT_KEYS });
  const cls = classify(msg, roles, DEFAULT_CONTEXT);
  const outflow = computeOutflow(msg, roles, DEFAULT_CONTEXT);
  return { msg, roles, cls, outflow };
}

/**
 * Build a legacy message with a single instruction whose program id is the
 * given base58 program key, placed as a static key. Layout: idx0 fee payer,
 * idx1 program, plus extra accounts as needed. Returns the raw bytes.
 */
function singleIxMessage(programId: string, data: number[], extraAccts = 0): Uint8Array {
  const progKeyBytes = base58ToBytes(programId);
  const out: number[] = [];
  // header: 1 signer, 0 readonly-signed, (1 + extraAccts) readonly-unsigned.
  const numKeys = 2 + extraAccts;
  out.push(1, 0, 1 + extraAccts);
  out.push(numKeys);
  out.push(...key(1)); // idx0 fee payer
  out.push(...progKeyBytes); // idx1 program
  for (let i = 0; i < extraAccts; i++) out.push(...key(100 + i)); // extra readonly
  out.push(...key(250)); // blockhash
  out.push(1); // 1 instruction
  out.push(1); // programIdIndex = 1
  out.push(0); // 0 accounts for simplicity
  out.push(data.length);
  out.push(...data);
  return Uint8Array.from(out);
}

describe("T6.1 Transfer vs TransferChecked (C3)", () => {
  it("SPL Transfer (disc 3, 9 bytes) reads amount 1,000,000 at offset 1", () => {
    const data = [3, ...u64le(1_000_000n)];
    expect(data.length).toBe(9);
    const { outflow } = review(singleIxMessage(SPL_TOKEN, data));
    expect(outflow.splTransfers.length).toBe(1);
    expect(outflow.splTransfers[0]!.amount).toBe("1000000");
    expect(outflow.splTransfers[0]!.decimals).toBeUndefined();
  });

  it("SPL TransferChecked (disc 12, 10 bytes) reads amount + decimals 6", () => {
    const data = [12, ...u64le(1_000_000n), 6];
    expect(data.length).toBe(10);
    const { outflow } = review(singleIxMessage(SPL_TOKEN, data));
    expect(outflow.splTransfers.length).toBe(1);
    expect(outflow.splTransfers[0]!.amount).toBe("1000000");
    expect(outflow.splTransfers[0]!.decimals).toBe(6);
  });

  it("a 9-byte payload under disc 12 is NOT accepted as TransferChecked", () => {
    // disc 12 with only 9 bytes is malformed (needs 10); must not be counted.
    const data = [12, ...u64le(1_000_000n)];
    const { outflow } = review(singleIxMessage(SPL_TOKEN, data));
    expect(outflow.splTransfers.length).toBe(0);
  });
});

describe("T6.2 / T6.3 SetAuthority None vs Some + invalid type (C4/C5)", () => {
  it("SetAuthority Some (AccountOwner=2) surfaces the new authority", () => {
    const newAuth = key(7);
    const data = [6, 2, 1, ...newAuth]; // 35 bytes
    expect(data.length).toBe(35);
    const { cls } = review(singleIxMessage(SPL_TOKEN, data));
    const f = cls.findings.find((x) => x.id === "spl-set-authority");
    expect(f).toBeTruthy();
    expect(f!.severity).toBe("REJECT");
    expect(f!.detail).toContain("AccountOwner");
    expect(f!.detail).toContain(base58Encode(Uint8Array.from(newAuth)));
  });

  it("SetAuthority None (disable mint authority) shows cleared", () => {
    const data = [6, 0, 0]; // 3 bytes, MintTokens, None
    const { cls } = review(singleIxMessage(SPL_TOKEN, data));
    const f = cls.findings.find((x) => x.id === "spl-set-authority");
    expect(f).toBeTruthy();
    expect(f!.detail).toContain("MintTokens");
    expect(f!.detail).toContain("cleared (None)");
  });

  it("AuthorityType 8 (PermanentDelegate) on classic SPL Token is flagged INVALID", () => {
    const data = [6, 8, 1, ...key(7)];
    const { cls } = review(singleIxMessage(SPL_TOKEN, data));
    const f = cls.findings.find((x) => x.id === "spl-set-authority");
    expect(f!.detail).toContain("INVALID on classic SPL Token");
    expect(f!.detail).toContain("PermanentDelegate");
  });

  it("Token-2022 SetAuthority Some(PermanentDelegate=8) is valid (not flagged invalid)", () => {
    const data = [6, 8, 1, ...key(7)];
    const { cls } = review(singleIxMessage(TOKEN_2022, data));
    const f = cls.findings.find((x) => x.id === "token2022-set-authority");
    expect(f!.detail).toContain("PermanentDelegate");
    expect(f!.detail).not.toContain("INVALID");
  });
});

describe("T6.4 / T6.5 / T6.6 TLV walk (C9/C10/V5)", () => {
  it("PermanentDelegate (ext 12) is surfaced from a Token-2022 mint TLV", () => {
    // 210-byte buffer: account_type 0x01 (mint) @165; TLV @166: type=12 len=32.
    // (166 + 4 header + 32 value = 202 <= 210.)
    const data = new Uint8Array(210);
    data[165] = 0x01;
    // entry: type 12 (LE), length 32 (LE), 32-byte value
    data[166] = 12;
    data[167] = 0;
    data[168] = 32;
    data[169] = 0;
    const res = walkTlv(data);
    expect(res.accountType).toBe("mint");
    expect(res.entries.some((e) => e.extensionType === 12)).toBe(true);
    expect(res.dangerous.some((d) => d.extensionType === 12)).toBe(true);
    expect(res.dangerous[0]!.note).toContain("PermanentDelegate");
  });

  it("walks ALL TLV entries, not just the first (T6.5)", () => {
    const data = new Uint8Array(300);
    data[165] = 0x01;
    let o = 166;
    // entry 1: TransferHook (14), len 64
    data[o++] = 14; data[o++] = 0; data[o++] = 64; data[o++] = 0; o += 64;
    // entry 2: TransferFeeConfig (1), len 8
    data[o++] = 1; data[o++] = 0; data[o++] = 8; data[o++] = 0; o += 8;
    const res = walkTlv(data);
    const types = res.entries.map((e) => e.extensionType);
    expect(types).toContain(14);
    expect(types).toContain(1);
    expect(res.dangerous.map((d) => d.extensionType).sort()).toEqual([1, 14]);
  });

  it("a base-length (82 mint / 165 account) buffer has NO TLV and is not over-read (T6.6)", () => {
    expect(walkTlv(new Uint8Array(82))).toEqual({ accountType: "none", entries: [], dangerous: [] });
    expect(walkTlv(new Uint8Array(165))).toEqual({ accountType: "none", entries: [], dangerous: [] });
  });

  it("fail-closed on a TLV length that runs past the buffer", () => {
    const data = new Uint8Array(180);
    data[165] = 0x01;
    data[166] = 12; data[167] = 0; data[168] = 0xff; data[169] = 0xff; // length 65535
    expect(() => walkTlv(data)).toThrow(/runs past buffer/);
  });

  it("unknown ExtensionType is labelled unknown, not crashed (T6.7)", () => {
    const data = new Uint8Array(200);
    data[165] = 0x01;
    data[166] = 99; data[167] = 0; data[168] = 0; data[169] = 0;
    const res = walkTlv(data);
    expect(res.entries[0]!.name).toContain("unknown(99)");
  });
});

describe("T7.2 loader Upgrade + new BPF/System primitives (C15/V4)", () => {
  it("BPF Loader Upgrade (tag 3 u32-LE) is REJECT", () => {
    const { cls } = review(singleIxMessage(BPF_LOADER, u32le(3)));
    const f = cls.findings.find((x) => x.id === "bpf-upgrade");
    expect(f!.severity).toBe("REJECT");
  });

  it("BPF Loader Close (tag 5) is REJECT", () => {
    const { cls } = review(singleIxMessage(BPF_LOADER, u32le(5)));
    expect(cls.findings.find((x) => x.id === "bpf-close")!.severity).toBe("REJECT");
  });

  it("BPF Loader SetAuthorityChecked (tag 7) is REJECT", () => {
    const { cls } = review(singleIxMessage(BPF_LOADER, u32le(7)));
    expect(cls.findings.find((x) => x.id === "bpf-set-upgrade-authority-checked")!.severity).toBe("REJECT");
  });

  it("System Assign (tag 1) ownership change is REJECT", () => {
    const { cls } = review(singleIxMessage("11111111111111111111111111111111", u32le(1)));
    expect(cls.findings.find((x) => x.id === "system-assign")!.severity).toBe("REJECT");
    expect(cls.authorityOrOwnershipChange).toBe(true);
  });

  it("System AssignWithSeed (tag 10) is REJECT", () => {
    const { cls } = review(singleIxMessage("11111111111111111111111111111111", u32le(10)));
    expect(cls.findings.find((x) => x.id === "system-assign-with-seed")!.severity).toBe("REJECT");
  });
});

describe("T7.4 / T7.5 / T7.6 ComputeBudget benign + routing-by-program-id (C0/C16)", () => {
  it("ComputeBudget SetCUPrice (u8 tag 3, u64) is benign -- no finding", () => {
    const data = [3, ...u64le(1000n)]; // borsh u8 tag 3 + u64 micro-lamports
    const { cls } = review(singleIxMessage(COMPUTE_BUDGET, data));
    expect(cls.findings.length).toBe(0);
    expect(cls.unknownPrograms.length).toBe(0);
  });

  it("ComputeBudget SetCULimit (u8 tag 2, u32) is benign", () => {
    const data = [2, ...u32le(200_000)];
    const { cls } = review(singleIxMessage(COMPUTE_BUDGET, data));
    expect(cls.findings.length).toBe(0);
  });

  it("bytes `02 00 00 00 ...` are System Transfer under System but benign under ComputeBudget (C0)", () => {
    const transferData = [...u32le(2), ...u64le(2_000_000_000n)]; // 2 SOL
    // Under System: a large transfer above the 1 SOL threshold => HOLD finding.
    const sys = review(singleIxMessage("11111111111111111111111111111111", transferData, 1));
    // Need account[0] to be the signer for outflow; but classify large-transfer
    // is independent of outflow. Just assert the large-transfer finding fires.
    expect(sys.cls.findings.some((f) => f.id === "system-large-transfer")).toBe(true);

    // Under ComputeBudget: the SAME bytes are a borsh u8 tag 2 (SetCULimit) and
    // must NOT be read as a u32-LE System Transfer. No danger finding.
    const cb = review(singleIxMessage(COMPUTE_BUDGET, transferData));
    expect(cb.cls.findings.length).toBe(0);
  });

  it("a crafted [2,1,0,0] under System is NOT a clean Transfer(2) (u32 strictness)", () => {
    const data = [2, 1, 0, 0, ...u64le(5_000_000_000n)];
    const { cls, outflow } = review(singleIxMessage("11111111111111111111111111111111", data, 1));
    expect(cls.findings.some((f) => f.id === "system-large-transfer")).toBe(false);
    expect(outflow.lamports).toBe("0");
  });
});

// ---- base58 decode for embedding program ids in synthetic keys -------------

function base58ToBytes(b58: string): Uint8Array {
  const ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  const map: Record<string, number> = {};
  for (let i = 0; i < ALPHABET.length; i++) map[ALPHABET[i]!] = i;
  let bytes: number[] = [];
  for (const ch of b58) {
    let carry = map[ch]!;
    for (let j = 0; j < bytes.length; j++) {
      carry += bytes[j]! * 58;
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
  const out = new Uint8Array(32);
  const body = bytes.reverse();
  const offset = 32 - body.length - leadingZeros;
  for (let i = 0; i < body.length; i++) out[offset + i] = body[i]!;
  return out;
}
