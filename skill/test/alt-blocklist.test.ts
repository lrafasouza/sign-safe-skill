/**
 * alt-blocklist.test.ts -- SECURITY: ALT-resolved recipients must be screened
 * against blocklist (bug fix for v0.4 gap).
 *
 * BUG REPRO (failing before fix):
 *   When a transfer recipient is in an ALT (v0 message) and `resolvedAltTables`
 *   resolves it to a real address, the old code returned `address:null` from
 *   `resolveRecipient` and `collectScreenCandidates` never saw the real address.
 *   Result: blocklist screening silently SKIPPED the ALT recipient → SIGN when
 *   it should be REJECT ("blocklisted-recipient").
 *
 * INVARIANT:
 *   An address treated as `addressVerified=true` in the SIGN gate MUST be
 *   simultaneously visible to outflow recipient resolution AND blocklist
 *   screening. Never allow one without the other.
 *
 * OFFLINE: no network; synthetic v0 byte buffers only.
 */

import { describe, it, expect } from "vitest";
import { reviewBase64 } from "../src/verdict.ts";
import { base58Encode } from "../src/decode.ts";
import { v0Bytes, toB64, key, u64le, u32le } from "./helpers.ts";

// ---------------------------------------------------------------------------
// Address constants (deterministic fill-byte keys)
// ---------------------------------------------------------------------------

/** A 32-byte key filled with a single byte, as Uint8Array. */
function testKey32(byte: number): Uint8Array {
  return new Uint8Array(32).fill(byte);
}

// Static keys
const SIGNER_B = 0x01; // fee payer / signer
const SYSTEM_B = 0x00; // System Program (all-zeros)
const SPL_TOKEN_B = 0xaa; // placeholder for SPL Token program id
const SOURCE_TOKEN_ACCT_B = 0x04; // SPL token source account
const AUTHORITY_B = 0x05; // SPL token authority (same as signer)

// ALT table
const TABLE_B = 0x50;
const TABLE_B58 = base58Encode(testKey32(TABLE_B));

// Bad address (on blocklist)
const BAD_B = 0xba;
const BAD_B58 = base58Encode(testKey32(BAD_B));

// Good address (not on blocklist)
const GOOD_B = 0x99;
const GOOD_B58 = base58Encode(testKey32(GOOD_B));

// ALT slot 0 → BAD address (the drainer)
// ALT slot 1 → GOOD address (benign control)

const RESOLVED_BAD = new Map<string, readonly string[]>([
  [TABLE_B58, [BAD_B58, GOOD_B58]],
]);
const RESOLVED_GOOD = new Map<string, readonly string[]>([
  [TABLE_B58, [GOOD_B58, GOOD_B58]],
]);
// Unresolved (empty map — fail-closed, ALT slots have no address)
const UNRESOLVED = new Map<string, readonly string[]>();

// Real program ids as bytes
const SYSTEM_BYTES = new Uint8Array(32).fill(0); // 11111111... (all zeros)
// SPL Token program id as bytes (for embedding as a static key)
// We embed it as a fill-byte for simplicity; actual discriminator detection
// only needs the program id in the static key list.
// However, our classify relies on ix.programId matching the real string.
// So we embed the actual SPL Token id.
function base58ToBytes(b58: string): number[] {
  const ALPHA = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  const m: Record<string, number> = {};
  for (let i = 0; i < ALPHA.length; i++) m[ALPHA[i]!] = i;
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
  const out = new Array<number>(32).fill(0);
  const body = bytes.reverse();
  const off = 32 - body.length - lz;
  for (let i = 0; i < body.length; i++) out[off + i] = body[i]!;
  return out;
}

const SPL_TOKEN_PID = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const SPL_TOKEN_PID_BYTES = base58ToBytes(SPL_TOKEN_PID);

// ---------------------------------------------------------------------------
// Message builders
// ---------------------------------------------------------------------------

/**
 * Build a v0 message containing a single System Transfer (tag=2) where:
 *   - funding account (from) = static key index 0 (signer)
 *   - recipient (to) = ALT slot 0 (combined index = numStaticKeys + 0)
 *
 * Static keys: [signer(0x01), system-program(all-zeros)]
 *   Index 0 = signer (0x01)
 *   Index 1 = System Program (all-zeros)
 * ALT: table=TABLE_B, writable=[0] → combined index 2
 *
 * System Transfer instruction:
 *   programIdIndex = 1 (System Program at static key index 1)
 *   accounts = [0 (signer/from), 2 (ALT slot 0, to)]
 *   data = [u32le(2), u64le(lamports)]
 */
function buildSolTransferToAlt(lamports = 100_000_000n): Uint8Array {
  const SYSTEM_TAG = [...u32le(2)]; // tag=2 (Transfer)
  const AMT = [...u64le(lamports)];
  const data = [...SYSTEM_TAG, ...AMT];

  // Static keys: [signer(0x01), system-program(all-zeros)]
  // We use a custom approach: embed the keys manually since legacyBytes uses
  // fill-byte shortcuts. We'll use v0Bytes with a special keyBytes approach.
  //
  // v0Bytes takes header, keyBytes (fill-byte array), ixs, luts.
  // keyBytes=[0x01, 0x00] → key(0x01)=signer, key(0x00)=system-program
  // system program is all-zeros which IS key(0x00). ✓
  //
  // ALT combined index for ALT writable slot 0 = 2 (= 2 static keys + 0)
  return v0Bytes(
    [1, 0, 1], // 1 signer, 0 readonly signed, 1 readonly unsigned (system prog)
    [SIGNER_B, 0x00], // key(0x01)=signer, key(0x00)=system program
    [
      {
        prog: 1, // system program at static index 1
        accts: [0, 2], // from=index0(signer), to=index2(ALT slot 0)
        data,
      },
    ],
    [{ table: TABLE_B, writable: [0], readonly: [] }],
  );
}

/**
 * Build a v0 message containing a SPL Token Transfer (disc=3) where:
 *   - source token account = static key index 0 (fee payer area, signer)
 *   - destination token account = ALT slot 0 (combined index = numStaticKeys + 0)
 *   - authority = static key index 1 (signer)
 *   - SPL Token program = static key index 2
 *
 * Static keys: [source(0x04), authority(0x05), spl-token-pid]
 * Header: [2 signers, 0 readonly signed, 0 readonly unsigned]
 *   Index 0 = source (signer-writable)
 *   Index 1 = authority (signer-writable)
 *   Index 2 = SPL Token program (demoted: called as program)
 * ALT: writable=[0] → combined index 3
 *
 * SPL Transfer instruction:
 *   programIdIndex = 2 (SPL Token)
 *   accounts = [0(source), 3(ALT dest), 1(authority)]
 *   data = [u8(3), u64le(amount)]
 */
function buildSplTransferToAlt(amount = 1_000_000n): Uint8Array {
  const data = [3, ...u64le(amount)]; // disc=3 (Transfer), amount

  // We need to embed the real SPL Token program id as a static key.
  // v0Bytes builds keys using key(byte) = 32 bytes filled with `byte`.
  // We cannot use fill-byte for the SPL Token pid. Instead, we build manually.

  // Manual v0 construction so we can embed the real program id.
  // Header + version prefix
  const out: number[] = [];
  out.push(0x80); // v0 prefix
  // header: [numRequiredSignatures=2, numReadonlySigned=0, numReadonlyUnsigned=0]
  out.push(2, 0, 0);
  // compact-u16 for 3 static keys
  out.push(3);
  // key 0: source token account (0x04 fill)
  for (let i = 0; i < 32; i++) out.push(SOURCE_TOKEN_ACCT_B);
  // key 1: authority (0x05 fill, signer)
  for (let i = 0; i < 32; i++) out.push(AUTHORITY_B);
  // key 2: SPL Token program
  out.push(...SPL_TOKEN_PID_BYTES);
  // blockhash (32 bytes fill 0xfa)
  for (let i = 0; i < 32; i++) out.push(0xfa);
  // 1 instruction
  out.push(1);
  // ix: programIdIndex=2, accounts=[0, 3, 1], data=[3, ...u64]
  out.push(2); // programIdIndex
  out.push(3); // 3 accounts
  out.push(0, 3, 1); // source=0, dest=3(ALT slot 0), auth=1
  out.push(9); // data length = 9 bytes
  out.push(...data);
  // 1 ALT lookup
  out.push(1);
  // ALT key: TABLE_B fill
  for (let i = 0; i < 32; i++) out.push(TABLE_B);
  // writable: [0]
  out.push(1); // 1 writable index
  out.push(0);
  // readonly: none
  out.push(0);

  return Uint8Array.from(out);
}

/**
 * Build a v0 message with SPL Approve (disc=4) where the delegate is in an ALT.
 *   Static keys: [source(0x04), owner/signer(0x05), spl-token-pid]
 *   ALT: writable=[0] → combined index 3 = delegate
 *
 * SPL Approve (disc=4):
 *   accounts=[0(source), 3(delegate=ALT slot 0), 1(owner)]
 *   data=[u8(4), u64le(amount)]
 */
function buildSplApproveWithAltDelegate(amount = 999_000n): Uint8Array {
  const data = [4, ...u64le(amount)]; // disc=4 (Approve), amount

  const out: number[] = [];
  out.push(0x80); // v0
  out.push(2, 0, 0); // 2 signers
  out.push(3); // 3 static keys
  for (let i = 0; i < 32; i++) out.push(SOURCE_TOKEN_ACCT_B); // key 0: source
  for (let i = 0; i < 32; i++) out.push(AUTHORITY_B); // key 1: owner/signer
  out.push(...SPL_TOKEN_PID_BYTES); // key 2: SPL Token program
  for (let i = 0; i < 32; i++) out.push(0xfa); // blockhash
  out.push(1); // 1 instruction
  // ix: programIdIndex=2, accounts=[0(source), 3(delegate/ALT), 1(owner)]
  out.push(2); // programIdIndex
  out.push(3); // 3 accounts
  out.push(0, 3, 1);
  out.push(data.length);
  out.push(...data);
  // 1 ALT
  out.push(1);
  for (let i = 0; i < 32; i++) out.push(TABLE_B);
  out.push(1); out.push(0); // 1 writable index = [0]
  out.push(0); // 0 readonly indexes
  return Uint8Array.from(out);
}

// ---------------------------------------------------------------------------
// T_ALT_BLOCK.1 -- SOL Transfer to ALT-resolved BAD address → REJECT
// ---------------------------------------------------------------------------

describe("T_ALT_BLOCK.1 SOL transfer to ALT-resolved blocklisted recipient → REJECT", () => {
  const bytes = buildSolTransferToAlt(100_000_000n);
  const b64 = toB64(bytes);
  const blocklist = [BAD_B58];

  it("BUG REPRO: with BAD resolved + blocklist → REJECT (was SIGN before fix)", () => {
    const v = reviewBase64(b64, {
      lamportThreshold: 1_000_000_000,
      resolvedAltTables: RESOLVED_BAD,
      recipientBlocklist: blocklist,
    });
    expect(v.decision).toBe("REJECT");
    const f = v.findings.find((f) => f.id === "blocklisted-recipient");
    expect(f).toBeDefined();
    expect(f?.severity).toBe("REJECT");
  });

  it("control: BAD address not on blocklist → not REJECT for blocklist", () => {
    const v = reviewBase64(b64, {
      lamportThreshold: 1_000_000_000,
      resolvedAltTables: RESOLVED_BAD,
      recipientBlocklist: [], // empty blocklist
    });
    // Should SIGN (resolved, no finding) or HOLD for other reasons, not blocklist-REJECT
    expect(v.findings.filter((f) => f.id === "blocklisted-recipient")).toHaveLength(0);
    // With fully resolved ALT + no danger + below threshold → SIGN
    expect(v.decision).toBe("SIGN");
  });

  it("control: GOOD address on resolved ALT → not REJECT for blocklist", () => {
    const v = reviewBase64(b64, {
      lamportThreshold: 1_000_000_000,
      resolvedAltTables: RESOLVED_GOOD,
      recipientBlocklist: blocklist,
    });
    expect(v.findings.filter((f) => f.id === "blocklisted-recipient")).toHaveLength(0);
    expect(v.decision).toBe("SIGN");
  });

  it("control: ALT unresolved (no resolvedAltTables) → HOLD (fail-closed, not SIGN, not spurious REJECT)", () => {
    const v = reviewBase64(b64, {
      lamportThreshold: 1_000_000_000,
      resolvedAltTables: UNRESOLVED,
      recipientBlocklist: blocklist,
    });
    // Unresolved ALT → HOLD (rolesUnverified), not SIGN, no blocklist REJECT
    expect(v.decision).toBe("HOLD");
    expect(v.flags.rolesUnverified).toBe(true);
    expect(v.findings.filter((f) => f.id === "blocklisted-recipient")).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// T_ALT_BLOCK.2 -- SPL Token Transfer to ALT-resolved BAD address → REJECT
// ---------------------------------------------------------------------------

describe("T_ALT_BLOCK.2 SPL token transfer to ALT-resolved blocklisted destination → REJECT", () => {
  const bytes = buildSplTransferToAlt(500_000n);
  const b64 = toB64(bytes);
  const blocklist = [BAD_B58];

  it("BUG REPRO: with BAD resolved + blocklist → REJECT (was SIGN before fix)", () => {
    const v = reviewBase64(b64, {
      lamportThreshold: 1_000_000_000,
      resolvedAltTables: RESOLVED_BAD,
      recipientBlocklist: blocklist,
    });
    expect(v.decision).toBe("REJECT");
    const f = v.findings.find((f) => f.id === "blocklisted-recipient");
    expect(f).toBeDefined();
    expect(f?.severity).toBe("REJECT");
  });

  it("control: GOOD address resolved, BAD on blocklist → no blocklist REJECT", () => {
    const v = reviewBase64(b64, {
      lamportThreshold: 1_000_000_000,
      resolvedAltTables: RESOLVED_GOOD,
      recipientBlocklist: blocklist,
    });
    expect(v.findings.filter((f) => f.id === "blocklisted-recipient")).toHaveLength(0);
    expect(v.decision).toBe("SIGN");
  });

  it("control: ALT unresolved → HOLD (fail-closed)", () => {
    const v = reviewBase64(b64, {
      lamportThreshold: 1_000_000_000,
      resolvedAltTables: UNRESOLVED,
      recipientBlocklist: blocklist,
    });
    expect(v.decision).toBe("HOLD");
    expect(v.flags.rolesUnverified).toBe(true);
    expect(v.findings.filter((f) => f.id === "blocklisted-recipient")).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// T_ALT_BLOCK.3 -- SPL Approve delegate in ALT → REJECT when blocklisted
// ---------------------------------------------------------------------------

describe("T_ALT_BLOCK.3 SPL Approve delegate in ALT, resolved to blocklisted address → REJECT", () => {
  const bytes = buildSplApproveWithAltDelegate();
  const b64 = toB64(bytes);
  const blocklist = [BAD_B58];

  it("BUG REPRO: delegate in ALT resolved to BAD + blocklist → REJECT (covers collectScreenCandidates)", () => {
    const v = reviewBase64(b64, {
      lamportThreshold: 1_000_000_000,
      resolvedAltTables: RESOLVED_BAD,
      recipientBlocklist: blocklist,
    });
    expect(v.decision).toBe("REJECT");
    const f = v.findings.find((f) => f.id === "blocklisted-recipient");
    expect(f).toBeDefined();
    expect(f?.severity).toBe("REJECT");
  });

  it("control: GOOD address → no blocklist REJECT", () => {
    const v = reviewBase64(b64, {
      lamportThreshold: 1_000_000_000,
      resolvedAltTables: RESOLVED_GOOD,
      recipientBlocklist: blocklist,
    });
    expect(v.findings.filter((f) => f.id === "blocklisted-recipient")).toHaveLength(0);
  });

  it("control: unresolved ALT → HOLD, no spurious blocklist REJECT", () => {
    const v = reviewBase64(b64, {
      lamportThreshold: 1_000_000_000,
      resolvedAltTables: UNRESOLVED,
      recipientBlocklist: blocklist,
    });
    expect(v.decision).toBe("HOLD");
    expect(v.findings.filter((f) => f.id === "blocklisted-recipient")).toHaveLength(0);
  });
});
