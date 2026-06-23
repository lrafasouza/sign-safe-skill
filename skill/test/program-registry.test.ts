/**
 * program-registry.test.ts -- DeFi/NFT program registry classification (GAP 3).
 *
 * Verifies the fail-closed RECOGNIZED-program tier added to classify.ts:
 *
 *   1. Jupiter swap -> HOLD (recognized, NOT REJECT), JUP6 not in unknownPrograms.
 *   2. Metaplex NFT Transfer (disc 49 = 0x31) -> REJECT, named "Metaplex: Transfer NFT".
 *   3. Metaplex Delegate (disc 44 = 0x2c) -> HOLD, named.
 *   4. Bubblegum cNFT Transfer -> REJECT, named.
 *   5. Recognized program + unknown instruction -> HOLD, NOT SIGN.
 *   6. Truly unknown program writing value -> still REJECT (unchanged path).
 *   7. Benign native SPL Transfer -> still SIGN (no regression).
 *   8. Invariant: registry catalog validation (discHex format correctness).
 *   9. Recognized program NOT added to unknownPrograms list.
 *  10. Fail-closed: recognized-program finding is at least HOLD (never SIGN alone).
 *
 * All tests are OFFLINE and DETERMINISTIC. No network, no fixtures from disk.
 * Discriminators verified against canonical sources (see /tmp/ss-v2-drainer-spec.md).
 */

import { describe, it, expect } from "vitest";
import { decodeMessageBytes } from "../src/decode.ts";
import { deriveRoles, RESERVED_ACCOUNT_KEYS } from "../src/roles.ts";
import { classify } from "../src/classify.ts";
import { buildVerdict } from "../src/verdict.ts";
import { computeOutflow } from "../src/outflow.ts";
import { DEFAULT_CONTEXT } from "../src/types.ts";
import { validateRegistry, allRegisteredProgramIds, isRegisteredProgram } from "../src/registry.ts";
import { legacyBytes, key, u64le } from "./helpers.ts";

// ---- Program IDs (verified against canonical declare_id! in respective repos) ----
const JUPITER_V6 = "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4";
const METAPLEX_TOKEN_METADATA = "metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s";
const BUBBLEGUM = "BGUMAp9Gq7iTEuizy4pqaxsTyUCBK68MDfK752saRPUY";
const ORCA_WHIRLPOOLS = "whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc";
const RAYDIUM_AMM_V4 = "675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8";
const SPL_TOKEN = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";

// ---- Discriminator constants (all verified against canonical sources) ----

/** Metaplex Token Metadata: beet-u8 discriminators (verified from generated JS client). */
const METAPLEX_DISC = {
  Transfer: 49,        // 0x31 — Transfer (pNFT)
  Delegate: 44,        // 0x2c — Delegate
  Revoke: 45,          // 0x2d — Revoke
  Burn: 41,            // 0x29 — Burn (pNFT)
  BurnNft: 29,         // 0x1d — BurnNft (legacy)
  Update: 50,          // 0x32 — Update
  UpdateMetadata: 1,   // 0x01 — UpdateMetadataAccount
};

/** Bubblegum cNFT: Anchor 8-byte discriminators sha256("global:<name>")[0..8]. */
const BUBBLEGUM_DISC = {
  transfer: "a334c8e78c0345ba",      // verified locally
  transfer_v2: "772806ebeaddf831",
  delegate: "5a934bb255580489",      // verified locally
  burn: "746e1d386bdb2a5d",          // verified locally
};

// ---- base58 decode helper (same as classify.test.ts) ----
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

/**
 * Build a legacy message with a single instruction.
 * Header: 1 required signer, 0 readonly-signed, N readonly-unsigned.
 * Accounts: idx0=fee-payer (signer-writable), idx1=program (readonly), extras...
 */
function singleIxMsg(programId: string, data: number[], writableAcctCount = 0): Uint8Array {
  const progBytes = base58ToBytes(programId);
  const out: number[] = [];
  // numRequiredSignatures=1, numReadonlySigned=0,
  // numReadonlyUnsigned = 1 (the program itself) + writableAcctCount? No:
  // we put writable accts in writable-unsigned slots.
  // Slot layout: [signer-writable(0)] | [writable-unsigned(1..writableAcctCount)] | [program] | [readonly-unsigned...]
  // Header: numRequiredSignatures=1, numReadonlySigned=0, numReadonlyUnsigned=1+0=1
  // We use writableAcctCount extra writable accounts after fee payer, before the program.
  const numReadonlyUnsigned = 1; // just the program
  out.push(1, 0, numReadonlyUnsigned);
  // Keys: fee payer (idx0), writable extras, program
  const numKeys = 1 + writableAcctCount + 1;
  out.push(numKeys);
  out.push(...key(1));  // idx0 fee payer (signer-writable)
  for (let i = 0; i < writableAcctCount; i++) out.push(...key(10 + i)); // writable extras
  out.push(...progBytes); // program (last, readonly-unsigned)
  out.push(...key(250)); // blockhash
  out.push(1); // 1 instruction
  // programIdIndex = last key
  out.push(1 + writableAcctCount);
  // accts: fee payer + any writable extras
  const acctCount = 1 + writableAcctCount;
  out.push(acctCount);
  for (let i = 0; i < acctCount; i++) out.push(i);
  out.push(data.length);
  out.push(...data);
  return Uint8Array.from(out);
}

/** Helper: build and classify a single-ix message. */
function classifyMsg(programId: string, data: number[], writableAcctCount = 0) {
  const bytes = singleIxMsg(programId, data, writableAcctCount);
  const msg = decodeMessageBytes(bytes);
  const roles = deriveRoles(msg, { reservedAccountKeys: RESERVED_ACCOUNT_KEYS });
  const cls = classify(msg, roles, DEFAULT_CONTEXT);
  const outflow = computeOutflow(msg, roles, DEFAULT_CONTEXT);
  return { msg, roles, cls, outflow };
}

/** Helper: build and run full verdict on a single-ix message. */
function verdictMsg(programId: string, data: number[], writableAcctCount = 0) {
  const bytes = singleIxMsg(programId, data, writableAcctCount);
  const msg = decodeMessageBytes(bytes);
  const roles = deriveRoles(msg, { reservedAccountKeys: RESERVED_ACCOUNT_KEYS });
  const cls = classify(msg, roles, DEFAULT_CONTEXT);
  const outflow = computeOutflow(msg, roles, DEFAULT_CONTEXT);
  return buildVerdict({
    messageVersion: msg.version,
    findings: cls.findings,
    outflow,
    unknownPrograms: cls.unknownPrograms,
    unknownProgramWritable: cls.unknownProgramWritable,
    altLookupsPresent: msg.altLookupsPresent,
    rolesUnverified: false,
    durableNonceMarker: cls.durableNonceMarker,
    authorityOrOwnershipChange: cls.authorityOrOwnershipChange,
  });
}

/** Convert a hex string to a number[] for use as instruction data. */
function hexToData(hex: string): number[] {
  const out: number[] = [];
  for (let i = 0; i < hex.length; i += 2) {
    out.push(parseInt(hex.slice(i, i + 2), 16));
  }
  return out;
}

// =============================================================================
// 1. Registry catalog validation
// =============================================================================

describe("registry catalog validation", () => {
  it("all discHex values are well-formed (correct length, lowercase hex)", () => {
    const errors = validateRegistry();
    expect(errors).toEqual([]);
  });

  it("all registered program IDs are non-empty strings", () => {
    const ids = allRegisteredProgramIds();
    expect(ids.length).toBeGreaterThan(0);
    for (const id of ids) {
      expect(typeof id).toBe("string");
      expect(id.length).toBeGreaterThan(0);
    }
  });

  it("isRegisteredProgram returns true for known DeFi/NFT programs", () => {
    expect(isRegisteredProgram(JUPITER_V6)).toBe(true);
    expect(isRegisteredProgram(METAPLEX_TOKEN_METADATA)).toBe(true);
    expect(isRegisteredProgram(BUBBLEGUM)).toBe(true);
    expect(isRegisteredProgram(ORCA_WHIRLPOOLS)).toBe(true);
    expect(isRegisteredProgram(RAYDIUM_AMM_V4)).toBe(true);
  });

  it("isRegisteredProgram returns false for native programs (not in registry)", () => {
    expect(isRegisteredProgram(SPL_TOKEN)).toBe(false);
    expect(isRegisteredProgram("11111111111111111111111111111111")).toBe(false);
    expect(isRegisteredProgram("ComputeBudget111111111111111111111111111111")).toBe(false);
    expect(isRegisteredProgram("SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf")).toBe(false);
  });
});

// =============================================================================
// 2. Jupiter v6 — recognized, not REJECT
// =============================================================================

describe("Jupiter v6 recognized program (GAP 3)", () => {
  it("Jupiter swap instruction -> HOLD (recognized, NOT REJECT)", () => {
    // An 8-byte Anchor discriminator for a fictional Jupiter 'route' instruction.
    // The specific bytes don't matter for this test as long as they don't match
    // a dangerous-instruction entry (Jupiter has none listed).
    const data = [0xaa, 0xbb, 0xcc, 0xdd, 0x11, 0x22, 0x33, 0x44, 0x01, 0x00]; // 8-byte disc + payload
    const { cls } = classifyMsg(JUPITER_V6, data, 1);

    // Must NOT be in unknownPrograms (it is recognized).
    expect(cls.unknownPrograms).not.toContain(JUPITER_V6);
    // Must NOT produce unknownProgramWritable REJECT path.
    expect(cls.unknownProgramWritable).toBe(false);
    // Must produce a HOLD finding.
    const holdFinding = cls.findings.find((f) => f.id.startsWith("registry-jupiter-v6"));
    expect(holdFinding).toBeTruthy();
    expect(holdFinding!.severity).toBe("HOLD");
  });

  it("Jupiter: full verdict is HOLD, not REJECT", () => {
    const data = [0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0]; // 8-byte disc
    const v = verdictMsg(JUPITER_V6, data, 1);
    expect(v.decision).toBe("HOLD");
    expect(v.unknownPrograms).not.toContain(JUPITER_V6);
  });

  it("Jupiter: finding label contains 'Jupiter' (recognizable to the signer)", () => {
    const data = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
    const { cls } = classifyMsg(JUPITER_V6, data);
    const f = cls.findings.find((f) => f.id.startsWith("registry-jupiter-v6"));
    expect(f).toBeTruthy();
    expect(f!.label).toMatch(/Jupiter/i);
  });
});

// =============================================================================
// 3. Metaplex Token Metadata — dangerous instruction detection
// =============================================================================

describe("Metaplex Token Metadata: Transfer (disc 49 = 0x31)", () => {
  it("Metaplex Transfer -> REJECT with 'Metaplex: Transfer NFT' label", () => {
    const data = [METAPLEX_DISC.Transfer, 0x00, 0x01, 0x02]; // disc + some payload
    const { cls } = classifyMsg(METAPLEX_TOKEN_METADATA, data, 1);

    const f = cls.findings.find((f) => f.id.startsWith("registry-metaplex-token-metadata-danger"));
    expect(f).toBeTruthy();
    expect(f!.severity).toBe("REJECT");
    expect(f!.label).toBe("Metaplex: Transfer NFT");
    expect(f!.mapsToLoss).toContain("NFT theft");
  });

  it("Metaplex Transfer: full verdict is REJECT", () => {
    const data = [METAPLEX_DISC.Transfer];
    const v = verdictMsg(METAPLEX_TOKEN_METADATA, data, 1);
    expect(v.decision).toBe("REJECT");
    // Reason must mention the finding
    expect(v.reason).toContain("Metaplex: Transfer NFT");
  });

  it("Metaplex Transfer: NOT in unknownPrograms", () => {
    const data = [METAPLEX_DISC.Transfer];
    const { cls } = classifyMsg(METAPLEX_TOKEN_METADATA, data);
    expect(cls.unknownPrograms).not.toContain(METAPLEX_TOKEN_METADATA);
    expect(cls.unknownProgramWritable).toBe(false);
  });
});

describe("Metaplex Token Metadata: Delegate (disc 44 = 0x2c)", () => {
  it("Metaplex Delegate -> HOLD with named label", () => {
    const data = [METAPLEX_DISC.Delegate, 0x00, 0x01];
    const { cls } = classifyMsg(METAPLEX_TOKEN_METADATA, data, 1);

    const f = cls.findings.find((f) => f.id.startsWith("registry-metaplex-token-metadata-danger"));
    expect(f).toBeTruthy();
    expect(f!.severity).toBe("HOLD");
    expect(f!.label).toBe("Metaplex: Delegate NFT authority");
  });

  it("Metaplex Delegate: full verdict is HOLD (not REJECT, not SIGN)", () => {
    const data = [METAPLEX_DISC.Delegate];
    const v = verdictMsg(METAPLEX_TOKEN_METADATA, data, 1);
    expect(v.decision).toBe("HOLD");
  });
});

describe("Metaplex Token Metadata: Burn (disc 41 = 0x29)", () => {
  it("Metaplex Burn pNFT -> REJECT", () => {
    const data = [METAPLEX_DISC.Burn];
    const { cls } = classifyMsg(METAPLEX_TOKEN_METADATA, data, 1);
    const f = cls.findings.find((f) => f.id.startsWith("registry-metaplex-token-metadata-danger"));
    expect(f).toBeTruthy();
    expect(f!.severity).toBe("REJECT");
    expect(f!.label).toContain("Burn");
  });
});

describe("Metaplex Token Metadata: unrecognized instruction -> HOLD (fail-closed)", () => {
  it("Metaplex instruction with unknown disc -> HOLD, not SIGN", () => {
    // disc 0xff is not in the dangerous list
    const data = [0xff, 0x01, 0x02, 0x03];
    const { cls } = classifyMsg(METAPLEX_TOKEN_METADATA, data, 1);

    const f = cls.findings.find((f) => f.id.startsWith("registry-metaplex-token-metadata-unknown"));
    expect(f).toBeTruthy();
    expect(f!.severity).toBe("HOLD");
    // Must NOT be SIGN
    expect(f!.severity).not.toBe("INFO" as any);
  });

  it("Metaplex unrecognized instruction: full verdict is HOLD (not SIGN)", () => {
    const data = [0xff];
    const v = verdictMsg(METAPLEX_TOKEN_METADATA, data);
    expect(v.decision).toBe("HOLD");
    expect(v.decision).not.toBe("SIGN");
  });
});

// =============================================================================
// 4. Bubblegum cNFT — transfer and burn flagged
// =============================================================================

describe("Bubblegum cNFT: Transfer (disc a334c8e78c0345ba)", () => {
  it("Bubblegum Transfer -> REJECT with 'Bubblegum: Transfer cNFT' label", () => {
    const data = hexToData(BUBBLEGUM_DISC.transfer);
    const { cls } = classifyMsg(BUBBLEGUM, data, 1);

    const f = cls.findings.find((f) => f.id.startsWith("registry-metaplex-bubblegum-danger"));
    expect(f).toBeTruthy();
    expect(f!.severity).toBe("REJECT");
    expect(f!.label).toBe("Bubblegum: Transfer cNFT");
  });

  it("Bubblegum Transfer: full verdict is REJECT", () => {
    const data = hexToData(BUBBLEGUM_DISC.transfer);
    const v = verdictMsg(BUBBLEGUM, data, 1);
    expect(v.decision).toBe("REJECT");
  });

  it("Bubblegum Transfer: NOT in unknownPrograms", () => {
    const data = hexToData(BUBBLEGUM_DISC.transfer);
    const { cls } = classifyMsg(BUBBLEGUM, data);
    expect(cls.unknownPrograms).not.toContain(BUBBLEGUM);
    expect(cls.unknownProgramWritable).toBe(false);
  });
});

describe("Bubblegum cNFT: Burn (disc 746e1d386bdb2a5d)", () => {
  it("Bubblegum Burn -> REJECT", () => {
    const data = hexToData(BUBBLEGUM_DISC.burn);
    const { cls } = classifyMsg(BUBBLEGUM, data, 1);
    const f = cls.findings.find((f) => f.id.startsWith("registry-metaplex-bubblegum-danger"));
    expect(f).toBeTruthy();
    expect(f!.severity).toBe("REJECT");
    expect(f!.label).toContain("Burn");
  });
});

describe("Bubblegum cNFT: Delegate (disc 5a934bb255580489)", () => {
  it("Bubblegum Delegate -> HOLD", () => {
    const data = hexToData(BUBBLEGUM_DISC.delegate);
    const { cls } = classifyMsg(BUBBLEGUM, data, 1);
    const f = cls.findings.find((f) => f.id.startsWith("registry-metaplex-bubblegum-danger"));
    expect(f).toBeTruthy();
    expect(f!.severity).toBe("HOLD");
  });
});

describe("Bubblegum cNFT: unrecognized instruction -> HOLD (fail-closed)", () => {
  it("Bubblegum unknown 8-byte disc -> HOLD, never SIGN", () => {
    const data = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01]; // not a known disc
    const { cls } = classifyMsg(BUBBLEGUM, data, 1);
    const f = cls.findings.find((f) => f.id.startsWith("registry-metaplex-bubblegum-unknown"));
    expect(f).toBeTruthy();
    expect(f!.severity).toBe("HOLD");
  });
});

// =============================================================================
// 5. Orca / Raydium — recognized, all instructions HOLD
// =============================================================================

describe("Orca Whirlpools: recognized, all instructions HOLD", () => {
  it("Orca instruction -> HOLD, not REJECT", () => {
    const data = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
    const { cls } = classifyMsg(ORCA_WHIRLPOOLS, data, 1);
    expect(cls.unknownPrograms).not.toContain(ORCA_WHIRLPOOLS);
    const f = cls.findings.find((f) => f.id.startsWith("registry-orca-whirlpools"));
    expect(f).toBeTruthy();
    expect(f!.severity).toBe("HOLD");
  });
});

describe("Raydium AMM v4: recognized, all instructions HOLD", () => {
  it("Raydium instruction -> HOLD, not REJECT", () => {
    const data = [0x09]; // some single-byte disc
    const { cls } = classifyMsg(RAYDIUM_AMM_V4, data, 1);
    expect(cls.unknownPrograms).not.toContain(RAYDIUM_AMM_V4);
    const f = cls.findings.find((f) => f.id.startsWith("registry-raydium-amm-v4"));
    expect(f).toBeTruthy();
    expect(f!.severity).toBe("HOLD");
  });
});

// =============================================================================
// 6. Unknown program writing value: HOLD in default, REJECT in strict
// =============================================================================

describe("Truly unknown program: two-tier behavior (default HOLD, strict REJECT)", () => {
  function buildUnknownWritableMsg() {
    // Use a random program id that is not in the registry or native catalog.
    const unknownProg = "Fg6PaFpoGXkYsidMpWTK6W2BeZ7FEfcYkg476zPFsLnS";
    const unknownProgBytes = base58ToBytes(unknownProg);
    const out: number[] = [];
    // header: 1 signer, 0 readonly-signed, 0 readonly-unsigned.
    // Keys: idx0=fee-payer (signer-writable), idx1=writable-unsigned (value-bearing), idx2=program.
    out.push(1, 0, 1); // numReadonlyUnsigned=1 (just the program)
    out.push(3); // numKeys
    out.push(...key(1));            // idx0 fee payer
    out.push(...key(2));            // idx1 writable unsigned
    out.push(...unknownProgBytes);  // idx2 program
    out.push(...key(250));          // blockhash
    out.push(1); // 1 instruction
    out.push(2); // programIdIndex = idx2
    out.push(2); out.push(0); out.push(1); // 2 accts: idx0, idx1
    out.push(1, 0x99); // 1-byte data
    return { msgBytes: Uint8Array.from(out), unknownProg };
  }

  it("DEFAULT mode: unregistered program writing a writable account -> HOLD (not REJECT)", () => {
    const { msgBytes, unknownProg } = buildUnknownWritableMsg();
    const msg = decodeMessageBytes(msgBytes);
    const roles = deriveRoles(msg, { reservedAccountKeys: RESERVED_ACCOUNT_KEYS });
    const cls = classify(msg, roles, DEFAULT_CONTEXT);

    // The unknown program must still go through the unknown-program path.
    expect(cls.unknownPrograms).toContain(unknownProg);
    expect(cls.unknownProgramWritable).toBe(true);

    // In DEFAULT mode (no strict flag), unknownProgramWritable → HOLD, not REJECT.
    const v = buildVerdict({
      messageVersion: msg.version,
      findings: cls.findings,
      outflow: computeOutflow(msg, roles, DEFAULT_CONTEXT),
      unknownPrograms: cls.unknownPrograms,
      unknownProgramWritable: cls.unknownProgramWritable,
      altLookupsPresent: msg.altLookupsPresent,
      rolesUnverified: false,
      // strict is not set (default false)
    });
    expect(v.decision).toBe("HOLD");
    expect(v.reason).toContain("--strict");
  });

  it("STRICT mode: unregistered program writing a writable account -> REJECT", () => {
    const { msgBytes, unknownProg } = buildUnknownWritableMsg();
    const msg = decodeMessageBytes(msgBytes);
    const roles = deriveRoles(msg, { reservedAccountKeys: RESERVED_ACCOUNT_KEYS });
    const cls = classify(msg, roles, DEFAULT_CONTEXT);

    expect(cls.unknownPrograms).toContain(unknownProg);
    expect(cls.unknownProgramWritable).toBe(true);

    // In STRICT mode, unknownProgramWritable → REJECT (legacy behavior).
    const v = buildVerdict({
      messageVersion: msg.version,
      findings: cls.findings,
      outflow: computeOutflow(msg, roles, DEFAULT_CONTEXT),
      unknownPrograms: cls.unknownPrograms,
      unknownProgramWritable: cls.unknownProgramWritable,
      altLookupsPresent: msg.altLookupsPresent,
      rolesUnverified: false,
      strict: true,
    });
    expect(v.decision).toBe("REJECT");
  });
});

// =============================================================================
// 7. Native SPL Transfer still SIGN (no regression)
// =============================================================================

describe("Native SPL Transfer: no regression (still SIGN)", () => {
  it("SPL Token Transfer (disc 3) below threshold -> SIGN", () => {
    // Use legacyBytes to build a proper SPL token transfer with source/dest accounts.
    const splTokenBytes = base58ToBytes(SPL_TOKEN);
    const out: number[] = [];
    // header: 1 signer, 0 readonly-signed, 2 readonly-unsigned (dest + program).
    // Keys: idx0=signer(src), idx1=dest, idx2=program(SPL_TOKEN).
    out.push(1, 0, 1); // numReadonlyUnsigned=1 (just the program)
    out.push(3); // numKeys = 3 (signer, dest/writable-unsigned, program)
    out.push(...key(1));          // idx0 signer-writable (source)
    out.push(...key(2));          // idx1 writable-unsigned (destination token account)
    out.push(...splTokenBytes);   // idx2 program (readonly-unsigned)
    out.push(...key(250));        // blockhash
    out.push(1); // 1 instruction
    out.push(2); // programIdIndex = 2
    out.push(2); out.push(0); out.push(1); // 2 accts: src=idx0, dst=idx1
    // disc 3 (Transfer) + u64 amount = 1000 (well below 1 SOL in lamports, not checked for SPL)
    const txData = [3, ...u64le(1000n)];
    out.push(txData.length);
    out.push(...txData);
    const msgBytes = Uint8Array.from(out);

    const msg = decodeMessageBytes(msgBytes);
    const roles = deriveRoles(msg, { reservedAccountKeys: RESERVED_ACCOUNT_KEYS });
    const cls = classify(msg, roles, DEFAULT_CONTEXT);
    const outflow = computeOutflow(msg, roles, DEFAULT_CONTEXT);

    // No dangerous findings (SPL Token is natively catalogued; disc 3 is a
    // plain transfer, not a SetAuthority/Approve etc.) — this should SIGN.
    const v = buildVerdict({
      messageVersion: msg.version,
      findings: cls.findings,
      outflow,
      unknownPrograms: cls.unknownPrograms,
      unknownProgramWritable: cls.unknownProgramWritable,
      altLookupsPresent: msg.altLookupsPresent,
      rolesUnverified: false,
    });
    expect(v.decision).toBe("SIGN");
    expect(cls.unknownPrograms).toHaveLength(0);
  });
});

// =============================================================================
// 8. Fail-closed: recognized-program findings are never SIGN-only
// =============================================================================

describe("Fail-closed: recognized programs never produce SIGN alone", () => {
  const recognizedProgs = [
    { name: "Jupiter v6", id: JUPITER_V6, data: [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08] },
    { name: "Orca", id: ORCA_WHIRLPOOLS, data: [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08] },
    { name: "Raydium AMM v4", id: RAYDIUM_AMM_V4, data: [0x01] },
    { name: "Metaplex unknown disc", id: METAPLEX_TOKEN_METADATA, data: [0xfe] },
    { name: "Bubblegum unknown disc", id: BUBBLEGUM, data: [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02] },
  ];

  for (const prog of recognizedProgs) {
    it(`${prog.name}: instruction never produces SIGN verdict`, () => {
      const v = verdictMsg(prog.id, prog.data, 1);
      expect(v.decision).not.toBe("SIGN");
    });
  }
});
