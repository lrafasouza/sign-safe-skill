/**
 * strict-mode.test.ts -- Two-tier gate: DEFAULT mode vs STRICT mode (Phase D calibration).
 *
 * Asserts the deliberate recalibration after the mainnet precision study showing 63%
 * of benign transactions were hard-REJECT in the old single-tier mode.
 *
 * Test groups:
 *   S1  Unknown program writing to a value-bearing account
 *       S1.1 DEFAULT: unknownProgramWritable → HOLD (not REJECT)
 *       S1.2 STRICT:  unknownProgramWritable → REJECT
 *       S1.3 reason string in HOLD mentions "--strict"
 *
 *   S2  Durable-nonce + HOLD-class-only findings (no authority change)
 *       S2.1 DEFAULT: durable-nonce + registered-program-unknown-instruction → HOLD
 *       S2.2 STRICT:  same → REJECT (broad driftComposite)
 *       S2.3 DEFAULT: durable-nonce + unknown program present (writable) → HOLD
 *       S2.4 STRICT:  durable-nonce + unknown program present → REJECT
 *
 *   S3  Genuine Drift class (authority/ownership change) — always REJECT
 *       S3.1 DEFAULT: durable-nonce + SPL SetAuthority → REJECT
 *       S3.2 STRICT:  durable-nonce + SPL SetAuthority → REJECT (unchanged)
 *       S3.3 DEFAULT: durable-nonce + System Assign (REJECT-class) → REJECT
 *       S3.4 STRICT:  durable-nonce + System Assign → REJECT (unchanged)
 *
 *   S4  Catalog REJECT-class findings — always REJECT regardless of mode
 *       S4.1 DEFAULT: SPL SetAuthority (AccountOwner change) → REJECT
 *       S4.2 STRICT:  SPL SetAuthority → REJECT (same)
 *       S4.3 DEFAULT: blocklisted recipient → REJECT
 *       S4.4 STRICT:  blocklisted recipient → REJECT (same)
 *
 *   S5  Recall preserved — malicious families still caught in DEFAULT
 *       S5.1 SetAuthority (account owner) still REJECT
 *       S5.2 System Assign → still REJECT
 *       S5.3 Bare durable nonce alone → HOLD in both modes (unchanged)
 *       S5.4 Bare durable nonce + governanceContext → REJECT in both modes
 *
 *   S6  Strict-vs-default monotone invariant
 *       S6.1 strict cannot produce SIGN where default produces HOLD or REJECT
 *       S6.2 strict cannot produce HOLD where default produces REJECT
 *
 *   S7  HOLD reason strings in DEFAULT mode
 *       S7.1 unknownWritable HOLD reason contains "--strict"
 *       S7.2 unknownWritable HOLD reason contains the program address
 *
 * All tests are OFFLINE and DETERMINISTIC. No network, no RPC.
 */

import { describe, it, expect } from "vitest";
import { reviewBase64, buildVerdict } from "../src/verdict.ts";
import { u32le, u64le, key, toB64 } from "./helpers.ts";
import type { VerdictContext, Finding, StaticOutflow } from "../src/types.ts";

// ---------------------------------------------------------------------------
// Program constants
// ---------------------------------------------------------------------------

const SYSTEM = "11111111111111111111111111111111";
const SPL_TOKEN = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
// A program not in the catalog or registry.
const UNKNOWN_PROG_FILLER = 77; // key byte; produces a predictable non-catalog address

// ---------------------------------------------------------------------------
// base58 decode helper (copied from squad-verdict.test.ts)
// ---------------------------------------------------------------------------

function base58ToBytes(b58: string): Uint8Array {
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

/**
 * Build a legacy message placing real program ids at chosen static indices.
 * `keySpecs`: per static key, either a fill byte (number) or a base58 id.
 */
function buildMessage(
  header: [number, number, number],
  keySpecs: Array<number | string>,
  ixs: Array<{ prog: number; accts: number[]; data: number[] }>,
): Uint8Array {
  const out: number[] = [];
  out.push(...header);
  out.push(keySpecs.length);
  for (const k of keySpecs) {
    if (typeof k === "number") out.push(...key(k));
    else out.push(...Array.from(base58ToBytes(k)));
  }
  out.push(...key(250)); // blockhash
  out.push(ixs.length);
  for (const ix of ixs) {
    out.push(ix.prog);
    out.push(ix.accts.length);
    out.push(...ix.accts);
    out.push(ix.data.length);
    out.push(...ix.data);
  }
  return Uint8Array.from(out);
}

// ---------------------------------------------------------------------------
// Context helpers
// ---------------------------------------------------------------------------

const DEFAULT_CTX: VerdictContext = { lamportThreshold: 1_000_000_000 };
const STRICT_CTX: VerdictContext = { lamportThreshold: 1_000_000_000, strict: true };

// ---------------------------------------------------------------------------
// S1: Unknown program writing to a value-bearing account
// ---------------------------------------------------------------------------

describe("S1: unknown program + writable account — default HOLD, strict REJECT", () => {
  /**
   * Build a message where an unknown program writes to a non-signer writable
   * account. Header: 1 signer, 0 ro-signed, 1 ro-unsigned (the unknown program).
   * Keys: [feePayer, writableValue, unknownProg]. The program ix writes to
   * writableValue (index 1).
   */
  function buildUnknownWritableMsg(): Uint8Array {
    // keySpecs: idx0=feePayer(1), idx1=writableValue(2), idx2=unknownProg(77)
    // Header: 1 signer, 0 ro-signed, 1 ro-unsigned (just the program)
    return buildMessage(
      [1, 0, 1],
      [1, 2, UNKNOWN_PROG_FILLER],
      [{ prog: 2, accts: [0, 1], data: [0x01, 0x02, 0x03] }],
    );
  }

  it("S1.1 DEFAULT: unknown program writes to writable account -> HOLD (not REJECT)", () => {
    const v = reviewBase64(toB64(buildUnknownWritableMsg()), DEFAULT_CTX);
    expect(v.decision).toBe("HOLD");
    expect(v.flags.unknownProgramPresent).toBe(true);
  });

  it("S1.2 STRICT: unknown program writes to writable account -> REJECT", () => {
    const v = reviewBase64(toB64(buildUnknownWritableMsg()), STRICT_CTX);
    expect(v.decision).toBe("REJECT");
    expect(v.flags.unknownProgramPresent).toBe(true);
  });

  it("S1.3 DEFAULT HOLD reason mentions '--strict' (opt-in guidance)", () => {
    const v = reviewBase64(toB64(buildUnknownWritableMsg()), DEFAULT_CTX);
    expect(v.reason).toContain("--strict");
  });

  it("S1.4 DEFAULT HOLD reason contains the unknown program address", () => {
    const v = reviewBase64(toB64(buildUnknownWritableMsg()), DEFAULT_CTX);
    // The unknown program list should be in the reason
    expect(v.unknownPrograms.length).toBeGreaterThan(0);
    expect(v.reason).toContain(v.unknownPrograms[0]);
  });

  it("S1.5 neither mode ever SIGNs when unknown program writes to value account", () => {
    const vDefault = reviewBase64(toB64(buildUnknownWritableMsg()), DEFAULT_CTX);
    const vStrict = reviewBase64(toB64(buildUnknownWritableMsg()), STRICT_CTX);
    expect(vDefault.decision).not.toBe("SIGN");
    expect(vStrict.decision).not.toBe("SIGN");
  });
});

// ---------------------------------------------------------------------------
// S2: Durable-nonce + HOLD-class-only findings
// ---------------------------------------------------------------------------

describe("S2: durable-nonce + HOLD-class-only — default HOLD, strict REJECT", () => {
  // Jupiter v6 produces a HOLD finding (registered-program-unknown-instruction),
  // not a REJECT-class finding. In DEFAULT mode, durable-nonce + HOLD-only → HOLD.
  // In STRICT mode, durable-nonce + any non-INFO finding → REJECT.
  const JUPITER_V6 = "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4";

  function buildNoncePlusJupiterMsg(): Uint8Array {
    // ix0 = AdvanceNonceAccount (System), ix1 = Jupiter instruction (8-byte disc, HOLD only)
    const unknownJupDisc = [0xaa, 0xbb, 0xcc, 0xdd, 0x11, 0x22, 0x33, 0x44];
    return buildMessage(
      [1, 0, 1],
      [1, SYSTEM, JUPITER_V6, 3],
      [
        { prog: 1, accts: [3, 0], data: u32le(4) },    // ix0: AdvanceNonce (System=idx1)
        { prog: 2, accts: [0, 3], data: unknownJupDisc }, // ix1: Jupiter unknown-instruction (HOLD)
      ],
    );
  }

  it("S2.1 DEFAULT: durable-nonce + Jupiter HOLD-only → HOLD (not REJECT)", () => {
    const v = reviewBase64(toB64(buildNoncePlusJupiterMsg()), DEFAULT_CTX);
    expect(v.decision).toBe("HOLD");
    // Should have nonce finding + Jupiter HOLD finding
    expect(v.findings.some((f) => f.id === "durable-nonce-advance")).toBe(true);
  });

  it("S2.2 STRICT: durable-nonce + Jupiter HOLD-only → REJECT (broad driftComposite)", () => {
    const v = reviewBase64(toB64(buildNoncePlusJupiterMsg()), STRICT_CTX);
    expect(v.decision).toBe("REJECT");
    // Reason should mention durable-nonce + unverified/dangerous instruction
    expect(v.reason.toLowerCase()).toMatch(/durable-nonce|drift|non-expiring/);
  });

  it("S2.3 DEFAULT: durable-nonce + unknown program (writable) → HOLD", () => {
    // ix0 = AdvanceNonce, ix1 = unknown program writing to a writable account
    const msg = buildMessage(
      [1, 0, 1],
      [1, SYSTEM, UNKNOWN_PROG_FILLER, 3],
      [
        { prog: 1, accts: [3, 0], data: u32le(4) },     // ix0: AdvanceNonce
        { prog: 2, accts: [0, 3], data: [0x01, 0x02] }, // ix1: unknown prog + writable
      ],
    );
    const v = reviewBase64(toB64(msg), DEFAULT_CTX);
    // DEFAULT: unknownProgramWritable → HOLD (not REJECT); driftCompositeDefault also HOLD
    // (no REJECT-class catalog finding, no authority change)
    expect(v.decision).toBe("HOLD");
    expect(v.flags.unknownProgramPresent).toBe(true);
  });

  it("S2.4 STRICT: durable-nonce + unknown program → REJECT", () => {
    const msg = buildMessage(
      [1, 0, 1],
      [1, SYSTEM, UNKNOWN_PROG_FILLER, 3],
      [
        { prog: 1, accts: [3, 0], data: u32le(4) },
        { prog: 2, accts: [0, 3], data: [0x01, 0x02] },
      ],
    );
    const v = reviewBase64(toB64(msg), STRICT_CTX);
    expect(v.decision).toBe("REJECT");
  });
});

// ---------------------------------------------------------------------------
// S3: Genuine Drift class — always REJECT regardless of mode
// ---------------------------------------------------------------------------

describe("S3: genuine Drift class (authority/ownership change) — always REJECT", () => {
  // SPL SetAuthority (disc 6, AccountOwner change) is a REJECT-class catalog finding.
  // durable-nonce + SetAuthority → REJECT in BOTH modes.
  const setAuth = [6, 2, 1, ...key(9)]; // AccountOwner change, Some

  function buildNoncePlusSetAuthMsg(): Uint8Array {
    return buildMessage(
      [1, 0, 1],
      [1, SYSTEM, 3, SPL_TOKEN],
      [
        { prog: 1, accts: [2, 0], data: u32le(4) }, // ix0 AdvanceNonce
        { prog: 3, accts: [2, 0], data: setAuth },   // ix1 SetAuthority (REJECT)
      ],
    );
  }

  it("S3.1 DEFAULT: durable-nonce + SPL SetAuthority → REJECT (Drift reason)", () => {
    const v = reviewBase64(toB64(buildNoncePlusSetAuthMsg()), DEFAULT_CTX);
    expect(v.decision).toBe("REJECT");
    expect(v.reason).toContain("Drift");
  });

  it("S3.2 STRICT: durable-nonce + SPL SetAuthority → REJECT (unchanged)", () => {
    const v = reviewBase64(toB64(buildNoncePlusSetAuthMsg()), STRICT_CTX);
    expect(v.decision).toBe("REJECT");
    expect(v.reason).toContain("Drift");
  });

  it("S3.3 DEFAULT: durable-nonce + System Assign (REJECT-class) → REJECT", () => {
    const msg = buildMessage(
      [1, 0, 1],
      [1, SYSTEM, 3],
      [
        { prog: 1, accts: [2, 0], data: u32le(4) }, // ix0 AdvanceNonce
        { prog: 1, accts: [2], data: u32le(1) },     // ix1 System Assign (REJECT)
      ],
    );
    const v = reviewBase64(toB64(msg), DEFAULT_CTX);
    expect(v.decision).toBe("REJECT");
    expect(v.reason).toContain("Drift");
  });

  it("S3.4 STRICT: durable-nonce + System Assign → REJECT (unchanged)", () => {
    const msg = buildMessage(
      [1, 0, 1],
      [1, SYSTEM, 3],
      [
        { prog: 1, accts: [2, 0], data: u32le(4) },
        { prog: 1, accts: [2], data: u32le(1) },
      ],
    );
    const v = reviewBase64(toB64(msg), STRICT_CTX);
    expect(v.decision).toBe("REJECT");
  });
});

// ---------------------------------------------------------------------------
// S4: Catalog REJECT-class findings — always REJECT, both modes
// ---------------------------------------------------------------------------

describe("S4: catalog REJECT-class findings — always REJECT in both modes", () => {
  // SPL Token SetAuthority (disc 6, AccountOwner = type 2, Some newAuth at data[3..35])
  const setAuth = [6, 2, 1, ...key(9)]; // AccountOwner change

  it("S4.1 DEFAULT: SPL SetAuthority alone → REJECT (unchanged)", () => {
    const msg = buildMessage(
      [1, 0, 1],
      [1, 3, SPL_TOKEN],
      [{ prog: 2, accts: [1, 0], data: setAuth }],
    );
    const v = reviewBase64(toB64(msg), DEFAULT_CTX);
    expect(v.decision).toBe("REJECT");
    const f = v.findings.find((x) => x.id === "spl-set-authority");
    expect(f).toBeTruthy();
    expect(f!.severity).toBe("REJECT");
  });

  it("S4.2 STRICT: SPL SetAuthority alone → REJECT (same)", () => {
    const msg = buildMessage(
      [1, 0, 1],
      [1, 3, SPL_TOKEN],
      [{ prog: 2, accts: [1, 0], data: setAuth }],
    );
    const v = reviewBase64(toB64(msg), STRICT_CTX);
    expect(v.decision).toBe("REJECT");
  });

  it("S4.3 DEFAULT: blocklisted recipient → REJECT (unchanged)", () => {
    // Build a System Transfer and check the recipient against a blocklist.
    const recipientKey = new Uint8Array(32).fill(0xba); // 0xba fill
    let b58 = "";
    {
      const A = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
      let n = 0n;
      for (const b of recipientKey) n = n * 256n + BigInt(b);
      let s = "";
      while (n > 0n) { s = A[Number(n % 58n)]! + s; n /= 58n; }
      b58 = s;
    }

    const msg = buildMessage(
      [1, 0, 1],
      [1, SYSTEM, 0xba],
      [{ prog: 1, accts: [0, 2], data: [...u32le(2), ...u64le(500_000_000n)] }],
    );
    const ctx: VerdictContext = {
      lamportThreshold: 1_000_000_000,
      recipientBlocklist: [b58],
    };
    const v = reviewBase64(toB64(msg), ctx);
    expect(v.decision).toBe("REJECT");
    expect(v.findings.some((f) => f.id === "blocklisted-recipient")).toBe(true);
  });

  it("S4.4 STRICT+blocklist: blocklisted recipient → REJECT (same)", () => {
    const recipientKey = new Uint8Array(32).fill(0xba);
    let b58 = "";
    {
      const A = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
      let n = 0n;
      for (const b of recipientKey) n = n * 256n + BigInt(b);
      let s = "";
      while (n > 0n) { s = A[Number(n % 58n)]! + s; n /= 58n; }
      b58 = s;
    }
    const msg = buildMessage(
      [1, 0, 1],
      [1, SYSTEM, 0xba],
      [{ prog: 1, accts: [0, 2], data: [...u32le(2), ...u64le(500_000_000n)] }],
    );
    const ctx: VerdictContext = {
      lamportThreshold: 1_000_000_000,
      strict: true,
      recipientBlocklist: [b58],
    };
    const v = reviewBase64(toB64(msg), ctx);
    expect(v.decision).toBe("REJECT");
  });
});

// ---------------------------------------------------------------------------
// S5: Recall preserved — malicious families still caught in DEFAULT mode
// ---------------------------------------------------------------------------

describe("S5: recall preserved in DEFAULT mode", () => {
  it("S5.1 SPL SetAuthority(AccountOwner) still REJECT in DEFAULT", () => {
    // This is the primary malicious case: changing token account ownership.
    const setAuth = [6, 2, 1, ...key(9)]; // AccountOwner change, Some newAuth
    const msg = buildMessage(
      [1, 0, 1],
      [1, 3, SPL_TOKEN],
      [{ prog: 2, accts: [1, 0], data: setAuth }],
    );
    const v = reviewBase64(toB64(msg), DEFAULT_CTX);
    expect(v.decision).toBe("REJECT");
    expect(v.findings.some((f) => f.id === "spl-set-authority" && f.severity === "REJECT")).toBe(true);
  });

  it("S5.2 System Assign → still REJECT in DEFAULT", () => {
    // System Assign (u32-LE tag 1) changes the program owner of an account.
    const msg = buildMessage(
      [1, 0, 1],
      [1, SYSTEM, 3],
      [{ prog: 1, accts: [2], data: u32le(1) }], // Assign
    );
    const v = reviewBase64(toB64(msg), DEFAULT_CTX);
    expect(v.decision).toBe("REJECT");
    expect(v.findings.some((f) => f.id === "system-assign" && f.severity === "REJECT")).toBe(true);
  });

  it("S5.3 bare durable nonce alone → HOLD in DEFAULT (not REJECT)", () => {
    const msg = buildMessage(
      [1, 0, 1],
      [1, SYSTEM, 3],
      [{ prog: 1, accts: [2, 0], data: u32le(4) }], // AdvanceNonce only
    );
    const vDefault = reviewBase64(toB64(msg), DEFAULT_CTX);
    const vStrict = reviewBase64(toB64(msg), STRICT_CTX);
    expect(vDefault.decision).toBe("HOLD");
    expect(vStrict.decision).toBe("HOLD"); // bare nonce is HOLD in both modes
    expect(vDefault.reason).not.toContain("Drift");
    expect(vStrict.reason).not.toContain("Drift");
  });

  it("S5.4 bare durable nonce + governanceContext → REJECT in both modes", () => {
    const msg = buildMessage(
      [1, 0, 1],
      [1, SYSTEM, 3],
      [{ prog: 1, accts: [2, 0], data: u32le(4) }],
    );
    const defaultGov: VerdictContext = { ...DEFAULT_CTX, governanceContext: true };
    const strictGov: VerdictContext = { ...STRICT_CTX, governanceContext: true };

    const vDefault = reviewBase64(toB64(msg), defaultGov);
    const vStrict = reviewBase64(toB64(msg), strictGov);
    expect(vDefault.decision).toBe("REJECT");
    expect(vStrict.decision).toBe("REJECT");
    expect(vDefault.reason.toLowerCase()).toMatch(/governance|policy/);
    expect(vStrict.reason.toLowerCase()).toMatch(/governance|policy/);
  });
});

// ---------------------------------------------------------------------------
// S6: Strict-vs-default monotone invariant (via buildVerdict directly)
// ---------------------------------------------------------------------------

describe("S6: strict-vs-default monotone invariant", () => {
  const SEVERITY_ORDER = { SIGN: 0, HOLD: 1, REJECT: 2 };

  function makeDummyOutflow(): StaticOutflow {
    return {
      lamports: "0",
      splTransfers: [],
      exceedsLamportThreshold: false,
      lamportTransfers: [],
      outboundToNonSigner: false,
    };
  }

  it("S6.1 strict cannot produce SIGN where default produces HOLD", () => {
    // A finding that produces HOLD in default should produce at least HOLD in strict.
    const holdFinding: Finding = {
      id: "some-hold",
      label: "Some HOLD finding",
      severity: "HOLD",
      instructionIndex: 0,
      programId: "SomeProgramId11111111111111111111111111111111",
      detail: "A HOLD finding that does not escalate in default.",
      mapsToLoss: "Some potential loss.",
    };

    const vDefault = buildVerdict({
      messageVersion: "legacy",
      findings: [holdFinding],
      outflow: makeDummyOutflow(),
      unknownPrograms: [],
      unknownProgramWritable: false,
      altLookupsPresent: false,
      rolesUnverified: false,
      strict: false,
    });
    const vStrict = buildVerdict({
      messageVersion: "legacy",
      findings: [holdFinding],
      outflow: makeDummyOutflow(),
      unknownPrograms: [],
      unknownProgramWritable: false,
      altLookupsPresent: false,
      rolesUnverified: false,
      strict: true,
    });

    expect(SEVERITY_ORDER[vStrict.decision]).toBeGreaterThanOrEqual(SEVERITY_ORDER[vDefault.decision]);
    expect(vStrict.decision).not.toBe("SIGN");
  });

  it("S6.2 strict cannot produce HOLD where default produces REJECT", () => {
    // A REJECT-class finding in default must also be REJECT in strict.
    const rejectFinding: Finding = {
      id: "spl-set-authority",
      label: "SPL Token: SetAuthority (AccountOwner change)",
      severity: "REJECT",
      instructionIndex: 0,
      programId: SPL_TOKEN,
      detail: "SetAuthority changes the account owner.",
      mapsToLoss: "Account ownership transfer.",
    };

    const vDefault = buildVerdict({
      messageVersion: "legacy",
      findings: [rejectFinding],
      outflow: makeDummyOutflow(),
      unknownPrograms: [],
      unknownProgramWritable: false,
      altLookupsPresent: false,
      rolesUnverified: false,
      strict: false,
    });
    const vStrict = buildVerdict({
      messageVersion: "legacy",
      findings: [rejectFinding],
      outflow: makeDummyOutflow(),
      unknownPrograms: [],
      unknownProgramWritable: false,
      altLookupsPresent: false,
      rolesUnverified: false,
      strict: true,
    });

    expect(vDefault.decision).toBe("REJECT");
    expect(vStrict.decision).toBe("REJECT");
    expect(SEVERITY_ORDER[vStrict.decision]).toBeGreaterThanOrEqual(SEVERITY_ORDER[vDefault.decision]);
  });
});

// ---------------------------------------------------------------------------
// S6b: strict + governanceContext composed — both independently cause REJECT
//      and together they also REJECT; the combination is coherent
// ---------------------------------------------------------------------------

describe("S6b: strict + governanceContext combined on durable-nonce + HOLD-class-only", () => {
  /**
   * Build a legacy message with:
   *   ix0 = AdvanceNonceAccount (durable-nonce marker)
   *   ix1 = Jupiter unknown instruction (HOLD-class only, not REJECT)
   *
   * This composite is:
   *   - HOLD in DEFAULT mode (nonce + HOLD-only finding → HOLD)
   *   - REJECT in STRICT mode (broad driftCompositeStrict)
   *   - REJECT in governanceContext alone (bare nonce → governance reject)
   *   - REJECT in STRICT + governanceContext together (both escalate)
   */
  const JUPITER_V6 = "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4";

  function buildNoncePlusJupiter(): Uint8Array {
    const unknownJupDisc = [0xaa, 0xbb, 0xcc, 0xdd, 0x11, 0x22, 0x33, 0x44];
    return buildMessage(
      [1, 0, 1],
      [1, SYSTEM, JUPITER_V6, 3],
      [
        { prog: 1, accts: [3, 0], data: u32le(4) },        // ix0: AdvanceNonce
        { prog: 2, accts: [0, 3], data: unknownJupDisc },  // ix1: Jupiter HOLD-only
      ],
    );
  }

  it("S6b.1 DEFAULT: durable-nonce + HOLD-only → HOLD (baseline)", () => {
    const v = reviewBase64(toB64(buildNoncePlusJupiter()), DEFAULT_CTX);
    expect(v.decision).toBe("HOLD");
  });

  it("S6b.2 STRICT alone: durable-nonce + HOLD-only → REJECT", () => {
    const v = reviewBase64(toB64(buildNoncePlusJupiter()), STRICT_CTX);
    expect(v.decision).toBe("REJECT");
  });

  it("S6b.3 governanceContext alone: durable-nonce → REJECT (governance policy)", () => {
    const ctx: VerdictContext = { ...DEFAULT_CTX, governanceContext: true };
    const v = reviewBase64(toB64(buildNoncePlusJupiter()), ctx);
    expect(v.decision).toBe("REJECT");
    expect(v.reason.toLowerCase()).toMatch(/governance|policy/);
  });

  it("S6b.4 STRICT + governanceContext together: durable-nonce + HOLD-only → REJECT (composed)", () => {
    const ctx: VerdictContext = { ...STRICT_CTX, governanceContext: true };
    const v = reviewBase64(toB64(buildNoncePlusJupiter()), ctx);
    expect(v.decision).toBe("REJECT");
  });

  it("S6b.5 strict+governance produces REJECT at least as severe as each alone", () => {
    const strictOnly: VerdictContext = { ...DEFAULT_CTX, strict: true };
    const govOnly: VerdictContext = { ...DEFAULT_CTX, governanceContext: true };
    const both: VerdictContext = { ...DEFAULT_CTX, strict: true, governanceContext: true };
    const ORDER: Record<string, number> = { SIGN: 0, HOLD: 1, REJECT: 2 };

    const vStrict = reviewBase64(toB64(buildNoncePlusJupiter()), strictOnly);
    const vGov = reviewBase64(toB64(buildNoncePlusJupiter()), govOnly);
    const vBoth = reviewBase64(toB64(buildNoncePlusJupiter()), both);

    // Combined must be >= strict alone
    expect(ORDER[vBoth.decision]!).toBeGreaterThanOrEqual(ORDER[vStrict.decision]!);
    // Combined must be >= governance alone
    expect(ORDER[vBoth.decision]!).toBeGreaterThanOrEqual(ORDER[vGov.decision]!);
  });
});

// ---------------------------------------------------------------------------
// S7: HOLD reason string content in DEFAULT mode
// ---------------------------------------------------------------------------

describe("S7: HOLD reason string content (DEFAULT mode)", () => {
  function buildUnknownWritableMsg(): Uint8Array {
    return buildMessage(
      [1, 0, 1],
      [1, 2, UNKNOWN_PROG_FILLER],
      [{ prog: 2, accts: [0, 1], data: [0x01, 0x02, 0x03] }],
    );
  }

  it("S7.1 DEFAULT unknownWritable HOLD reason mentions '--strict' as the upgrade path", () => {
    const v = reviewBase64(toB64(buildUnknownWritableMsg()), DEFAULT_CTX);
    expect(v.decision).toBe("HOLD");
    expect(v.reason).toContain("--strict");
    expect(v.reason.toLowerCase()).toMatch(/unknown program/);
  });

  it("S7.2 DEFAULT unknownWritable HOLD reason contains the unknown program address", () => {
    const v = reviewBase64(toB64(buildUnknownWritableMsg()), DEFAULT_CTX);
    expect(v.decision).toBe("HOLD");
    expect(v.unknownPrograms.length).toBeGreaterThan(0);
    // Each unknown program address must appear in the reason string
    for (const prog of v.unknownPrograms) {
      expect(v.reason).toContain(prog);
    }
  });

  it("S7.3 STRICT unknownWritable REJECT reason mentions 'uncatalogued' or 'unknown'", () => {
    const v = reviewBase64(toB64(buildUnknownWritableMsg()), STRICT_CTX);
    expect(v.decision).toBe("REJECT");
    expect(v.reason.toLowerCase()).toMatch(/uncatalogued|unknown/);
  });
});
