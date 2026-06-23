/**
 * roles-alt-resolve.test.ts -- T_A2: resolvedAltTables channel in deriveRoles.
 *
 * Tests that providing resolvedAltTables in VerdictContext allows the core to
 * produce verified (addressVerified=true) roles for ALT-sourced accounts.
 *
 * Also tests the end-to-end effect on reviewBase64: a v0 message that is HOLD
 * due to unresolved ALT becomes SIGN when the map fully resolves all ALT roles
 * AND nothing else flags; stays HOLD when map is missing/partial.
 *
 * OFFLINE: no network, synthetic byte buffers only.
 */

import { describe, it, expect } from "vitest";
import { deriveRoles, hasUnverifiedRoles, RESERVED_ACCOUNT_KEYS } from "../src/roles.ts";
import { decodeMessageBytes } from "../src/decode.ts";
import { reviewBase64 } from "../src/verdict.ts";
import { base58Encode } from "../src/decode.ts";
import { v0Bytes, toB64, key } from "./helpers.ts";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** A 32-byte key filled with a single byte value (as Uint8Array). */
function testKey32(byte: number): Uint8Array {
  return new Uint8Array(32).fill(byte);
}

// Table and resolved address keys for tests
const TABLE_BYTE = 50;
const TABLE_KEY_BYTES = testKey32(TABLE_BYTE);
const TABLE_B58 = base58Encode(TABLE_KEY_BYTES);

const RESOLVED_W0_BYTES = testKey32(0x10);
const RESOLVED_W0_B58 = base58Encode(RESOLVED_W0_BYTES);

const RESOLVED_R0_BYTES = testKey32(0x20);
const RESOLVED_R0_B58 = base58Encode(RESOLVED_R0_BYTES);

/**
 * Build a minimal benign v0 message with one ALT that contributes:
 *   - writableIndexes: [0] (ALT slot 0)
 *   - readonlyIndexes: [1] (ALT slot 1)
 * The ALT table address is TABLE_B58.
 * No dangerous instructions; all static keys are fee payer only.
 */
function buildV0WithAlt(): Uint8Array {
  return v0Bytes(
    [1, 0, 0], // header: 1 signer, 0 readonly signers, 0 readonly unsigned
    [1], // single static key: fee payer (key(1))
    [], // no instructions
    [{ table: TABLE_BYTE, writable: [0], readonly: [1] }], // 1 writable ALT slot, 1 readonly
  );
}

// ---------------------------------------------------------------------------
// T_A2.1 — no resolvedAltTables => ALT roles have addressVerified=false
// ---------------------------------------------------------------------------

describe("T_A2.1 no resolvedAltTables -> ALT roles are addressVerified=false", () => {
  const msg = decodeMessageBytes(buildV0WithAlt());

  it("message has altLookupsPresent", () => {
    expect(msg.altLookupsPresent).toBe(true);
  });

  it("without resolvedAltTables, ALT roles are unverified", () => {
    const roles = deriveRoles(msg, { reservedAccountKeys: RESERVED_ACCOUNT_KEYS });
    const altRoles = roles.filter((r) => !r.addressVerified);
    expect(altRoles.length).toBe(2);
    // Addresses are synthetic
    expect(altRoles[0]!.address).toBe(`alt:${TABLE_B58}#w0`);
    expect(altRoles[1]!.address).toBe(`alt:${TABLE_B58}#r1`);
  });

  it("hasUnverifiedRoles is true without resolution", () => {
    const roles = deriveRoles(msg, { reservedAccountKeys: RESERVED_ACCOUNT_KEYS });
    expect(hasUnverifiedRoles(roles)).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// T_A2.2 — with resolvedAltTables fully covering indexes => addressVerified=true
// ---------------------------------------------------------------------------

describe("T_A2.2 resolvedAltTables fully resolved -> ALT roles get real address + addressVerified=true", () => {
  const msg = decodeMessageBytes(buildV0WithAlt());

  // ALT table has addresses at slot 0 = RESOLVED_W0 and slot 1 = RESOLVED_R0
  const resolvedAltTables = new Map<string, readonly string[]>([
    [TABLE_B58, [RESOLVED_W0_B58, RESOLVED_R0_B58]],
  ]);

  it("ALT roles have real addresses when map covers the table", () => {
    const roles = deriveRoles(msg, {
      reservedAccountKeys: RESERVED_ACCOUNT_KEYS,
      resolvedAltTables,
    });
    const altRoles = roles.filter((r) => r.index >= 1); // static keys come first
    expect(altRoles[0]!.address).toBe(RESOLVED_W0_B58);
    expect(altRoles[0]!.addressVerified).toBe(true);
    expect(altRoles[1]!.address).toBe(RESOLVED_R0_B58);
    expect(altRoles[1]!.addressVerified).toBe(true);
  });

  it("hasUnverifiedRoles is false when all ALT roles are resolved", () => {
    const roles = deriveRoles(msg, {
      reservedAccountKeys: RESERVED_ACCOUNT_KEYS,
      resolvedAltTables,
    });
    expect(hasUnverifiedRoles(roles)).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// T_A2.3 — partial/out-of-range map => addressVerified=false (fail-closed)
// ---------------------------------------------------------------------------

describe("T_A2.3 partial/out-of-range resolvedAltTables -> still addressVerified=false", () => {
  const msg = decodeMessageBytes(buildV0WithAlt());

  it("table present but indexes out of range -> unverified", () => {
    // ALT table only has 1 address (slot 0) but we need slots 0 AND 1
    const partialMap = new Map<string, readonly string[]>([
      [TABLE_B58, [RESOLVED_W0_B58]], // only slot 0, not slot 1
    ]);
    const roles = deriveRoles(msg, {
      reservedAccountKeys: RESERVED_ACCOUNT_KEYS,
      resolvedAltTables: partialMap,
    });
    const altRoles = roles.filter((r) => r.index >= 1);
    // slot 0 writable is in range -> verified
    expect(altRoles[0]!.addressVerified).toBe(true);
    expect(altRoles[0]!.address).toBe(RESOLVED_W0_B58);
    // slot 1 readonly is out of range -> still unverified
    expect(altRoles[1]!.addressVerified).toBe(false);
    expect(altRoles[1]!.address).toBe(`alt:${TABLE_B58}#r1`);
  });

  it("table absent from map -> unverified", () => {
    const emptyMap = new Map<string, readonly string[]>();
    const roles = deriveRoles(msg, {
      reservedAccountKeys: RESERVED_ACCOUNT_KEYS,
      resolvedAltTables: emptyMap,
    });
    const altRoles = roles.filter((r) => !r.addressVerified);
    expect(altRoles.length).toBe(2);
  });

  it("hasUnverifiedRoles stays true when only partially resolved", () => {
    const partialMap = new Map<string, readonly string[]>([
      [TABLE_B58, [RESOLVED_W0_B58]], // missing slot 1
    ]);
    const roles = deriveRoles(msg, {
      reservedAccountKeys: RESERVED_ACCOUNT_KEYS,
      resolvedAltTables: partialMap,
    });
    expect(hasUnverifiedRoles(roles)).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// T_A2.4 — reserved-key demotion applies to resolved ALT roles
// ---------------------------------------------------------------------------

describe("T_A2.4 resolved ALT role is demoted if it's a reserved key", () => {
  // Build a v0 message where the ALT writable slot resolves to the System program.
  const SYSTEM_B58 = "11111111111111111111111111111111";
  const SYSTEM_BYTES = new Uint8Array(32); // all zeros

  const resolvedAltTables = new Map<string, readonly string[]>([
    [TABLE_B58, [SYSTEM_B58, RESOLVED_R0_B58]],
  ]);

  it("resolved writable ALT that is a reserved key has writableRuntime=false", () => {
    const msg = decodeMessageBytes(buildV0WithAlt());
    const roles = deriveRoles(msg, {
      reservedAccountKeys: RESERVED_ACCOUNT_KEYS,
      resolvedAltTables,
    });
    const altWritable = roles.find((r) => r.address === SYSTEM_B58);
    expect(altWritable).toBeDefined();
    expect(altWritable!.addressVerified).toBe(true);
    expect(altWritable!.writablePartition).toBe(true);
    expect(altWritable!.writableRuntime).toBe(false); // demoted by reserved set
    expect(altWritable!.demotedToReadonly).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// T_A2.5 — end-to-end reviewBase64: HOLD becomes SIGN when fully resolved
// ---------------------------------------------------------------------------

describe("T_A2.5 reviewBase64 end-to-end: HOLD->SIGN with fully resolved ALT", () => {
  const b64 = toB64(buildV0WithAlt());

  it("without resolvedAltTables, v0 message with ALT is HOLD", () => {
    const v = reviewBase64(b64);
    expect(v.decision).toBe("HOLD");
    expect(v.flags.altLookupsPresent).toBe(true);
    expect(v.flags.rolesUnverified).toBe(true);
  });

  it("with fully resolved table, benign v0 message becomes SIGN", () => {
    const resolvedAltTables = new Map<string, readonly string[]>([
      [TABLE_B58, [RESOLVED_W0_B58, RESOLVED_R0_B58]],
    ]);
    const v = reviewBase64(b64, {
      lamportThreshold: 1_000_000_000,
      resolvedAltTables,
    });
    expect(v.decision).toBe("SIGN");
    expect(v.flags.altLookupsPresent).toBe(true);
    expect(v.flags.rolesUnverified).toBe(false);
  });

  it("with partial resolution (table present, indexes incomplete), remains HOLD", () => {
    const partialMap = new Map<string, readonly string[]>([
      [TABLE_B58, [RESOLVED_W0_B58]], // only slot 0, missing slot 1 (r1)
    ]);
    const v = reviewBase64(b64, {
      lamportThreshold: 1_000_000_000,
      resolvedAltTables: partialMap,
    });
    expect(v.decision).toBe("HOLD");
    expect(v.flags.rolesUnverified).toBe(true);
  });

  it("with empty resolvedAltTables map (table absent), remains HOLD", () => {
    const v = reviewBase64(b64, {
      lamportThreshold: 1_000_000_000,
      resolvedAltTables: new Map(),
    });
    expect(v.decision).toBe("HOLD");
    expect(v.flags.rolesUnverified).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// T_A2.6 — Multi-table ALT: two distinct tables; partial resolution is fail-closed
// ---------------------------------------------------------------------------

describe("T_A2.6 multi-table ALT: two distinct tables, partial resolution stays HOLD", () => {
  // Build a v0 message with TWO distinct ALTs:
  //   TABLE_A (byte 0x50): writable index 0
  //   TABLE_B (byte 0x60): writable index 0
  // The message uses ALT-sourced account at slot 1 (from TABLE_A) and slot 2 (from TABLE_B).

  const TABLE_A_BYTE = 0x50;
  const TABLE_B_BYTE = 0x60;
  const TABLE_A_BYTES = new Uint8Array(32).fill(TABLE_A_BYTE);
  const TABLE_B_BYTES = new Uint8Array(32).fill(TABLE_B_BYTE);
  const TABLE_A_B58 = base58Encode(TABLE_A_BYTES);
  const TABLE_B_B58 = base58Encode(TABLE_B_BYTES);

  const RESOLVED_A0_BYTES = new Uint8Array(32).fill(0x1a);
  const RESOLVED_A0_B58 = base58Encode(RESOLVED_A0_BYTES);
  const RESOLVED_B0_BYTES = new Uint8Array(32).fill(0x1b);
  const RESOLVED_B0_B58 = base58Encode(RESOLVED_B0_BYTES);

  function buildV0TwoTables(): Uint8Array {
    return v0Bytes(
      [1, 0, 0],       // 1 signer, 0 readonly signers, 0 readonly unsigned
      [1],             // single static key: fee payer
      [],              // no instructions
      [
        { table: TABLE_A_BYTE, writable: [0], readonly: [] }, // ALT A: slot 0 writable
        { table: TABLE_B_BYTE, writable: [0], readonly: [] }, // ALT B: slot 0 writable
      ],
    );
  }

  const msgBytes = buildV0TwoTables();
  const msg = decodeMessageBytes(msgBytes);

  it("message has 2 address table lookups", () => {
    expect(msg.addressTableLookups.length).toBe(2);
    expect(msg.addressTableLookups[0]!.accountKey).toBe(TABLE_A_B58);
    expect(msg.addressTableLookups[1]!.accountKey).toBe(TABLE_B_B58);
  });

  it("with BOTH tables resolved → all ALT roles are addressVerified=true", () => {
    const resolvedAltTables = new Map<string, readonly string[]>([
      [TABLE_A_B58, [RESOLVED_A0_B58]],
      [TABLE_B_B58, [RESOLVED_B0_B58]],
    ]);
    const roles = deriveRoles(msg, {
      reservedAccountKeys: RESERVED_ACCOUNT_KEYS,
      resolvedAltTables,
    });
    const altRoles = roles.filter((r) => !r.verified); // ALT-sourced roles are not verified
    expect(altRoles.every((r) => r.addressVerified)).toBe(true);
    expect(hasUnverifiedRoles(roles)).toBe(false);
  });

  it("with ONLY table A resolved → table B role stays unverified (HOLD) — fail-closed per-table", () => {
    const resolvedAltTables = new Map<string, readonly string[]>([
      [TABLE_A_B58, [RESOLVED_A0_B58]],
      // TABLE_B intentionally omitted
    ]);
    const roles = deriveRoles(msg, {
      reservedAccountKeys: RESERVED_ACCOUNT_KEYS,
      resolvedAltTables,
    });
    // Table A role should be verified
    const tableARole = roles.find((r) => r.address === RESOLVED_A0_B58);
    expect(tableARole).toBeDefined();
    expect(tableARole!.addressVerified).toBe(true);
    // Table B role should remain unverified
    const tableBRole = roles.find((r) => r.address.startsWith("alt:") && r.address.includes(TABLE_B_B58));
    expect(tableBRole).toBeDefined();
    expect(tableBRole!.addressVerified).toBe(false);
    // Overall: still has unverified roles → HOLD
    expect(hasUnverifiedRoles(roles)).toBe(true);
  });

  it("end-to-end: both tables resolved → reviewBase64 can reach SIGN", () => {
    const b64 = toB64(msgBytes);
    const resolvedAltTables = new Map<string, readonly string[]>([
      [TABLE_A_B58, [RESOLVED_A0_B58]],
      [TABLE_B_B58, [RESOLVED_B0_B58]],
    ]);
    const v = reviewBase64(b64, { lamportThreshold: 1_000_000_000, resolvedAltTables });
    expect(v.flags.rolesUnverified).toBe(false);
    expect(v.decision).toBe("SIGN");
  });

  it("end-to-end: only table A resolved → remains HOLD (table B still unverified)", () => {
    const b64 = toB64(msgBytes);
    const resolvedAltTables = new Map<string, readonly string[]>([
      [TABLE_A_B58, [RESOLVED_A0_B58]],
    ]);
    const v = reviewBase64(b64, { lamportThreshold: 1_000_000_000, resolvedAltTables });
    expect(v.flags.rolesUnverified).toBe(true);
    expect(v.decision).toBe("HOLD");
  });
});
