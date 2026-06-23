/**
 * squad-verdict.test.ts -- FEATURE 3 acceptance tests.
 *
 * Tests the integration of Squads vaultTransactionExecute detection with the
 * verdict layer, durable-nonce escalation broadening, and governanceContext.
 *
 * Test groups:
 *   H  Squads vaultTransactionExecute + verdict integration
 *      H1 execute without inner bytes -> HOLD (unverified finding injected)
 *      H2 execute WITH inner update_admin -> REJECT + reason mentions authority
 *      H3 execute WITH inner unresolved (ALT) inner -> HOLD or REJECT
 *   I  Real-Drift shape: durable-nonce + Squads execute -> REJECT
 *      I1 durable-nonce + execute without inner -> REJECT (driftComposite)
 *      I2 durable-nonce + execute with inner update_admin -> REJECT + authority mention
 *   J  Bare durable nonce stays HOLD (regression guard)
 *      J1 bare durable nonce ALONE -> HOLD (not REJECT)
 *      J2 bare durable nonce ALONE reason does NOT contain "Drift"
 *   K  governanceContext flag
 *      K1 bare nonce + governanceContext -> REJECT
 *      K2 reason mentions governance policy
 *      K3 durable nonce + execute without inner + governanceContext -> REJECT
 *   L  Fail-closed: never SIGN a Squads execute (with or without inner)
 *      L1 execute without inner -> not SIGN
 *      L2 execute with benign-data inner -> not SIGN
 */

import { describe, it, expect } from "vitest";
import { reviewBase64, buildVerdict } from "../src/verdict.ts";
import { u32le, u64le, key, toB64 } from "./helpers.ts";
import type { VerdictContext } from "../src/types.ts";

// ---------------------------------------------------------------------------
// Program constants
// ---------------------------------------------------------------------------

const SYSTEM = "11111111111111111111111111111111";
const SQUADS_V4 = "SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf";
const SPL_TOKEN = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";

/** sha256("global:vault_transaction_execute")[0..8] = c208a15799a419ab */
const VAULT_TX_EXECUTE_DISC = [0xc2, 0x08, 0xa1, 0x57, 0x99, 0xa4, 0x19, 0xab];
/** VaultTransaction account discriminator: sha256("account:VaultTransaction")[0..8] */
const VAULT_TX_ACCOUNT_DISC = [0xa8, 0xfa, 0xa2, 0x64, 0x51, 0x0e, 0xa2, 0xcf];
/** update_admin discriminator: a1b028d53cb8b3e4 */
const UPDATE_ADMIN_DISC = [0xa1, 0xb0, 0x28, 0xd5, 0x3c, 0xb8, 0xb3, 0xe4];

// ---------------------------------------------------------------------------
// Helpers
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

/**
 * Build a synthetic VaultTransaction account (borsh-encoded) with a SINGLE
 * inner instruction whose programIdIndex is resolvable from accountKeys.
 *
 * Layout mirrors buildMinimalVaultTx in squads.test.ts (u32-LE Vec prefixes).
 * numKeys keys are filled with bytes 0x10+i; the inner instruction uses
 * instrProgramIdIndex to select accountKeys[instrProgramIdIndex], and
 * instrData as its data.
 */
function buildSyntheticVaultTx(opts: {
  instrProgramIdIndex: number;
  instrData: number[];
  numKeys?: number;
}): Uint8Array {
  const numKeys = opts.numKeys ?? 3;
  const bytes: number[] = [];

  // discriminator (8 bytes)
  bytes.push(...VAULT_TX_ACCOUNT_DISC);
  // multisig Pubkey (32)
  bytes.push(...new Array(32).fill(0x01));
  // creator Pubkey (32)
  bytes.push(...new Array(32).fill(0x02));
  // index u64-LE (8)
  bytes.push(1, 0, 0, 0, 0, 0, 0, 0);
  // bump, vault_index, vault_bump
  bytes.push(255, 0, 254);
  // ephemeral_signer_bumps Vec<u8>: length=0
  bytes.push(0, 0, 0, 0);

  // --- VaultTransactionMessage ---
  bytes.push(1, 1, 1); // num_signers, num_writable_signers, num_writable_non_signers

  // account_keys Vec<Pubkey>: numKeys entries (each 32 bytes, filled with 0x10+i)
  bytes.push(...u32le(numKeys));
  for (let i = 0; i < numKeys; i++) {
    bytes.push(...new Array(32).fill(0x10 + i));
  }

  // instructions Vec: 1 entry
  bytes.push(...u32le(1));
  bytes.push(opts.instrProgramIdIndex);
  bytes.push(...u32le(0)); // accountIndexes: empty
  bytes.push(...u32le(opts.instrData.length));
  bytes.push(...opts.instrData);

  // address_table_lookups Vec: empty
  bytes.push(...u32le(0));

  return new Uint8Array(bytes);
}

/**
 * Build a VaultTransaction with an inner instruction whose programIdIndex is
 * in ALT space (>= numKeys), so programId cannot be resolved offline.
 */
function buildUnresolvedVaultTx(): Uint8Array {
  return buildSyntheticVaultTx({
    numKeys: 3,
    instrProgramIdIndex: 5, // >= 3 keys => ALT space, unresolved
    instrData: [0xde, 0xad, 0xbe, 0xef, 0x00, 0x00, 0x00, 0x00],
  });
}

/**
 * Build a VaultTransaction that decodes cleanly but carries ZERO inner
 * instructions (empty instruction vector). Used to prove the gate never SIGNs
 * a Squads execute whose decoded inner content is empty.
 */
function buildEmptyVaultTx(): Uint8Array {
  const numKeys = 3;
  const bytes: number[] = [];
  bytes.push(...VAULT_TX_ACCOUNT_DISC);
  bytes.push(...new Array(32).fill(0x01)); // multisig
  bytes.push(...new Array(32).fill(0x02)); // creator
  bytes.push(1, 0, 0, 0, 0, 0, 0, 0); // index u64-LE
  bytes.push(255, 0, 254); // bump, vault_index, vault_bump
  bytes.push(0, 0, 0, 0); // ephemeral_signer_bumps Vec<u8> len=0
  bytes.push(1, 1, 1); // num_signers, num_writable_signers, num_writable_non_signers
  bytes.push(...u32le(numKeys));
  for (let i = 0; i < numKeys; i++) bytes.push(...new Array(32).fill(0x10 + i));
  bytes.push(...u32le(0)); // instructions Vec: ZERO entries
  bytes.push(...u32le(0)); // address_table_lookups Vec: empty
  return new Uint8Array(bytes);
}

// ---------------------------------------------------------------------------
// H: Squads vaultTransactionExecute + verdict integration
// ---------------------------------------------------------------------------

describe("H: Squads vaultTransactionExecute verdict integration", () => {
  it("H1 execute WITHOUT inner bytes -> HOLD (squads-execute-unverified finding injected)", () => {
    // A message with a Squads vaultTransactionExecute top-level instruction,
    // but no VaultTransaction PDA bytes provided to reviewBase64.
    const msg = buildMessage(
      [1, 0, 1],
      [1, SQUADS_V4],
      [{ prog: 1, accts: [0], data: VAULT_TX_EXECUTE_DISC }],
    );
    const v = reviewBase64(toB64(msg));
    expect(v.decision).toBe("HOLD");
    const f = v.findings.find((x) => x.id === "squads-execute-unverified");
    expect(f).toBeTruthy();
    expect(f!.severity).toBe("HOLD");
    expect(f!.detail).toContain("VaultTransaction PDA");
  });

  it("H2 execute WITH inner update_admin -> REJECT, reason mentions authority transfer", () => {
    // A Squads execute message with a synthetic VaultTransaction PDA that has
    // an update_admin inner instruction (discriminator a1b028d53cb8b3e4).
    const msg = buildMessage(
      [1, 0, 1],
      [1, SQUADS_V4],
      [{ prog: 1, accts: [0], data: VAULT_TX_EXECUTE_DISC }],
    );
    // Build VaultTransaction with inner instrProgramIdIndex=0 (resolves to
    // accountKeys[0] which is some key filled with 0x10), instrData = UPDATE_ADMIN_DISC.
    const vaultTxBytes = buildSyntheticVaultTx({
      numKeys: 3,
      instrProgramIdIndex: 0,
      instrData: UPDATE_ADMIN_DISC,
    });
    const v = reviewBase64(toB64(msg), { lamportThreshold: 1_000_000_000 }, vaultTxBytes);
    expect(v.decision).toBe("REJECT");
    // The reason should surface the inner authority transfer
    const innerFinding = v.findings.find((f) => f.id === "anchor-inner-update_admin");
    expect(innerFinding).toBeTruthy();
    expect(innerFinding!.severity).toBe("REJECT");
    // Reason text mentions the inner CPI danger
    expect(v.reason.toLowerCase()).toMatch(/inner|vault|squads|authority/);
  });

  it("H3 execute WITH unresolved inner (ALT) -> HOLD (fail-closed unresolved)", () => {
    const msg = buildMessage(
      [1, 0, 1],
      [1, SQUADS_V4],
      [{ prog: 1, accts: [0], data: VAULT_TX_EXECUTE_DISC }],
    );
    const vaultTxBytes = buildUnresolvedVaultTx();
    const v = reviewBase64(toB64(msg), { lamportThreshold: 1_000_000_000 }, vaultTxBytes);
    // Unresolved inner -> squads-inner-unresolved HOLD finding
    const f = v.findings.find((x) => x.id === "squads-inner-unresolved");
    expect(f).toBeTruthy();
    expect(f!.severity).toBe("HOLD");
    expect(v.decision === "HOLD" || v.decision === "REJECT").toBe(true);
  });
});

// ---------------------------------------------------------------------------
// I: Real-Drift shape (durable-nonce + Squads execute)
// ---------------------------------------------------------------------------

describe("I: real-Drift shape (durable-nonce + Squads vaultTransactionExecute)", () => {
  it("I1 DEFAULT: durable-nonce + Squads execute WITHOUT inner -> HOLD (driftComposite default uses narrowed formula)", () => {
    // ix0 = AdvanceNonceAccount (System), ix1 = vaultTransactionExecute (Squads)
    // In DEFAULT mode: durable-nonce + squads-execute-unverified (a HOLD-class finding) → HOLD.
    // The narrowed driftCompositeDefault only REJECTs on authority/ownership change or REJECT-class findings.
    const msg = buildMessage(
      [1, 0, 1],
      [1, SYSTEM, SQUADS_V4, 3],
      [
        { prog: 1, accts: [2, 0], data: u32le(4) },       // ix0: AdvanceNonce (System=idx1)
        { prog: 2, accts: [0], data: VAULT_TX_EXECUTE_DISC }, // ix1: vaultTransactionExecute
      ],
    );
    const v = reviewBase64(toB64(msg));
    expect(v.decision).toBe("HOLD");
    // squads-execute-unverified HOLD finding is still present
    expect(v.findings.some((f) => f.id === "squads-execute-unverified")).toBe(true);
  });

  it("I1-strict: durable-nonce + Squads execute WITHOUT inner + strict=true -> REJECT (broad driftComposite)", () => {
    // In STRICT mode, durable-nonce + any HOLD finding → REJECT.
    const msg = buildMessage(
      [1, 0, 1],
      [1, SYSTEM, SQUADS_V4, 3],
      [
        { prog: 1, accts: [2, 0], data: u32le(4) },
        { prog: 2, accts: [0], data: VAULT_TX_EXECUTE_DISC },
      ],
    );
    const ctx: VerdictContext = { lamportThreshold: 1_000_000_000, strict: true };
    const v = reviewBase64(toB64(msg), ctx);
    expect(v.decision).toBe("REJECT");
    expect(v.findings.some((f) => f.id === "squads-execute-unverified")).toBe(true);
  });

  it("I2 durable-nonce + execute WITH inner update_admin -> REJECT, reason mentions authority", () => {
    const msg = buildMessage(
      [1, 0, 1],
      [1, SYSTEM, SQUADS_V4, 3],
      [
        { prog: 1, accts: [2, 0], data: u32le(4) },
        { prog: 2, accts: [0], data: VAULT_TX_EXECUTE_DISC },
      ],
    );
    const vaultTxBytes = buildSyntheticVaultTx({
      numKeys: 3,
      instrProgramIdIndex: 0,
      instrData: UPDATE_ADMIN_DISC,
    });
    const v = reviewBase64(toB64(msg), { lamportThreshold: 1_000_000_000 }, vaultTxBytes);
    expect(v.decision).toBe("REJECT");
    // Should mention the inner authority transfer in the reason
    expect(v.reason).toContain("inner instruction");
    expect(v.reason.toLowerCase()).toMatch(/authority|admin/);
    // The inner finding should be present
    expect(v.findings.some((f) => f.id === "anchor-inner-update_admin")).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// J: Bare durable nonce HOLD regression guard
// ---------------------------------------------------------------------------

describe("J: bare durable nonce stays HOLD (regression guard)", () => {
  it("J1 bare durable nonce ALONE -> HOLD, not REJECT", () => {
    const msg = buildMessage(
      [1, 0, 1],
      [1, SYSTEM, 3],
      [{ prog: 1, accts: [2, 0], data: u32le(4) }],
    );
    const v = reviewBase64(toB64(msg));
    expect(v.decision).toBe("HOLD");
  });

  it("J2 bare durable nonce ALONE reason does NOT contain 'Drift'", () => {
    const msg = buildMessage(
      [1, 0, 1],
      [1, SYSTEM, 3],
      [{ prog: 1, accts: [2, 0], data: u32le(4) }],
    );
    const v = reviewBase64(toB64(msg));
    expect(v.reason).not.toContain("Drift");
  });
});

// ---------------------------------------------------------------------------
// K: governanceContext flag
// ---------------------------------------------------------------------------

describe("K: governanceContext flag escalates bare durable nonce to REJECT", () => {
  it("K1 bare durable nonce + governanceContext -> REJECT", () => {
    const msg = buildMessage(
      [1, 0, 1],
      [1, SYSTEM, 3],
      [{ prog: 1, accts: [2, 0], data: u32le(4) }],
    );
    const ctx: VerdictContext = { lamportThreshold: 1_000_000_000, governanceContext: true };
    const v = reviewBase64(toB64(msg), ctx);
    expect(v.decision).toBe("REJECT");
  });

  it("K2 governanceContext REJECT reason mentions governance policy", () => {
    const msg = buildMessage(
      [1, 0, 1],
      [1, SYSTEM, 3],
      [{ prog: 1, accts: [2, 0], data: u32le(4) }],
    );
    const ctx: VerdictContext = { lamportThreshold: 1_000_000_000, governanceContext: true };
    const v = reviewBase64(toB64(msg), ctx);
    expect(v.reason.toLowerCase()).toMatch(/governance|policy/);
  });

  it("K3 durable nonce + execute without inner + governanceContext -> REJECT", () => {
    const msg = buildMessage(
      [1, 0, 1],
      [1, SYSTEM, SQUADS_V4, 3],
      [
        { prog: 1, accts: [2, 0], data: u32le(4) },
        { prog: 2, accts: [0], data: VAULT_TX_EXECUTE_DISC },
      ],
    );
    const ctx: VerdictContext = { lamportThreshold: 1_000_000_000, governanceContext: true };
    const v = reviewBase64(toB64(msg), ctx);
    expect(v.decision).toBe("REJECT");
  });
});

// ---------------------------------------------------------------------------
// L: Fail-closed: never SIGN a Squads execute
// ---------------------------------------------------------------------------

describe("L: fail-closed: Squads execute never SIGN", () => {
  it("L1 execute without inner -> not SIGN", () => {
    const msg = buildMessage(
      [1, 0, 1],
      [1, SQUADS_V4],
      [{ prog: 1, accts: [0], data: VAULT_TX_EXECUTE_DISC }],
    );
    const v = reviewBase64(toB64(msg));
    expect(v.decision).not.toBe("SIGN");
  });

  it("L2 execute with opaque inner data (no catalog match) -> not SIGN", () => {
    const msg = buildMessage(
      [1, 0, 1],
      [1, SQUADS_V4],
      [{ prog: 1, accts: [0], data: VAULT_TX_EXECUTE_DISC }],
    );
    // Build VaultTransaction with innocuous-looking inner data (no catalog discriminator)
    const vaultTxBytes = buildSyntheticVaultTx({
      numKeys: 3,
      instrProgramIdIndex: 0,
      instrData: [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
    });
    const v = reviewBase64(toB64(msg), { lamportThreshold: 1_000_000_000 }, vaultTxBytes);
    // Even with unrecognized inner data, must not be SIGN (opaque inner -> HOLD)
    expect(v.decision).not.toBe("SIGN");
  });

  it("L3 execute with a vault that decodes to ZERO inner instructions -> not SIGN", () => {
    // Regression: a VaultTransaction PDA that decodes cleanly but carries an
    // EMPTY instruction vector gives the gate nothing affirmative to show the
    // signer. The inner content is effectively unknown, so it must be treated
    // exactly like a missing inner (mandatory HOLD injected) and NEVER SIGN.
    // Previously squadsExecuteWithoutInner only fired when decode FAILED, so a
    // zero-instruction vault coasted a Squads execute straight to SIGN.
    const msg = buildMessage(
      [1, 0, 1],
      [1, SQUADS_V4],
      [{ prog: 1, accts: [0], data: VAULT_TX_EXECUTE_DISC }],
    );
    const emptyVaultTx = buildEmptyVaultTx();
    const v = reviewBase64(toB64(msg), { lamportThreshold: 1_000_000_000 }, emptyVaultTx);
    expect(v.decision).not.toBe("SIGN");
    expect(v.findings.some((f) => f.id === "squads-execute-unverified")).toBe(true);
  });
});
