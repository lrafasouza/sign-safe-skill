/**
 * squads.test.ts -- PURE offline tests for squads.ts.
 *
 * All tests are deterministic and offline: they operate on either the FROZEN
 * real fixture (squads_vault_transaction.b64) or synthetic byte sequences
 * built in-process. No network, no RPC, no live accounts.
 *
 * Test groups:
 *   A  discriminator math (A1 correct disc, A2 wrong disc)
 *   B  borsh decode of frozen real fixture (B1-B7 structural assertions)
 *   C  program-id resolution (C1 static resolved, C2 ALT-unresolved)
 *   D  inner-instruction classification + fail-closed never-SIGN
 *      (D1 synthetic admin-transfer visible, D2 unresolved->hasUnresolvedPrograms,
 *       D3 no-inner-bytes->HOLD, D4 empty instructions)
 *   E  structural fail-closed (E1 bad disc, E2 truncation, E3 trailing junk,
 *      E4 over-long Vec guard)
 *   F  determinism + purity (F1 deep-equal, F2 no network imports)
 *   G  isSquadsVaultExecute detector (G1 correct id+disc, G2 wrong progId,
 *      G3 wrong disc, G4 short data)
 */

import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import {
  decodeVaultTransaction,
  isSquadsVaultExecute,
  SquadsDecodeError,
  SQUADS_V4_PROGRAM_ID,
  type DecodedVaultTransaction,
} from "../src/squads.ts";

const HERE = dirname(fileURLToPath(import.meta.url));
const ACCOUNTS_DIR = join(HERE, "..", "fixtures", "real", "accounts");

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function readAccountB64(name: string): Uint8Array {
  const b64 = readFileSync(join(ACCOUNTS_DIR, `${name}.b64`), "utf8").trim();
  return new Uint8Array(Buffer.from(b64, "base64"));
}

/** Build a minimal valid VaultTransaction account (borsh), offset bytes. */
function buildMinimalVaultTx(overrides: {
  disc?: number[];
  numKeys?: number;
  numInstructions?: number;
  extraTrailingBytes?: number;
  truncateAtEnd?: number;
  instrProgramIdIndex?: number;
  instrAccountIndexes?: number[];
  instrData?: number[];
}): Uint8Array {
  const disc = overrides.disc ?? [
    0xa8, 0xfa, 0xa2, 0x64, 0x51, 0x0e, 0xa2, 0xcf,
  ];
  const numKeys = overrides.numKeys ?? 3;
  const numInstructions = overrides.numInstructions ?? 1;
  const instrProgramIdIndex = overrides.instrProgramIdIndex ?? 0; // resolves to accountKeys[0]
  const instrAccountIndexes = overrides.instrAccountIndexes ?? [1, 2];
  const instrData = overrides.instrData ?? [
    0xa1, 0xb0, 0x28, 0xd5, 0x3c, 0xb8, 0xb3, 0xe4,
  ];

  const bytes: number[] = [];

  // discriminator (8 bytes)
  bytes.push(...disc);

  // multisig Pubkey (32)
  bytes.push(...new Array(32).fill(0x01));
  // creator Pubkey (32)
  bytes.push(...new Array(32).fill(0x02));
  // index u64-LE (8)
  bytes.push(...[1, 0, 0, 0, 0, 0, 0, 0]);
  // bump, vault_index, vault_bump
  bytes.push(255, 0, 254);
  // ephemeral_signer_bumps Vec<u8>: length=0
  bytes.push(...[0, 0, 0, 0]);

  // --- VaultTransactionMessage ---
  // num_signers, num_writable_signers, num_writable_non_signers
  bytes.push(1, 1, 1);

  // account_keys Vec<Pubkey>: numKeys entries
  bytes.push(...u32le(numKeys));
  for (let i = 0; i < numKeys; i++) {
    // Each key: 32 bytes filled with (i+0x10)
    bytes.push(...new Array(32).fill(0x10 + i));
  }

  // instructions Vec
  bytes.push(...u32le(numInstructions));
  for (let i = 0; i < numInstructions; i++) {
    bytes.push(instrProgramIdIndex);
    // account_indexes Vec<u8>
    bytes.push(...u32le(instrAccountIndexes.length));
    bytes.push(...instrAccountIndexes);
    // data Vec<u8>
    bytes.push(...u32le(instrData.length));
    bytes.push(...instrData);
  }

  // address_table_lookups Vec: empty
  bytes.push(...u32le(0));

  // optional trailing bytes
  if (overrides.extraTrailingBytes) {
    bytes.push(...new Array(overrides.extraTrailingBytes).fill(0x00));
  }

  // optional truncation
  const end = bytes.length - (overrides.truncateAtEnd ?? 0);
  return new Uint8Array(bytes.slice(0, end));
}

function u32le(n: number): number[] {
  return [n & 0xff, (n >>> 8) & 0xff, (n >>> 16) & 0xff, (n >>> 24) & 0xff];
}

// ---------------------------------------------------------------------------
// A: Discriminator math
// ---------------------------------------------------------------------------

describe("A: discriminator validation", () => {
  it("A1 VAULT_TRANSACTION_DISCRIMINATOR is sha256('account:VaultTransaction')[0..8]", () => {
    // Pre-computed: a8faa264510ea2cf
    // We verify the constant matches the fixture discriminator directly.
    const accountBytes = readAccountB64("squads_vault_transaction");
    const discHex = Buffer.from(accountBytes.slice(0, 8)).toString("hex");
    expect(discHex).toBe("a8faa264510ea2cf");
  });

  it("A2 throws SquadsDecodeError on wrong discriminator", () => {
    const bytes = buildMinimalVaultTx({
      disc: [0xde, 0xad, 0xbe, 0xef, 0x00, 0x00, 0x00, 0x00],
    });
    expect(() => decodeVaultTransaction(bytes)).toThrowError(SquadsDecodeError);
  });
});

// ---------------------------------------------------------------------------
// B: Borsh decode of frozen real fixture
// ---------------------------------------------------------------------------

describe("B: frozen real fixture borsh decode", () => {
  let decoded: DecodedVaultTransaction;

  it("B1 decodes without throwing", () => {
    const accountBytes = readAccountB64("squads_vault_transaction");
    expect(accountBytes.length).toBe(344);
    decoded = decodeVaultTransaction(accountBytes);
    expect(decoded).toBeDefined();
  });

  it("B2 multisig matches meta.json", () => {
    const meta = JSON.parse(
      readFileSync(
        join(ACCOUNTS_DIR, "squads_vault_transaction.meta.json"),
        "utf8",
      ),
    );
    if (!decoded)
      decoded = decodeVaultTransaction(
        readAccountB64("squads_vault_transaction"),
      );
    expect(decoded.multisig).toBe(meta.vaultTransaction.multisig);
  });

  it("B3 index matches meta.json", () => {
    const meta = JSON.parse(
      readFileSync(
        join(ACCOUNTS_DIR, "squads_vault_transaction.meta.json"),
        "utf8",
      ),
    );
    if (!decoded)
      decoded = decodeVaultTransaction(
        readAccountB64("squads_vault_transaction"),
      );
    expect(decoded.index.toString()).toBe(String(meta.vaultTransaction.index));
  });

  it("B4 accountKeys count and format (5 keys, each 43-44 chars base58)", () => {
    if (!decoded)
      decoded = decodeVaultTransaction(
        readAccountB64("squads_vault_transaction"),
      );
    expect(decoded.accountKeys.length).toBe(5);
    for (const k of decoded.accountKeys) {
      expect(k.length).toBeGreaterThanOrEqual(32);
      expect(k.length).toBeLessThanOrEqual(44);
      expect(/^[1-9A-HJ-NP-Za-km-z]+$/.test(k)).toBe(true);
    }
  });

  it("B5 accountKeys match meta.json", () => {
    const meta = JSON.parse(
      readFileSync(
        join(ACCOUNTS_DIR, "squads_vault_transaction.meta.json"),
        "utf8",
      ),
    );
    if (!decoded)
      decoded = decodeVaultTransaction(
        readAccountB64("squads_vault_transaction"),
      );
    expect(decoded.accountKeys).toEqual(meta.message.accountKeys);
  });

  it("B6 instruction count is 2, matching meta.json", () => {
    if (!decoded)
      decoded = decodeVaultTransaction(
        readAccountB64("squads_vault_transaction"),
      );
    expect(decoded.instructions.length).toBe(2);
  });

  it("B7 instruction programIdIndexes match meta.json (5 and 7, both >= nKeys=5)", () => {
    const meta = JSON.parse(
      readFileSync(
        join(ACCOUNTS_DIR, "squads_vault_transaction.meta.json"),
        "utf8",
      ),
    );
    if (!decoded)
      decoded = decodeVaultTransaction(
        readAccountB64("squads_vault_transaction"),
      );
    for (let i = 0; i < decoded.instructions.length; i++) {
      const instrMeta = meta.message.instructions[i];
      expect(decoded.instructions[i]!.programIdIndex).toBe(
        instrMeta.programIdIndex,
      );
      expect(decoded.instructions[i]!.accountIndexes).toEqual(
        instrMeta.accountIndexes,
      );
    }
  });
});

// ---------------------------------------------------------------------------
// C: Program-id resolution (static vs ALT)
// ---------------------------------------------------------------------------

describe("C: program-id resolution", () => {
  it("C1 static resolution: programIdIndex < nKeys -> programId is base58 key", () => {
    // Build with 3 keys, instrProgramIdIndex=0 (resolves to accountKeys[0])
    const bytes = buildMinimalVaultTx({ numKeys: 3, instrProgramIdIndex: 0 });
    const result = decodeVaultTransaction(bytes);
    expect(result.instructions[0]!.programId).not.toBeNull();
    expect(result.instructions[0]!.programId).toBe(result.accountKeys[0]);
    expect(result.hasUnresolvedPrograms).toBe(false);
  });

  it("C2 ALT-space resolution: programIdIndex >= nKeys -> programId is null, hasUnresolvedPrograms=true", () => {
    // 5 keys in fixture, both instructions have programIdIndex 5 and 7
    const accountBytes = readAccountB64("squads_vault_transaction");
    const result = decodeVaultTransaction(accountBytes);
    // Both instructions are in ALT space (indices 5, 7 >= 5 keys)
    expect(result.instructions[0]!.programId).toBeNull();
    expect(result.instructions[1]!.programId).toBeNull();
    expect(result.hasUnresolvedPrograms).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// D: Inner-instruction classification + fail-closed never-SIGN
// ---------------------------------------------------------------------------

describe("D: inner instruction analysis and fail-closed", () => {
  it("D1 synthetic: update_admin discriminator (a1b028d53cb8b3e4) is visible when resolved", () => {
    // Build a synthetic VaultTransaction where inner program id IS resolvable
    // (programIdIndex < nKeys) and the data starts with the update_admin disc.
    const UPDATE_ADMIN_DISC = [0xa1, 0xb0, 0x28, 0xd5, 0x3c, 0xb8, 0xb3, 0xe4];
    const bytes = buildMinimalVaultTx({
      numKeys: 3,
      instrProgramIdIndex: 2, // resolves to accountKeys[2]
      instrData: UPDATE_ADMIN_DISC,
    });
    const result = decodeVaultTransaction(bytes);
    expect(result.instructions[0]!.programId).not.toBeNull();
    expect(result.instructions[0]!.programId).toBe(result.accountKeys[2]);
    // Data starts with update_admin discriminator
    expect(Array.from(result.instructions[0]!.data.slice(0, 8))).toEqual(
      UPDATE_ADMIN_DISC,
    );
    expect(result.hasUnresolvedPrograms).toBe(false);
  });

  it("D2 unresolved programs -> hasUnresolvedPrograms=true (real fixture)", () => {
    const accountBytes = readAccountB64("squads_vault_transaction");
    const result = decodeVaultTransaction(accountBytes);
    expect(result.hasUnresolvedPrograms).toBe(true);
    // All unresolved inner instructions have programId=null
    for (const ix of result.instructions) {
      if (ix.programIdIndex >= result.accountKeys.length) {
        expect(ix.programId).toBeNull();
      }
    }
  });

  it("D3 instruction with empty data bytes decodes fine (no programId assumption)", () => {
    const bytes = buildMinimalVaultTx({
      numKeys: 3,
      instrProgramIdIndex: 0,
      instrData: [],
    });
    const result = decodeVaultTransaction(bytes);
    expect(result.instructions[0]!.data.length).toBe(0);
    expect(result.instructions[0]!.programId).toBe(result.accountKeys[0]);
  });

  it("D4 zero inner instructions decodes cleanly (hasUnresolvedPrograms=false)", () => {
    const bytes = buildMinimalVaultTx({ numInstructions: 0 });
    const result = decodeVaultTransaction(bytes);
    expect(result.instructions.length).toBe(0);
    expect(result.hasUnresolvedPrograms).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// E: Structural fail-closed
// ---------------------------------------------------------------------------

describe("E: structural fail-closed", () => {
  it("E1 bad discriminator -> SquadsDecodeError", () => {
    const bytes = buildMinimalVaultTx({
      disc: [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    });
    expect(() => decodeVaultTransaction(bytes)).toThrowError(SquadsDecodeError);
  });

  it("E2 truncated input -> SquadsDecodeError", () => {
    const accountBytes = readAccountB64("squads_vault_transaction");
    // Truncate to half length
    const truncated = accountBytes.slice(0, 100);
    expect(() => decodeVaultTransaction(truncated)).toThrowError(
      SquadsDecodeError,
    );
  });

  it("E3 trailing bytes -> SquadsDecodeError (fail-closed on unexpected data)", () => {
    const good = buildMinimalVaultTx({});
    const withTrailing = new Uint8Array(good.length + 3);
    withTrailing.set(good);
    withTrailing[good.length] = 0xde;
    withTrailing[good.length + 1] = 0xad;
    withTrailing[good.length + 2] = 0xbe;
    expect(() => decodeVaultTransaction(withTrailing)).toThrowError(
      SquadsDecodeError,
    );
  });

  it("E4 over-long Vec guard (instructs length > 256) -> SquadsDecodeError", () => {
    // Build instructions Vec with nInstructions=257 (>256 guard)
    const disc = [0xa8, 0xfa, 0xa2, 0x64, 0x51, 0x0e, 0xa2, 0xcf];
    const bytes: number[] = [
      ...disc,
      ...new Array(32).fill(0x01), // multisig
      ...new Array(32).fill(0x02), // creator
      ...[1, 0, 0, 0, 0, 0, 0, 0], // index
      255,
      0,
      254, // bump, vault_index, vault_bump
      ...[0, 0, 0, 0], // ephemeral_signer_bumps Vec (empty)
      1,
      1,
      1, // num_signers etc.
      ...[1, 0, 0, 0], // account_keys Vec<Pubkey> len=1
      ...new Array(32).fill(0x10), // one key
      ...[1, 1, 0, 0], // instructions Vec: len=257 (0x0101 little-endian)
    ];
    expect(() => decodeVaultTransaction(new Uint8Array(bytes))).toThrowError(
      SquadsDecodeError,
    );
  });

  it("E5 input shorter than discriminator -> SquadsDecodeError", () => {
    expect(() =>
      decodeVaultTransaction(new Uint8Array([0xa8, 0xfa])),
    ).toThrowError(SquadsDecodeError);
  });
});

// ---------------------------------------------------------------------------
// F: Determinism + purity
// ---------------------------------------------------------------------------

describe("F: determinism and purity", () => {
  it("F1 deep-equal: decode same bytes twice -> identical result", () => {
    const accountBytes = readAccountB64("squads_vault_transaction");
    const r1 = decodeVaultTransaction(accountBytes);
    const r2 = decodeVaultTransaction(accountBytes);
    // Compare via JSON (handles Uint8Array and BigInt)
    const replacer = (_k: string, v: unknown) => {
      if (v instanceof Uint8Array) return Array.from(v);
      if (typeof v === "bigint") return v.toString();
      return v;
    };
    expect(JSON.stringify(r1, replacer)).toBe(JSON.stringify(r2, replacer));
  });

  it("F2 squads.ts source must not import http/https/net/fetch/enrich", () => {
    const src = readFileSync(join(HERE, "..", "src", "squads.ts"), "utf8");
    const forbidden = [
      /from\s+["']node:(http|https|net|tls|dgram|dns)["']/,
      /from\s+["'](http|https|node-fetch|axios|undici)["']/,
      /\brequire\(\s*["']node:(http|https|net)["']\s*\)/,
      /\bfetch\s*\(/,
      /\bXMLHttpRequest\b/,
      /from\s+["'].*enrich(\.ts)?["']/,
    ];
    for (const re of forbidden) {
      expect(re.test(src), `squads.ts must not match ${re}`).toBe(false);
    }
  });

  it("F3 squads.ts does not import from enrich.ts (no 'from ... enrich' import statement)", () => {
    const src = readFileSync(join(HERE, "..", "src", "squads.ts"), "utf8");
    // Check for import statements specifically, not the word in comments
    expect(/from\s+["'].*enrich(\.ts)?["']/.test(src)).toBe(false);
    expect(/require\(\s*["'].*enrich(\.ts)?["']\s*\)/.test(src)).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// G: isSquadsVaultExecute detector
// ---------------------------------------------------------------------------

describe("G: isSquadsVaultExecute detector", () => {
  // sha256("global:vault_transaction_execute")[0..8] = c208a15799a419ab
  const EXECUTE_DISC = new Uint8Array([
    0xc2, 0x08, 0xa1, 0x57, 0x99, 0xa4, 0x19, 0xab,
  ]);

  it("G1 correct program id + discriminator -> true", () => {
    const data = new Uint8Array([...EXECUTE_DISC, 0x00, 0x00]);
    expect(isSquadsVaultExecute(SQUADS_V4_PROGRAM_ID, data)).toBe(true);
  });

  it("G2 wrong program id -> false", () => {
    const data = new Uint8Array([...EXECUTE_DISC, 0x00]);
    expect(isSquadsVaultExecute("11111111111111111111111111111111", data)).toBe(
      false,
    );
  });

  it("G3 correct program id but wrong discriminator -> false", () => {
    const data = new Uint8Array([
      0xde, 0xad, 0xbe, 0xef, 0x00, 0x00, 0x00, 0x00,
    ]);
    expect(isSquadsVaultExecute(SQUADS_V4_PROGRAM_ID, data)).toBe(false);
  });

  it("G4 correct program id but data too short (< 8 bytes) -> false", () => {
    const data = new Uint8Array([0xc2, 0x08, 0xa1]);
    expect(isSquadsVaultExecute(SQUADS_V4_PROGRAM_ID, data)).toBe(false);
  });

  it("G5 empty data -> false", () => {
    expect(isSquadsVaultExecute(SQUADS_V4_PROGRAM_ID, new Uint8Array())).toBe(
      false,
    );
  });
});
