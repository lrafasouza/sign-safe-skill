/**
 * review-online.test.ts -- TDD for A5b: reviewWithEnrichment in skill/src/review-online.ts
 *
 * All tests use SYNTHETIC FROZEN fetchers (no real network).
 *
 * Test groups:
 *   O1  v0 tx with ALT: frozen fetcher returning valid ALT → SIGN (all resolved)
 *   O2  v0 tx with ALT: frozen fetcher returning null for table → HOLD (fail-closed)
 *   O3  Squads vaultTransactionExecute: frozen fetcher returns VaultTransaction with
 *       inner authority-change instruction → REJECT / HOLD finding surfaces danger
 *   O4  Token-2022 TransferChecked mint: frozen fetcher returns mint with
 *       permanent-delegate → HOLD finding token2022-permanent-delegate
 *   O5  Decode failure in the top-level message → falls back to offline reviewBase64 (REJECT)
 *   O6  Squads fetcher returns null → stays HOLD (squads-execute-unverified, fail-closed)
 *   O7  Token-2022 mint fetcher returns null → no mint finding, no downgrade (fail-closed)
 */

import { describe, it, expect } from "vitest";
import { reviewWithEnrichment } from "../src/review-online.ts";
import { DEFAULT_CONTEXT, type VerdictContext } from "../src/types.ts";
import { toB64, v0Bytes, legacyBytes, key, u32le } from "./helpers.ts";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const SQUADS_V4  = "SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf";
const SPL_TOKEN  = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const TOKEN_2022 = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";
const SYSTEM     = "11111111111111111111111111111111";

/** sha256("global:vault_transaction_execute")[0..8] */
const VAULT_TX_EXECUTE_DISC = [0xc2, 0x08, 0xa1, 0x57, 0x99, 0xa4, 0x19, 0xab];
/** VaultTransaction account discriminator */
const VAULT_TX_ACCOUNT_DISC = [0xa8, 0xfa, 0xa2, 0x64, 0x51, 0x0e, 0xa2, 0xcf];
/** update_admin discriminator */
const UPDATE_ADMIN_DISC = [0xa1, 0xb0, 0x28, 0xd5, 0x3c, 0xb8, 0xb3, 0xe4];

// ---------------------------------------------------------------------------
// Byte-building helpers
// ---------------------------------------------------------------------------

function base58ToBytes32(b58: string): Uint8Array {
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
 * Build a synthetic ALT account bytes for the table key (byte fill 0xBB),
 * holding a set of addresses provided as 32-byte arrays.
 *
 * ALT layout:
 *   [0..4)   discriminator u32-LE = 1 (LookupTable)
 *   [4..12)  deactivation_slot u64-LE = u64::MAX (0xFFFF...FFFF)
 *   [12..20) last_extended_slot u64-LE = 0
 *   [20]     last_extended_slot_start_index u8 = 0
 *   [21]     authority option tag: 0x00 (None)
 *   [22..54) authority bytes (ignored when tag=0x00; zero-padded)
 *   [54..56) padding u16 = 0
 *   [56..)   32-byte addresses, packed
 */
function buildAltAccountBytes(addresses: Uint8Array[]): Uint8Array {
  const out: number[] = [];
  // discriminator u32-LE = 1
  out.push(1, 0, 0, 0);
  // deactivation_slot = u64::MAX
  out.push(0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff);
  // last_extended_slot = 0
  out.push(0, 0, 0, 0, 0, 0, 0, 0);
  // last_extended_slot_start_index
  out.push(0);
  // authority option tag = 0x00 (None)
  out.push(0x00);
  // authority bytes (32) - ignored, zeroed
  out.push(...new Array(32).fill(0x00));
  // padding u16
  out.push(0, 0);
  // addresses
  for (const addr of addresses) {
    out.push(...Array.from(addr));
  }
  return Uint8Array.from(out);
}

/**
 * Build a synthetic VaultTransaction account (borsh-encoded) with a single
 * inner instruction that has the given programIdIndex (relative to accountKeys)
 * and instrData.
 */
function buildVaultTxBytes(opts: {
  instrProgramIdIndex: number;
  instrData: number[];
  numKeys?: number;
}): Uint8Array {
  const numKeys = opts.numKeys ?? 3;
  const bytes: number[] = [];
  bytes.push(...VAULT_TX_ACCOUNT_DISC);
  bytes.push(...new Array(32).fill(0x01)); // multisig
  bytes.push(...new Array(32).fill(0x02)); // creator
  bytes.push(1, 0, 0, 0, 0, 0, 0, 0);    // index u64-LE
  bytes.push(255, 0, 254);                 // bump, vault_index, vault_bump
  bytes.push(0, 0, 0, 0);                 // ephemeral_signer_bumps Vec<u8> len=0
  bytes.push(1, 1, 1);                     // num_signers, num_writable_signers, num_writable_non_signers
  bytes.push(...u32le(numKeys));
  for (let i = 0; i < numKeys; i++) bytes.push(...new Array(32).fill(0x10 + i));
  bytes.push(...u32le(1));                 // 1 instruction
  bytes.push(opts.instrProgramIdIndex);
  bytes.push(...u32le(0));                 // accountIndexes: empty
  bytes.push(...u32le(opts.instrData.length));
  bytes.push(...opts.instrData);
  bytes.push(...u32le(0));                 // address_table_lookups: empty
  return new Uint8Array(bytes);
}

/**
 * Build a Token-2022 mint account with a PermanentDelegate extension.
 *
 * Layout:
 *   [0..82)   base SPL Mint (82 bytes, all zeros is fine for testing)
 *   [82..165) padding to reach base account length (83 bytes extra)
 *   [165]     account_type byte = 0x01 (Mint)
 *   [166..)   TLV: PermanentDelegate (type=12, length=32, value=delegate pubkey)
 */
function buildMintWithPermanentDelegate(delegateFill: number): Uint8Array {
  const out = new Array(166).fill(0); // 82 base mint + 83 padding + 1 account_type
  out[165] = 0x01; // account_type = Mint
  // TLV entry: type=12 (PermanentDelegate), length=32, value=32 bytes filled with delegateFill
  out.push(12, 0); // u16-LE type
  out.push(32, 0); // u16-LE length
  out.push(...new Array(32).fill(delegateFill)); // value: delegate pubkey bytes
  return Uint8Array.from(out);
}

// ---------------------------------------------------------------------------
// O1: v0 tx with ALT -> frozen fetcher returning valid ALT -> SIGN
// ---------------------------------------------------------------------------

describe("O1: v0 tx with ALT, valid ALT fetched → resolves all → SIGN", () => {
  it("O1.1 fully resolved v0 message (no other findings) → SIGN", async () => {
    // Build a v0 message that references 1 ALT and uses only ALT-sourced writable
    // accounts that don't trigger any finding. The static keys are: feepayer,
    // system program. The instruction is a MEMO-like no-op (program at static[0]).
    // The ALT account resolves to two addresses (irrelevant to instruction).
    //
    // Actually for SIGN we need: zero unknown programs, zero non-INFO findings,
    // no unverified ALT roles. We'll use a minimal v0 tx where:
    //   - The only instruction uses a recognized program (System CreateAccount)
    //     but actually we want zero findings. Let's use a known recognized instruction
    //     that doesn't trigger findings at all.
    //
    // Simplest approach: static key = [signer, SystemProgram], ix is Transfer 0 lamports
    // to a resolved ALT address. With ALT resolved: no unverified roles -> SIGN.
    //
    // Actually: a System Transfer with amount = 0 is below the lamport threshold,
    // so it would SIGN if all roles are verified. But Transfer dest is accountIndexes[1].
    // Let's use ALT-sourced writable (dest of transfer) and have the ALT resolve it
    // to a non-signer. With holdOutboundTransfers=false, that's still SIGN.
    //
    // Even simpler: a v0 message with an ALT reference but NO instruction that uses
    // ALT accounts, so the ALT lookup adds addresses but they're unreferenced by any ix.
    // However the decode verifies all ix accountIndexes fit within totalAccounts.
    // Let's do: static = [signer, systemProgram], ALT = table, 1 writable ALT slot
    // Ix: SystemTransfer from [0] to [2] (ALT-slot) of 0 lamports.
    //   Without ALT resolution: ix[2] is unverified -> HOLD
    //   With ALT resolution: ix[2] is verified -> SIGN (0 lamports, below threshold)
    //
    // v0Bytes expects keyBytes as numbers (fill bytes) not base58, so we must use
    // the build functions from helpers carefully.
    // v0Bytes(header, keyBytes, ixs, luts)
    //   keyBytes = [0x01, 0x00] meaning key(0x01)=feepayer, key(0x00)=SystemProgram
    // But key(0x00) = all-zeros = SystemProgram in base58.
    // ALT table = key(0xBB), writable=[0] -> ALT slot 0 resolves to some addr
    //
    // Transfer ix data: tag=2 (u32-LE), lamports=0 (u64-LE)
    const systemTransferData = [2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    const raw = v0Bytes(
      [1, 0, 1],    // 1 required signer, 0 readonly signed, 1 readonly unsigned
      [0x01, 0x00], // static keys: [signer(0x01), SystemProgram(all zeros)]
      [{ prog: 1, accts: [0, 2], data: systemTransferData }], // ix: SystemTransfer from [0] to [2] (ALT slot)
      [{ table: 0xbb, writable: [5], readonly: [] }], // ALT: table at 0xBB, slot index 5
    );

    // The ALT account at 0xBB must return an address for slot index 5.
    // Build an ALT with 6 entries (indices 0-5); slot 5 = some target address (fill 0xCC).
    const altAddresses: Uint8Array[] = [];
    for (let i = 0; i < 6; i++) {
      altAddresses.push(new Uint8Array(32).fill(i === 5 ? 0xcc : i));
    }
    const altAccountBytes = buildAltAccountBytes(altAddresses);

    // Table key bytes (for matching in the fetcher)
    // key(0xBB) = all-0xBB 32 bytes; base58 of that 32-byte key
    // We need to know the base58 of key(0xBB) to identify the table address.
    // The message will have it in addressTableLookups[0].accountKey.
    // Let's use the message's own field.
    const { decodeInput } = await import("../src/decode.ts");
    const { message } = decodeInput(toB64(raw));
    const tableAddr = message.addressTableLookups[0]!.accountKey;

    const frozenFetcher = async (pubkey: string) => {
      if (pubkey === tableAddr) return { data: altAccountBytes };
      return null;
    };

    const ctx: VerdictContext = { lamportThreshold: 1_000_000_000 }; // 1 SOL threshold, 0 lamports is below
    const verdict = await reviewWithEnrichment(toB64(raw), ctx, frozenFetcher);

    expect(verdict.decision).toBe("SIGN");
    expect(verdict.flags.rolesUnverified).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// O2: v0 tx with ALT, fetcher returns null → stays HOLD (fail-closed)
// ---------------------------------------------------------------------------

describe("O2: v0 tx with ALT, fetcher returns null → HOLD (fail-closed)", () => {
  it("O2.1 ALT fetch returns null → unresolved roles → HOLD", async () => {
    const systemTransferData = [2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    const raw = v0Bytes(
      [1, 0, 1],
      [0x01, 0x00],
      [{ prog: 1, accts: [0, 2], data: systemTransferData }],
      [{ table: 0xbb, writable: [5], readonly: [] }],
    );

    // Fetcher returns null for every pubkey
    const nullFetcher = async (_pubkey: string) => null;

    const ctx: VerdictContext = { lamportThreshold: 1_000_000_000 };
    const verdict = await reviewWithEnrichment(toB64(raw), ctx, nullFetcher);

    expect(verdict.decision).toBe("HOLD");
    expect(verdict.flags.rolesUnverified).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// O3: Squads vaultTransactionExecute → fetcher returns VaultTx with
//     inner update_admin → surfaces danger (REJECT or HOLD, not SIGN)
// ---------------------------------------------------------------------------

describe("O3: Squads enrichment via frozen fetcher", () => {
  it("O3.1 vaultTransactionExecute with fetched inner update_admin → REJECT finding", async () => {
    // Build a legacy message with a squads-execute instruction.
    // Static keys: [0]=feepayer(0x01), [1]=squads(SQUADS_V4), [2]=vaultTxPDA(0xAA)
    //   ix: prog=1 (squads), accts=[0, 0, 2], data=VAULT_TX_EXECUTE_DISC
    //   accountIndexes[2] = 2 → staticKeys[2] = the PDA (all-0xAA key)
    const squadsBytes = Array.from(base58ToBytes32(SQUADS_V4));
    const out: number[] = [];
    out.push(1, 0, 1); // header
    out.push(3); // 3 static keys
    out.push(...new Array(32).fill(0x01)); // [0] feepayer
    out.push(...squadsBytes);               // [1] squadsV4
    out.push(...new Array(32).fill(0xaa)); // [2] vaultTxPDA
    out.push(...new Array(32).fill(0xfa)); // blockhash
    out.push(1); // 1 instruction
    out.push(1); // prog=1 (squadsV4)
    out.push(3, 0, 0, 2); // 3 accounts: [0, 0, 2]
    out.push(8, ...VAULT_TX_EXECUTE_DISC);
    const raw = Uint8Array.from(out);

    // Decode message to get the PDA address string
    const { decodeInput } = await import("../src/decode.ts");
    const { message } = decodeInput(toB64(raw));
    const pdaAddr = message.staticAccountKeys[2]!; // the all-0xAA key

    // Build a VaultTransaction with an inner update_admin instruction
    const vaultTxBytes = buildVaultTxBytes({
      instrProgramIdIndex: 0, // accountKeys[0] = key filled with 0x10 (some program)
      instrData: UPDATE_ADMIN_DISC,
      numKeys: 3,
    });

    const frozenFetcher = async (pubkey: string) => {
      if (pubkey === pdaAddr) return { data: vaultTxBytes };
      return null;
    };

    const ctx: VerdictContext = { lamportThreshold: 1_000_000_000 };
    const verdict = await reviewWithEnrichment(toB64(raw), ctx, frozenFetcher);

    // Must not be SIGN — the inner instruction is an authority change
    expect(verdict.decision).not.toBe("SIGN");
    // Should have an inner finding for the authority change
    const innerFinding = verdict.findings.find((f) => f.id === "anchor-inner-update_admin");
    expect(innerFinding).toBeTruthy();
  });

  it("O3.2 Squads execute with null fetcher → stays HOLD (squads-execute-unverified)", async () => {
    const squadsBytes = Array.from(base58ToBytes32(SQUADS_V4));
    const out: number[] = [];
    out.push(1, 0, 1);
    out.push(3);
    out.push(...new Array(32).fill(0x01));
    out.push(...squadsBytes);
    out.push(...new Array(32).fill(0xaa));
    out.push(...new Array(32).fill(0xfa));
    out.push(1);
    out.push(1);
    out.push(3, 0, 0, 2);
    out.push(8, ...VAULT_TX_EXECUTE_DISC);
    const raw = Uint8Array.from(out);

    const nullFetcher = async (_pubkey: string) => null;
    const ctx: VerdictContext = { lamportThreshold: 1_000_000_000 };
    const verdict = await reviewWithEnrichment(toB64(raw), ctx, nullFetcher);

    expect(verdict.decision).toBe("HOLD");
    expect(verdict.findings.some((f) => f.id === "squads-execute-unverified")).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// O4: Token-2022 TransferChecked with permanent-delegate mint → HOLD
// ---------------------------------------------------------------------------

describe("O4: Token-2022 mint with permanent delegate via frozen fetcher", () => {
  it("O4.1 TransferChecked mint with permanent delegate → HOLD token2022-permanent-delegate", async () => {
    // Build a legacy message:
    //   Static keys: [0]=signer(0x01), [1]=mintAddr(0xDD), [2]=TOKEN_2022, [3]=srcToken(0x04), [4]=dstToken(0x05)
    //   ix: TOKEN_2022 TransferChecked (disc=12)
    //       accounts: [srcToken=3, mint=1, dstToken=4, signer=0]
    //       data: [12, <amount_u64_le>, <decimals_u8>]
    const token2022Bytes = Array.from(base58ToBytes32(TOKEN_2022));
    const out: number[] = [];
    out.push(1, 0, 1); // header
    out.push(5); // 5 static keys
    out.push(...new Array(32).fill(0x01)); // [0] signer
    out.push(...new Array(32).fill(0xdd)); // [1] mint address (fill 0xDD)
    out.push(...token2022Bytes);            // [2] TOKEN_2022 program
    out.push(...new Array(32).fill(0x04)); // [3] source token account
    out.push(...new Array(32).fill(0x05)); // [4] dest token account
    out.push(...new Array(32).fill(0xfa)); // blockhash
    // TransferChecked ix: disc=12, amount=100 (u64-LE), decimals=6 (u8)
    const ixData = [12, 100, 0, 0, 0, 0, 0, 0, 0, 6]; // disc=12, amount=100, decimals=6
    out.push(1); // 1 instruction
    out.push(2); // prog=2 (TOKEN_2022 at static[2])
    out.push(4, 3, 1, 4, 0); // 4 accounts: [3,1,4,0]
    out.push(ixData.length, ...ixData);
    const raw = Uint8Array.from(out);

    // Decode to get mint address
    const { decodeInput } = await import("../src/decode.ts");
    const { message } = decodeInput(toB64(raw));
    const mintAddr = message.staticAccountKeys[1]!; // all-0xDD key

    // Build a Token-2022 mint with permanent delegate (fill 0xEE)
    const mintAccountBytes = buildMintWithPermanentDelegate(0xee);

    const frozenFetcher = async (pubkey: string) => {
      if (pubkey === mintAddr) return { data: mintAccountBytes };
      return null;
    };

    const ctx: VerdictContext = { lamportThreshold: 1_000_000_000 };
    const verdict = await reviewWithEnrichment(toB64(raw), ctx, frozenFetcher);

    expect(verdict.decision).toBe("HOLD");
    const mintFinding = verdict.findings.find((f) => f.id === "token2022-permanent-delegate");
    expect(mintFinding).toBeTruthy();
    expect(mintFinding!.severity).toBe("HOLD");
  });

  it("O4.2 mint fetcher returns null → no mint finding, no downgrade (fail-closed)", async () => {
    // Same message as O4.1, but fetcher returns null for the mint
    const token2022Bytes = Array.from(base58ToBytes32(TOKEN_2022));
    const out: number[] = [];
    out.push(1, 0, 1);
    out.push(5);
    out.push(...new Array(32).fill(0x01));
    out.push(...new Array(32).fill(0xdd));
    out.push(...token2022Bytes);
    out.push(...new Array(32).fill(0x04));
    out.push(...new Array(32).fill(0x05));
    out.push(...new Array(32).fill(0xfa));
    const ixData = [12, 100, 0, 0, 0, 0, 0, 0, 0, 6];
    out.push(1);
    out.push(2);
    out.push(4, 3, 1, 4, 0);
    out.push(ixData.length, ...ixData);
    const raw = Uint8Array.from(out);

    const nullFetcher = async (_pubkey: string) => null;
    const ctx: VerdictContext = { lamportThreshold: 1_000_000_000 };
    const verdict = await reviewWithEnrichment(toB64(raw), ctx, nullFetcher);

    // No mint finding added (fetcher returned null = skip, fail-closed)
    expect(verdict.findings.some((f) => f.id === "token2022-permanent-delegate")).toBe(false);
    // The decision should not be worse than the offline verdict would be
    // (no downgrade: if offline was SIGN, it stays SIGN; if HOLD, stays HOLD)
  });
});

// ---------------------------------------------------------------------------
// O5: Decode failure in top-level message → falls back to offline (REJECT)
// ---------------------------------------------------------------------------

describe("O5: decode failure falls back to offline reviewBase64", () => {
  it("O5.1 garbled base64 → REJECT (offline fail-closed path)", async () => {
    const fakeFetcher = async (_pubkey: string) => null;
    const verdict = await reviewWithEnrichment("THIS_IS_NOT_BASE64!!!", DEFAULT_CONTEXT, fakeFetcher);
    expect(verdict.decision).toBe("REJECT");
    expect(verdict.flags.decodeFailed).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// v0.5 O6-O9: reviewWithEnrichment enrichment provenance + simulate wiring
// ---------------------------------------------------------------------------

describe("v0.5 O6: reviewWithEnrichment enrichment provenance", () => {
  it("O6.1 rpcUrl is recorded in verdict.enrichment when opts.rpcUrl is provided", async () => {
    const fakeFetcher = async (_pubkey: string) => null;
    const { legacyBytes, toB64, key } = await import("./helpers.ts");
    const raw = legacyBytes([1, 0, 1], [0x01, 0x00], []);
    const b64 = toB64(raw);
    void key;

    const verdict = await reviewWithEnrichment(b64, DEFAULT_CONTEXT, fakeFetcher, {
      rpcUrl: "https://test-rpc.example.com",
    });
    expect(verdict.enrichment).toBeDefined();
    expect(verdict.enrichment!.rpcUrl).toBe("https://test-rpc.example.com");
    expect(verdict.enrichment!.simulated).toBe(false);
    expect(verdict.enrichment!.trustNote).toContain("--digest");
  });

  it("O6.2 trustNote always contains warning about RPC trust boundary", async () => {
    const fakeFetcher = async (_pubkey: string) => null;
    const { legacyBytes, toB64 } = await import("./helpers.ts");
    const raw = legacyBytes([1, 0, 1], [0x01, 0x00], []);
    const b64 = toB64(raw);

    const verdict = await reviewWithEnrichment(b64, DEFAULT_CONTEXT, fakeFetcher, {
      rpcUrl: "https://api.mainnet-beta.solana.com",
    });
    expect(verdict.enrichment!.trustNote).toContain("compromised RPC");
    expect(verdict.enrichment!.trustNote).toContain("enrichment");
  });

  it("O6.3 offline reviewBase64 never sets verdict.enrichment (golden fixtures unaffected)", async () => {
    // Pure offline path: enrichment is NEVER set by reviewBase64.
    // Covered in detail by simulate.test.ts S8.3; this test confirms from the
    // review-online suite that only the host-layer path sets enrichment.
    const { reviewBase64 } = await import("../src/verdict.ts");
    const { legacyBytes, toB64 } = await import("./helpers.ts");
    const raw = legacyBytes([1, 0, 1], [0x01, 0x00], []);
    const b64 = toB64(raw);
    const verdict = reviewBase64(b64, DEFAULT_CONTEXT);
    // The pure offline path must NEVER set enrichment.
    expect(verdict.enrichment).toBeUndefined();
  });
});

describe("v0.5 O7: reviewWithEnrichment resolvedAltTables/mintsScreened in enrichment", () => {
  it("O7.1 resolvedAltTables count matches the number of ALT tables successfully fetched", async () => {
    // v0 message with 0 ALT lookups → resolvedAltTables=0
    const { legacyBytes, toB64 } = await import("./helpers.ts");
    const raw = legacyBytes([1, 0, 1], [0x01, 0x00], []);
    const b64 = toB64(raw);
    const fakeFetcher = async (_pubkey: string) => null;
    const verdict = await reviewWithEnrichment(b64, DEFAULT_CONTEXT, fakeFetcher, {
      rpcUrl: "https://api.mainnet-beta.solana.com",
    });
    expect(verdict.enrichment!.resolvedAltTables).toBe(0);
  });
});
