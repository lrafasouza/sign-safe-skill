/**
 * recipient.test.ts -- FEATURE 1: Recipient surfacing (GAP 2 closure).
 *
 * Verifies that outflow.lamportTransfers and outflow.splTransfers.destination
 * correctly capture the recipient base58 address (or mark it ALT-unresolved),
 * and that the outboundToNonSigner flag is correct for self vs external transfers.
 *
 * Account layout axioms (verified against solana-program/token interface):
 *   System Transfer:        accounts[0]=from, accounts[1]=to
 *   SPL Transfer:           accounts[0]=source, accounts[1]=destination, accounts[2]=authority
 *   SPL TransferChecked:    accounts[0]=source, accounts[1]=mint, accounts[2]=destination, accounts[3]=authority
 */

import { describe, it, expect } from "vitest";
import { reviewBase64 } from "../src/verdict.ts";
import { u32le, u64le, key, toB64, legacyBytes, v0Bytes } from "./helpers.ts";

// Known program IDs
const SYSTEM = "11111111111111111111111111111111";
const SPL_TOKEN = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";

// Disc constants
const SPL_TRANSFER_DISC = 3;
const SPL_TRANSFER_CHECKED_DISC = 12;

/**
 * Encode a base58 address to 32 bytes (naive big-number decode, sufficient
 * for test fixtures where we only need the round-trip, not a live address).
 */
function base58ToBytes(b58: string): number[] {
  const ALPHA = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  const map: Record<string, number> = {};
  for (let i = 0; i < ALPHA.length; i++) map[ALPHA[i]!] = i;
  const digits: number[] = [0];
  for (const ch of b58) {
    let carry = map[ch] ?? 0;
    for (let i = 0; i < digits.length; i++) {
      carry += digits[i]! * 58;
      digits[i] = carry & 0xff;
      carry >>= 8;
    }
    while (carry > 0) {
      digits.push(carry & 0xff);
      carry >>= 8;
    }
  }
  let leading = 0;
  for (const ch of b58) {
    if (ch === "1") leading++;
    else break;
  }
  const out = new Array(32).fill(0);
  const body = digits.reverse();
  const offset = 32 - body.length - leading;
  for (let i = 0; i < body.length; i++) out[offset + i] = body[i];
  return out;
}

/**
 * Build a legacy message where each key in keySpecs is:
 *   - a number: a 32-byte key filled with that byte
 *   - a string: a base58-decoded 32-byte address
 *   - a number[]: raw 32 bytes
 */
function buildLegacyMessage(
  header: [number, number, number],
  keySpecs: Array<number | number[] | string>,
  ixs: Array<{ prog: number; accts: number[]; data: number[] }>,
): Uint8Array {
  const out: number[] = [];
  out.push(...header);
  // simple byte count (compact-u16 for n <= 127 is just the byte n)
  out.push(keySpecs.length);
  for (const k of keySpecs) {
    if (typeof k === "number") out.push(...key(k));
    else if (typeof k === "string") out.push(...base58ToBytes(k));
    else out.push(...k);
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

// ─────────────────────────────────────────────────────────────────────────────
// Test addresses: a deterministic "attacker" key (fill=0xAA) and a "self" key
// (the signer at index 0, fill=0x01).
// ─────────────────────────────────────────────────────────────────────────────
const SIGNER_FILL = 0x01;
const ATTACKER_FILL = 0xaa;

describe("System Transfer — recipient surfacing", () => {
  it("surfaces the recipient base58 address in lamportTransfers", () => {
    // Layout: [0]=signer(0x01), [1]=System, [2]=recipient(0xAA)
    // Transfer: from=accts[0], to=accts[1] of the instruction
    // instruction accounts: [0]=signer_idx=0, [1]=recipient_idx=2
    const data = [...u32le(2), ...u64le(500_000_000n)]; // Transfer, 0.5 SOL
    const bytes = buildLegacyMessage(
      [1, 0, 1],
      [SIGNER_FILL, SYSTEM, ATTACKER_FILL],
      [{ prog: 1, accts: [0, 2], data }],
    );
    const v = reviewBase64(toB64(bytes));
    expect(v.outflow.lamportTransfers).toHaveLength(1);
    const t = v.outflow.lamportTransfers[0]!;
    expect(t.amount).toBe("500000000");
    expect(t.to).not.toBeNull();
    expect(t.toUnresolved).toBe(false);
    // The recipient address must be surfaced (not null, not empty)
    expect(t.to).toMatch(/^[1-9A-HJ-NP-Za-km-z]{32,44}$/);
  });

  it("outboundToNonSigner is true when recipient is NOT a signer", () => {
    // Signer at index 0; recipient at index 2 is NOT a signer.
    const data = [...u32le(2), ...u64le(100_000n)];
    const bytes = buildLegacyMessage(
      [1, 0, 1],
      [SIGNER_FILL, SYSTEM, ATTACKER_FILL],
      [{ prog: 1, accts: [0, 2], data }],
    );
    const v = reviewBase64(toB64(bytes));
    expect(v.outflow.lamportTransfers[0]!.outboundToNonSigner).toBe(true);
    expect(v.outflow.outboundToNonSigner).toBe(true);
  });

  it("outboundToNonSigner is false for a self-transfer (signer pays signer)", () => {
    // Both signer accounts at index 0 and 1 are signers (2 required signers).
    // Transfer from signer[0] to signer[1].
    const data = [...u32le(2), ...u64le(100_000n)];
    const bytes = buildLegacyMessage(
      [2, 0, 1], // 2 required signers
      [SIGNER_FILL, 0x02, SYSTEM], // idx0=signer, idx1=signer, idx2=System
      [{ prog: 2, accts: [0, 1], data }], // Transfer from idx0 to idx1
    );
    const v = reviewBase64(toB64(bytes));
    const transfers = v.outflow.lamportTransfers;
    expect(transfers).toHaveLength(1);
    expect(transfers[0]!.outboundToNonSigner).toBe(false);
    expect(v.outflow.outboundToNonSigner).toBe(false);
  });

  it("surfaces recipient address in the SIGN reason string", () => {
    const data = [...u32le(2), ...u64le(100_000n)];
    const bytes = buildLegacyMessage(
      [1, 0, 1],
      [SIGNER_FILL, SYSTEM, ATTACKER_FILL],
      [{ prog: 1, accts: [0, 2], data }],
    );
    const v = reviewBase64(toB64(bytes));
    expect(v.decision).toBe("SIGN");
    // The reason must contain a recipient address reference
    expect(v.reason).toMatch(/sends \d+ lamports to /);
  });
});

describe("SPL Transfer — destination surfacing", () => {
  it("surfaces destination address for SPL Transfer (disc 3, accountIndexes[1])", () => {
    // Layout: [0]=signer, [1]=SPL_TOKEN, [2]=source_token_acct, [3]=dest_token_acct, [4]=attacker
    // SPL Transfer accounts: [source, destination, authority]
    // Instruction accounts: [2]=source, [3]=dest_token_acct(ATTACKER_FILL fill), [0]=authority/signer
    const amount = 1_000_000n;
    const data = [SPL_TRANSFER_DISC, ...u64le(amount)];
    const bytes = buildLegacyMessage(
      [1, 0, 1],
      [SIGNER_FILL, SPL_TOKEN, 0x02, ATTACKER_FILL],
      [{ prog: 1, accts: [2, 3, 0], data }],
    );
    const v = reviewBase64(toB64(bytes));
    expect(v.outflow.splTransfers).toHaveLength(1);
    const s = v.outflow.splTransfers[0]!;
    expect(s.amount).toBe("1000000");
    expect(s.destination).toBeDefined();
    // destination index should be accountIndexes[1] = 3 (the ATTACKER_FILL account)
    expect(s.destination.index).toBe(3);
    expect(s.destination.addressUnresolved).toBe(false);
    expect(s.destination.address).not.toBeNull();
    expect(s.destination.outboundToNonSigner).toBe(true);
  });

  it("SPL TransferChecked uses accountIndexes[2] as destination (mint is [1], not dst)", () => {
    // SPL TransferChecked accounts: [source, mint, destination, authority]
    // Instruction accounts: [2]=source, [3]=mint, [4]=destination, [0]=authority
    // So accountIndexes[2] = the destination (index 4 in the message)
    const amount = 500_000n;
    const decimals = 6;
    const data = [SPL_TRANSFER_CHECKED_DISC, ...u64le(amount), decimals];
    const bytes = buildLegacyMessage(
      [1, 0, 1],
      [SIGNER_FILL, SPL_TOKEN, 0x02, 0x03, ATTACKER_FILL],
      // accts[0]=source(idx2), accts[1]=mint(idx3), accts[2]=dest(idx4), accts[3]=authority(idx0)
      [{ prog: 1, accts: [2, 3, 4, 0], data }],
    );
    const v = reviewBase64(toB64(bytes));
    expect(v.outflow.splTransfers).toHaveLength(1);
    const s = v.outflow.splTransfers[0]!;
    expect(s.amount).toBe("500000");
    expect(s.decimals).toBe(6);
    // Destination must be accountIndexes[2] = 4 (the ATTACKER_FILL account at msg idx 4)
    // NOT accountIndexes[1] = 3 (which is the mint)
    expect(s.destination.index).toBe(4);
    expect(s.destination.addressUnresolved).toBe(false);
    expect(s.destination.address).not.toBeNull();
    // Confirm it's not the mint (idx 3)
    expect(s.destination.index).not.toBe(3);
  });

  it("SPL Transfer outboundToNonSigner is false when destination is a signer", () => {
    // Two signers: signer[0] sends to signer[1]
    // SPL Transfer: [source_acct, dest_acct, authority] -> instruction accounts
    const amount = 100n;
    const data = [SPL_TRANSFER_DISC, ...u64le(amount)];
    const bytes = buildLegacyMessage(
      [2, 0, 1], // 2 signers
      [SIGNER_FILL, 0x02, SPL_TOKEN, 0x10, 0x20],
      // accts: source=idx3(0x10), dest=idx4(0x20 = second signer's token acct???)
      // Actually both signers are idx0 and idx1. Let's use idx4 which is readonly non-signer.
      // For a self-transfer: dest account is at a signer index.
      // Use idx1 (signer) as the destination account
      [{ prog: 2, accts: [3, 1, 0], data }], // source=idx3, dest=idx1(signer), authority=idx0
    );
    const v = reviewBase64(toB64(bytes));
    const s = v.outflow.splTransfers[0];
    expect(s).toBeDefined();
    // destination index is accountIndexes[1] = 1 (a signer)
    expect(s!.destination.index).toBe(1);
    expect(s!.destination.outboundToNonSigner).toBe(false);
    expect(v.outflow.outboundToNonSigner).toBe(false);
  });
});

describe("ALT-sourced recipient — unresolved marker", () => {
  it("ALT-loaded recipient is marked unresolved and outboundToNonSigner=true (fail-closed)", () => {
    // v0 message: 1 static key (signer+System in header), then 1 ALT-loaded writable account.
    // System Transfer from signer (idx 0) to ALT-loaded account (idx 2 after static keys).
    // Static keys: [0]=signer, [1]=System
    // ALT-loaded writable: idx 2 (first writable from the lookup table)
    const data = [...u32le(2), ...u64le(100_000n)];
    // v0Bytes takes fill-byte numbers for static keys; System program fill = 0x00
    const SYSTEM_FILL = 0x00; // all-zero bytes = System program address
    const bytes = v0Bytes(
      [1, 0, 1],
      [SIGNER_FILL, SYSTEM_FILL], // static keys: idx0=signer, idx1=System(all zeros)
      // ix: Transfer from idx0 (signer) to idx2 (ALT-loaded writable)
      [{ prog: 1, accts: [0, 2], data }],
      // LUT: table at fill 0xBB, writable=[0] (this becomes msg index 2), readonly=[]
      [{ table: 0xbb, writable: [0], readonly: [] }],
    );
    const v = reviewBase64(toB64(bytes));
    // The ALT is present; lamportTransfers should mark the recipient as unresolved
    expect(v.outflow.lamportTransfers).toHaveLength(1);
    const t = v.outflow.lamportTransfers[0]!;
    expect(t.toUnresolved).toBe(true);
    expect(t.to).toBeNull();
    expect(t.outboundToNonSigner).toBe(true);
    // The outflow-level flag must also be true
    expect(v.outflow.outboundToNonSigner).toBe(true);
  });
});
