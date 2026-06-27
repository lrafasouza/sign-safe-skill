/**
 * extract-vault-address.test.ts -- TDD for A3: extractVaultTransactionAddress
 *
 * Tests that the PURE extractor:
 *   1. Returns staticAccountKeys[ix.accountIndexes[2]] when a squads-execute
 *      instruction is found and index 2 is within static keys.
 *   2. Returns null when the account at position 2 is ALT-sourced.
 *   3. Returns null when there is no squads-execute instruction.
 *   4. Returns null when squads-execute has fewer than 3 account indexes.
 */

import { describe, it, expect } from "vitest";
import { extractVaultTransactionAddress } from "../src/squads.ts";
import { toB64, legacyBytes } from "./helpers.ts";
import { decodeInput } from "../src/decode.ts";

const SQUADS_V4 = "SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf";

/** sha256("global:vault_transaction_execute")[0..8] = c208a15799a419ab */
const VAULT_TX_EXECUTE_DISC = [0xc2, 0x08, 0xa1, 0x57, 0x99, 0xa4, 0x19, 0xab];

function base58ToBytes32(b58: string): number[] {
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
  const out = new Array(32).fill(0);
  const body = bytes.reverse();
  const off = 32 - body.length - lz;
  for (let i = 0; i < body.length; i++) out[off + i] = body[i]!;
  return out;
}

describe("A3: extractVaultTransactionAddress", () => {
  it("A3.1 returns staticKey at accountIndexes[2] when squads-execute found", () => {
    // keys: [0]=feepayer(0x01), [1]=squadsV4, [2]=vaultTxPda(0xAA), [3]=extra(0x03)
    // ix: prog=1 (squadsV4), accts=[0, 3, 2], data=VAULT_TX_EXECUTE_DISC
    //   accountIndexes[2] = 2 → staticAccountKeys[2] = key filled with 0xAA
    const squadsBytes = base58ToBytes32(SQUADS_V4);
    const pdaKey = new Array(32).fill(0xaa);
    const out: number[] = [];
    out.push(1, 0, 1); // header: 1 required signer, 0 readonly signed, 1 readonly unsigned
    out.push(4); // 4 keys (compact-u16 = single byte for < 128)
    out.push(...new Array(32).fill(0x01)); // [0] fee payer (signer-writable)
    out.push(...squadsBytes); // [1] SQUADS_V4 (readonly-unsigned = program)
    out.push(...pdaKey); // [2] vault tx PDA (writable)
    out.push(...new Array(32).fill(0x03)); // [3] extra account (writable)
    out.push(...new Array(32).fill(0xfa)); // blockhash
    out.push(1); // 1 instruction
    // prog=1 (squadsV4 at static[1])
    out.push(1);
    // 3 accounts: [0, 3, 2]
    out.push(3, 0, 3, 2);
    // data: 8 bytes = VAULT_TX_EXECUTE_DISC
    out.push(8, ...VAULT_TX_EXECUTE_DISC);
    const raw = Uint8Array.from(out);
    const { message } = decodeInput(toB64(raw));
    const addr = extractVaultTransactionAddress(message);
    // staticAccountKeys[2] is the pdaKey (all 0xAA) - should be non-null
    expect(addr).not.toBeNull();
    expect(typeof addr).toBe("string");
    expect(addr!.length).toBeGreaterThan(20);
  });

  it("A3.2 returns null when accountIndexes[2] is ALT-sourced (>= staticAccountKeys.length)", () => {
    // v0 message with an ALT reference
    // static keys: [0]=feepayer, [1]=squadsV4
    // ALT lookup: table at 0x05, writable=[10]
    // total accounts = 2 static + 1 alt-writable = 3
    // instruction: prog=1 (squadsV4), accts=[0, 0, 2] (index 2 is the ALT account)
    const squadsBytes = base58ToBytes32(SQUADS_V4);
    const out: number[] = [];
    out.push(0x80); // v0 prefix
    out.push(1, 0, 1); // header
    out.push(2); // 2 static keys
    out.push(...new Array(32).fill(0x01)); // [0] feepayer
    out.push(...squadsBytes); // [1] squadsV4
    out.push(...new Array(32).fill(0xfa)); // blockhash
    out.push(1); // 1 instruction
    out.push(1); // prog=1 (squadsV4 at static[1])
    // 3 accounts: indices [0, 0, 2]
    out.push(3, 0, 0, 2);
    out.push(8, ...VAULT_TX_EXECUTE_DISC);
    // 1 ALT lookup
    out.push(1); // compact-u16(1) num lookups
    out.push(...new Array(32).fill(0x05)); // table key
    out.push(1, 10); // 1 writable index: [10]
    out.push(0); // 0 readonly indexes
    const raw = Uint8Array.from(out);
    const { message } = decodeInput(toB64(raw));
    // staticAccountKeys.length = 2, so accountIndexes[2] = 2 >= 2 -> ALT-sourced -> null
    const addr = extractVaultTransactionAddress(message);
    expect(addr).toBeNull();
  });

  it("A3.3 returns null when there is no squads-execute instruction", () => {
    // Simple message with system program, no squads
    const raw = legacyBytes(
      [1, 0, 1],
      [0x01, 0x02, 0x03],
      [{ prog: 1, accts: [0], data: [2, 0, 0, 0, 100, 0, 0, 0, 0, 0, 0, 0] }],
    );
    const { message } = decodeInput(toB64(raw));
    const addr = extractVaultTransactionAddress(message);
    expect(addr).toBeNull();
  });

  it("A3.4 returns null when squads-execute instruction has fewer than 3 account indexes", () => {
    // squads-execute instruction but only 1 account in the account list
    const squadsBytes = base58ToBytes32(SQUADS_V4);
    const out: number[] = [];
    out.push(1, 0, 1); // header
    out.push(2); // 2 static keys
    out.push(...new Array(32).fill(0x01));
    out.push(...squadsBytes);
    out.push(...new Array(32).fill(0xfa)); // blockhash
    out.push(1); // 1 instruction
    out.push(1); // prog=1 (squadsV4)
    out.push(1, 0); // 1 account: [0]
    out.push(8, ...VAULT_TX_EXECUTE_DISC);
    const raw = Uint8Array.from(out);
    const { message } = decodeInput(toB64(raw));
    const addr = extractVaultTransactionAddress(message);
    expect(addr).toBeNull();
  });
});
