/**
 * auxiliary-programs.test.ts -- native auxiliary program recognition.
 *
 * These programs are not DeFi registry entries and not danger-catalog programs,
 * but they are common signer-adjacent instructions in real transactions. They
 * must not remain "unknown program" when the exact instruction can be bounded.
 */

import { describe, expect, it } from "vitest";
import { reviewBase64 } from "../src/verdict.ts";
import { toB64 } from "./helpers.ts";

const ASSOCIATED_TOKEN_ACCOUNT = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL";
const MEMO = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr";

function base58ToBytes(b58: string): Uint8Array {
  const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  const map: Record<string, number> = {};
  for (let i = 0; i < alphabet.length; i++) map[alphabet[i]!] = i;
  const bytes: number[] = [];
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
  return Uint8Array.from([
    ...new Array(leadingZeros).fill(0),
    ...bytes.reverse(),
  ]);
}

function key(byte: number): number[] {
  return new Array(32).fill(byte);
}

function compact(value: number): number[] {
  if (value < 0x80) return [value];
  throw new RangeError("test helper only supports one-byte short vec lengths");
}

function singleInstructionMessage(
  programId: string,
  data: number[],
  accountCount: number,
  opts: {
    numSigners?: number;
    instructionAccounts?: number[];
  } = {},
): string {
  const instructionAccounts =
    opts.instructionAccounts ??
    Array.from({ length: 1 + accountCount }, (_, index) => index);
  const out: number[] = [];
  out.push(opts.numSigners ?? 1, 0, 1); // signer keys first, program readonly-unsigned
  out.push(...compact(2 + accountCount));
  out.push(...key(1));
  for (let i = 0; i < accountCount; i++) out.push(...key(10 + i));
  out.push(...base58ToBytes(programId));
  out.push(...key(250));
  out.push(...compact(1));
  out.push(1 + accountCount);
  out.push(...compact(instructionAccounts.length));
  out.push(...instructionAccounts);
  out.push(...compact(data.length));
  out.push(...data);
  return toB64(Uint8Array.from(out));
}

function ataCreateIdempotentWithAltWallet(): string {
  const out: number[] = [];
  out.push(0x80); // v0
  out.push(1, 0, 1); // payer signer, ATA program readonly unsigned
  out.push(...compact(6));
  out.push(...key(1)); // 0 payer
  out.push(...key(10)); // 1 associated token account
  out.push(...key(11)); // 2 mint
  out.push(...key(12)); // 3 system program slot
  out.push(...key(13)); // 4 token program slot
  out.push(...base58ToBytes(ASSOCIATED_TOKEN_ACCOUNT)); // 5 ATA program
  out.push(...key(250));
  out.push(...compact(1));
  out.push(5); // programIdIndex
  out.push(...compact(6));
  out.push(0, 1, 6, 2, 3, 4); // wallet owner is ALT-loaded account index 6
  out.push(...compact(1));
  out.push(1);
  out.push(...compact(1)); // one lookup table
  out.push(...key(200));
  out.push(...compact(0)); // no writable loaded addresses
  out.push(...compact(1));
  out.push(0); // one readonly loaded wallet address, unresolved offline
  return toB64(Uint8Array.from(out));
}

describe("native auxiliary program recognition", () => {
  it("recognizes self-funded ATA CreateIdempotent as INFO instead of unknown-program HOLD", () => {
    // ATA accounts: [funding signer, ata, same wallet signer, mint, system, token].
    const verdict = reviewBase64(
      singleInstructionMessage(ASSOCIATED_TOKEN_ACCOUNT, [1], 4, {
        instructionAccounts: [0, 1, 0, 2, 3, 4],
      }),
    );
    expect(verdict.decision).toBe("SIGN");
    expect(verdict.unknownPrograms).not.toContain(ASSOCIATED_TOKEN_ACCOUNT);
    expect(verdict.findings.some((f) => f.id === "ata-create-idempotent")).toBe(
      true,
    );
    expect(
      verdict.findings.find((f) => f.id === "ata-create-idempotent")?.severity,
    ).toBe("INFO");
  });

  it("holds ATA CreateIdempotent when funding signer and wallet signer differ", () => {
    const verdict = reviewBase64(
      singleInstructionMessage(ASSOCIATED_TOKEN_ACCOUNT, [1], 5, {
        numSigners: 2,
        instructionAccounts: [0, 2, 1, 3, 4, 5],
      }),
    );
    expect(verdict.decision).toBe("HOLD");
    expect(
      verdict.findings.find(
        (f) => f.id === "ata-create-idempotent-external-wallet",
      )?.detail,
    ).toContain("same verified signer");
  });

  it("holds ATA CreateIdempotent when the wallet owner is not a signer", () => {
    const verdict = reviewBase64(
      singleInstructionMessage(ASSOCIATED_TOKEN_ACCOUNT, [1], 5),
    );
    expect(verdict.decision).toBe("HOLD");
    expect(verdict.unknownPrograms).not.toContain(ASSOCIATED_TOKEN_ACCOUNT);
    expect(
      verdict.findings.find(
        (f) => f.id === "ata-create-idempotent-external-wallet",
      )?.severity,
    ).toBe("HOLD");
  });

  it("holds ATA CreateIdempotent when the wallet owner is ALT-unresolved", () => {
    const verdict = reviewBase64(ataCreateIdempotentWithAltWallet());
    expect(verdict.decision).toBe("HOLD");
    expect(verdict.unknownPrograms).not.toContain(ASSOCIATED_TOKEN_ACCOUNT);
    expect(
      verdict.findings.find(
        (f) => f.id === "ata-create-idempotent-external-wallet",
      )?.detail,
    ).toContain("unverified");
  });

  it("holds ATA RecoverNested because it can move value out of a nested account", () => {
    const verdict = reviewBase64(
      singleInstructionMessage(ASSOCIATED_TOKEN_ACCOUNT, [2], 6),
    );
    expect(verdict.decision).toBe("HOLD");
    expect(verdict.unknownPrograms).not.toContain(ASSOCIATED_TOKEN_ACCOUNT);
    expect(verdict.findings.some((f) => f.id === "ata-recover-nested")).toBe(
      true,
    );
  });

  it("recognizes valid UTF-8 Memo payloads as INFO instead of unknown-program HOLD", () => {
    const data = [...Buffer.from("order:42", "utf8")];
    const verdict = reviewBase64(singleInstructionMessage(MEMO, data, 1));
    expect(verdict.decision).toBe("SIGN");
    expect(verdict.unknownPrograms).not.toContain(MEMO);
    expect(verdict.findings.some((f) => f.id === "memo-utf8")).toBe(true);
    expect(verdict.findings.find((f) => f.id === "memo-utf8")?.severity).toBe(
      "INFO",
    );
  });

  it("holds invalid Memo payloads instead of treating them as recognized text", () => {
    const verdict = reviewBase64(singleInstructionMessage(MEMO, [0xff], 1));
    expect(verdict.decision).toBe("HOLD");
    expect(verdict.unknownPrograms).not.toContain(MEMO);
    expect(verdict.findings.some((f) => f.id === "memo-invalid-utf8")).toBe(
      true,
    );
  });
});
