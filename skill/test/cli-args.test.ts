/**
 * cli-args.test.ts -- TDD for A5c: CLI parseArgs with --rpc and --vault-pda
 *
 * Since the CLI's main() cannot easily be unit-tested (it reads stdin/files and
 * calls process.exit), we test parseArgs as an exported function.
 */

import { describe, it, expect } from "vitest";
import { parseArgs } from "../src/cli.ts";

describe("A5c: CLI parseArgs with --rpc and --vault-pda", () => {
  it("C1 parses --rpc <url>", () => {
    const result = parseArgs(["--rpc", "https://api.mainnet-beta.solana.com"]);
    expect(result.rpcUrl).toBe("https://api.mainnet-beta.solana.com");
  });

  it("C2 parses --vault-pda <pubkey>", () => {
    const result = parseArgs(["--vault-pda", "SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf"]);
    expect(result.vaultPda).toBe("SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf");
  });

  it("C3 parses --rpc and --vault-pda together with a file argument", () => {
    const result = parseArgs([
      "msg.b64",
      "--rpc", "https://devnet.example.com",
      "--vault-pda", "11111111111111111111111111111112",
    ]);
    expect(result.file).toBe("msg.b64");
    expect(result.rpcUrl).toBe("https://devnet.example.com");
    expect(result.vaultPda).toBe("11111111111111111111111111111112");
  });

  it("C4 rpcUrl is undefined when --rpc is not provided", () => {
    const result = parseArgs(["msg.b64"]);
    expect(result.rpcUrl).toBeUndefined();
  });

  it("C5 vaultPda is undefined when --vault-pda is not provided", () => {
    const result = parseArgs(["msg.b64"]);
    expect(result.vaultPda).toBeUndefined();
  });

  it("C6 existing --threshold and --json flags still parse correctly alongside new flags", () => {
    const result = parseArgs([
      "msg.b64",
      "--threshold", "5000000000",
      "--json",
      "--rpc", "https://api.mainnet-beta.solana.com",
    ]);
    expect(result.threshold).toBe(5_000_000_000);
    expect(result.jsonOnly).toBe(true);
    expect(result.rpcUrl).toBe("https://api.mainnet-beta.solana.com");
  });

  it("C7 throws when --rpc is provided without a value", () => {
    expect(() => parseArgs(["--rpc"])).toThrow();
  });

  it("C8 throws when --vault-pda is provided without a value", () => {
    expect(() => parseArgs(["--vault-pda"])).toThrow();
  });
});

// ---------------------------------------------------------------------------
// C_STRICT: --strict flag parsing
// ---------------------------------------------------------------------------

describe("C_STRICT: parseArgs --strict flag", () => {
  it("C9 --strict alone sets strict:true", () => {
    const result = parseArgs(["--strict"]);
    expect(result.strict).toBe(true);
  });

  it("C10 --strict with --rpc composes correctly", () => {
    const result = parseArgs(["--strict", "--rpc", "https://mainnet.example.com"]);
    expect(result.strict).toBe(true);
    expect(result.rpcUrl).toBe("https://mainnet.example.com");
  });

  it("C11 --strict with --threshold composes correctly", () => {
    const result = parseArgs(["--strict", "--threshold", "2000000000"]);
    expect(result.strict).toBe(true);
    expect(result.threshold).toBe(2_000_000_000);
  });

  it("C12 --strict with --rpc and --threshold all compose", () => {
    const result = parseArgs([
      "msg.b64",
      "--strict",
      "--rpc", "https://api.devnet.solana.com",
      "--threshold", "500000000",
    ]);
    expect(result.file).toBe("msg.b64");
    expect(result.strict).toBe(true);
    expect(result.rpcUrl).toBe("https://api.devnet.solana.com");
    expect(result.threshold).toBe(500_000_000);
  });

  it("C13 strict is undefined when --strict is not provided", () => {
    const result = parseArgs(["msg.b64", "--rpc", "https://api.mainnet-beta.solana.com"]);
    expect(result.strict).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// v0.5: --simulate flag parsing
// ---------------------------------------------------------------------------

describe("v0.5 C_SIMULATE: parseArgs --simulate flag", () => {
  it("C14 --simulate without --rpc throws (fail-closed: simulation needs RPC)", () => {
    expect(() => parseArgs(["--simulate"])).toThrow(/--rpc/i);
  });

  it("C15 --simulate with --rpc parses correctly", () => {
    const result = parseArgs(["--simulate", "--rpc", "https://api.mainnet-beta.solana.com"]);
    expect(result.simulate).toBe(true);
    expect(result.rpcUrl).toBe("https://api.mainnet-beta.solana.com");
  });

  it("C16 --simulate is undefined when not provided", () => {
    const result = parseArgs(["--rpc", "https://api.mainnet-beta.solana.com"]);
    expect(result.simulate).toBeUndefined();
  });

  it("C17 --simulate with --rpc and other flags composes correctly", () => {
    const result = parseArgs([
      "msg.b64",
      "--rpc", "https://api.mainnet-beta.solana.com",
      "--simulate",
      "--strict",
      "--threshold", "2000000000",
    ]);
    expect(result.simulate).toBe(true);
    expect(result.strict).toBe(true);
    expect(result.threshold).toBe(2_000_000_000);
    expect(result.rpcUrl).toBe("https://api.mainnet-beta.solana.com");
  });
});
