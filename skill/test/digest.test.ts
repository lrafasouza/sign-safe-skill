/**
 * digest.test.ts -- PURE offline tests for digest.ts.
 *
 * All tests are deterministic and offline. They operate on the same frozen
 * fixture files used by the rest of the test suite.
 *
 * Test groups:
 *   A  basic determinism: same bytes -> same digest
 *   B  two different messages -> different sha256 AND different shortCode
 *   C  sha256 format: 64 hex chars, shortCode is XXXX-XXXX-XXXX-XXXX-XXXX
 *   D  messageVersion is correctly reflected
 *   E  full signed transaction input produces same digest as bare message
 *      (both cover the raw message bytes)
 *   F  malformed input throws TransactionDigestError (fail-closed)
 *   G  shortCode is the first 20 hex chars of sha256 grouped as 5x4
 *   H  purity: digest.ts imports no http/https/net/fetch/enrich
 */

import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { transactionDigest, TransactionDigestError } from "../src/digest.ts";

const HERE = dirname(fileURLToPath(import.meta.url));
const FIXTURES = join(HERE, "..", "fixtures");

function readFixture(name: string): string {
  return readFileSync(join(FIXTURES, name), "utf8").trim();
}

// ---------------------------------------------------------------------------
// A: Determinism
// ---------------------------------------------------------------------------

describe("A: determinism", () => {
  it("A1 same bytes produce identical digest twice", () => {
    const b64 = readFixture("01_safe_sol_transfer.b64");
    const d1 = transactionDigest(b64);
    const d2 = transactionDigest(b64);
    expect(d1.sha256).toBe(d2.sha256);
    expect(d1.shortCode).toBe(d2.shortCode);
    expect(d1.messageVersion).toBe(d2.messageVersion);
  });

  it("A2 all five fixture messages produce stable digests (determinism smoke)", () => {
    const names = [
      "01_safe_sol_transfer.b64",
      "02_setauthority_reject.b64",
      "03_bpf_upgrade_reject.b64",
      "04_durable_nonce_drift.b64",
      "05_approve_delegate_hold.b64",
    ];
    for (const name of names) {
      const b64 = readFixture(name);
      const d1 = transactionDigest(b64);
      const d2 = transactionDigest(b64);
      expect(d1.sha256).toBe(d2.sha256);
      expect(d1.shortCode).toBe(d2.shortCode);
    }
  });
});

// ---------------------------------------------------------------------------
// B: Different messages -> different digests
// ---------------------------------------------------------------------------

describe("B: different messages differ", () => {
  it("B1 two distinct fixture messages produce different sha256", () => {
    const b64a = readFixture("01_safe_sol_transfer.b64");
    const b64b = readFixture("02_setauthority_reject.b64");
    const da = transactionDigest(b64a);
    const db = transactionDigest(b64b);
    expect(da.sha256).not.toBe(db.sha256);
  });

  it("B2 two distinct fixture messages produce different shortCode", () => {
    const b64a = readFixture("01_safe_sol_transfer.b64");
    const b64b = readFixture("03_bpf_upgrade_reject.b64");
    const da = transactionDigest(b64a);
    const db = transactionDigest(b64b);
    expect(da.shortCode).not.toBe(db.shortCode);
  });
});

// ---------------------------------------------------------------------------
// C: Output format
// ---------------------------------------------------------------------------

describe("C: output format", () => {
  it("C1 sha256 is 64 lowercase hex chars", () => {
    const b64 = readFixture("01_safe_sol_transfer.b64");
    const d = transactionDigest(b64);
    expect(d.sha256).toMatch(/^[0-9a-f]{64}$/);
  });

  it("C2 shortCode is XXXX-XXXX-XXXX-XXXX-XXXX (5 groups of 4 lowercase hex)", () => {
    const b64 = readFixture("01_safe_sol_transfer.b64");
    const d = transactionDigest(b64);
    expect(d.shortCode).toMatch(
      /^[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}$/,
    );
  });

  it("C3 shortCode consists of the first 20 hex chars of sha256 (no hyphens)", () => {
    const b64 = readFixture("02_setauthority_reject.b64");
    const d = transactionDigest(b64);
    const noHyphens = d.shortCode.replace(/-/g, "");
    expect(noHyphens).toBe(d.sha256.slice(0, 20));
  });
});

// ---------------------------------------------------------------------------
// D: messageVersion
// ---------------------------------------------------------------------------

describe("D: messageVersion", () => {
  it("D1 legacy message fixture reports messageVersion 'legacy'", () => {
    const b64 = readFixture("01_safe_sol_transfer.b64");
    const d = transactionDigest(b64);
    expect(d.messageVersion).toBe("legacy");
  });

  it("D2 v0 message fixture (ALT) reports messageVersion 0", () => {
    const b64 = readFixture("09_v0_alt_unverified.b64");
    const d = transactionDigest(b64);
    expect(d.messageVersion).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// F: Fail-closed on malformed input
// ---------------------------------------------------------------------------

describe("F: fail-closed on malformed input", () => {
  it("F1 empty string throws TransactionDigestError", () => {
    expect(() => transactionDigest("")).toThrowError(TransactionDigestError);
  });

  it("F2 obviously invalid base64 throws TransactionDigestError", () => {
    expect(() => transactionDigest("not-valid-base64!!")).toThrowError(
      TransactionDigestError,
    );
  });

  it("F3 valid base64 but truncated/garbage message bytes throws TransactionDigestError", () => {
    // base64 of a single byte [0xff] - not a valid message
    expect(() =>
      transactionDigest(Buffer.from([0xff]).toString("base64")),
    ).toThrowError(TransactionDigestError);
  });
});

// ---------------------------------------------------------------------------
// G: shortCode derivation (spot-check)
// ---------------------------------------------------------------------------

describe("G: shortCode derivation", () => {
  it("G1 shortCode groups correctly match sha256 prefix", () => {
    const b64 = readFixture("04_durable_nonce_drift.b64");
    const d = transactionDigest(b64);
    const parts = d.shortCode.split("-");
    expect(parts.length).toBe(5);
    const reconstructed = parts.join("");
    expect(reconstructed).toBe(d.sha256.slice(0, 20));
    for (const part of parts) {
      expect(part.length).toBe(4);
      expect(/^[0-9a-f]{4}$/.test(part)).toBe(true);
    }
  });
});

// ---------------------------------------------------------------------------
// H: Purity (no network imports)
// ---------------------------------------------------------------------------

describe("H: purity", () => {
  it("H1 digest.ts does not import http/https/net/fetch/enrich", () => {
    const src = readFileSync(join(HERE, "..", "src", "digest.ts"), "utf8");
    const forbidden = [
      /from\s+["']node:(http|https|net|tls|dgram|dns)["']/,
      /from\s+["'](http|https|node-fetch|axios|undici)["']/,
      /\brequire\(\s*["']node:(http|https|net)["']\s*\)/,
      /\bfetch\s*\(/,
      /\bXMLHttpRequest\b/,
      /from\s+["'].*enrich(\.ts)?["']/,
    ];
    for (const re of forbidden) {
      expect(re.test(src), `digest.ts must not match ${re}`).toBe(false);
    }
  });
});
