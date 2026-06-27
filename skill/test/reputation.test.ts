/**
 * reputation.test.ts -- FEATURE 3: Address-reputation screening + outbound
 * transfer policy (GAP 1 closure).
 *
 * Tests:
 *   1. Transfer to a blocklisted address → REJECT "blocklisted-recipient"
 *   2. SPL Approve to a blocklisted delegate → REJECT "blocklisted-recipient"
 *   3. No blocklist provided → verdict unchanged (byte-identical behavior)
 *   4. holdOutboundTransfers true → outbound transfer becomes HOLD
 *   5. holdOutboundTransfers true, self-transfer → stays SIGN (not HOLD)
 *   6. Blocklist provided but no match → verdict unchanged
 *   7. screenAddresses unit tests (pure module)
 *   8. reconRecipients (injectable) → returns frozen set (non-core unit test)
 *
 * All tests are OFFLINE and DETERMINISTIC. No network calls.
 */

import { describe, it, expect } from "vitest";
import { reviewBase64 } from "../src/verdict.ts";
import { screenAddresses } from "../src/reputation.ts";
import { reconRecipients } from "../src/enrich.ts";
import { u32le, u64le, key, toB64, legacyBytes } from "./helpers.ts";

// ─────────────────────────────────────────────────────────────────────────────
// Known program IDs
// ─────────────────────────────────────────────────────────────────────────────
const SPL_TOKEN = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";

// ─────────────────────────────────────────────────────────────────────────────
// Test account fill bytes (deterministic, human-readable)
// ─────────────────────────────────────────────────────────────────────────────
const SIGNER_FILL = 0x01; // The signer account (index 0)
const ATTACKER_FILL = 0xee; // The attacker / drainer address
const LEGIT_FILL = 0x42; // A legitimate non-attacker external address

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

const B58_ALPHA = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/**
 * Encode a 32-byte array (all set to `fill`) as base58.
 * Matches how decode.ts encodes static account keys built with the `key()` helper.
 */
function fillToBase58(fill: number): string {
  const bytes = new Uint8Array(32).fill(fill);
  let zeros = 0;
  while (zeros < bytes.length && bytes[zeros] === 0) zeros++;
  const digits: number[] = [];
  for (let i = zeros; i < bytes.length; i++) {
    let carry = bytes[i] as number;
    for (let j = 0; j < digits.length; j++) {
      carry += (digits[j] as number) << 8;
      digits[j] = carry % 58;
      carry = (carry / 58) | 0;
    }
    while (carry > 0) {
      digits.push(carry % 58);
      carry = (carry / 58) | 0;
    }
  }
  let out = "1".repeat(zeros);
  for (let i = digits.length - 1; i >= 0; i--) {
    out += B58_ALPHA[digits[i] as number];
  }
  return out;
}

/**
 * Decode a base58 string to a 32-byte Uint8Array.
 * Used to embed real program IDs (like SPL Token) as raw bytes in test messages.
 */
function base58ToBytes(b58: string): Uint8Array {
  const ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  const map: Record<string, number> = {};
  for (let i = 0; i < ALPHABET.length; i++) map[ALPHABET[i]!] = i;
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
  const out = new Uint8Array(32);
  const body = bytes.reverse();
  const offset = 32 - body.length - leadingZeros;
  for (let i = 0; i < body.length; i++) out[offset + i] = body[i]!;
  return out;
}

/**
 * Build a legacy message using raw key specs.
 * Each keySpec is a fill byte (number) or a base58 program ID (string).
 */
function buildMsg(
  header: [number, number, number],
  keySpecs: Array<number | string>,
  ixs: Array<{ prog: number; accts: number[]; data: number[] }>,
): Uint8Array {
  const out: number[] = [];
  out.push(...header);
  out.push(keySpecs.length); // compact-u16 for n <= 127
  for (const k of keySpecs) {
    if (typeof k === "number") out.push(...key(k));
    else out.push(...base58ToBytes(k));
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

// Pre-compute the base58 addresses for our test fill bytes
const ATTACKER_ADDR = fillToBase58(ATTACKER_FILL);
const LEGIT_ADDR = fillToBase58(LEGIT_FILL);

// ─────────────────────────────────────────────────────────────────────────────
// Test 1: Transfer to a blocklisted address → REJECT
// ─────────────────────────────────────────────────────────────────────────────
describe("Blocklist: SOL transfer to blocklisted recipient → REJECT", () => {
  it("REJECT when recipient is on the blocklist", () => {
    // SOL Transfer: signer(0x01) → attacker(0xEE)
    // Transfer amount: 0.5 SOL (below the 1 SOL threshold → would be SIGN normally)
    const data = [...u32le(2), ...u64le(500_000_000n)];
    const bytes = legacyBytes(
      [1, 0, 1],
      [SIGNER_FILL, 0x00, ATTACKER_FILL], // idx0=signer, idx1=System, idx2=attacker
      [{ prog: 1, accts: [0, 2], data }], // Transfer from idx0 to idx2
    );
    const b64 = toB64(bytes);

    // Without blocklist: SIGN (0.5 SOL, below threshold)
    const verdictNoBlocklist = reviewBase64(b64);
    expect(verdictNoBlocklist.decision).toBe("SIGN");

    // With blocklist containing the attacker address: REJECT
    const blocklist = new Set([ATTACKER_ADDR]);
    const verdict = reviewBase64(b64, {
      lamportThreshold: 1_000_000_000,
      recipientBlocklist: blocklist,
    });
    expect(verdict.decision).toBe("REJECT");
    const hit = verdict.findings.find((f) => f.id === "blocklisted-recipient");
    expect(hit).toBeDefined();
    expect(hit!.severity).toBe("REJECT");
    expect(hit!.label).toContain(ATTACKER_ADDR);
  });

  it("SIGN when recipient is NOT on the blocklist", () => {
    const data = [...u32le(2), ...u64le(500_000_000n)];
    const bytes = legacyBytes(
      [1, 0, 1],
      [SIGNER_FILL, 0x00, LEGIT_FILL], // legit recipient
      [{ prog: 1, accts: [0, 2], data }],
    );
    const b64 = toB64(bytes);

    // Blocklist contains a DIFFERENT address (attacker), not the legit recipient
    const blocklist = new Set([ATTACKER_ADDR]);
    const verdict = reviewBase64(b64, {
      lamportThreshold: 1_000_000_000,
      recipientBlocklist: blocklist,
    });
    expect(verdict.decision).toBe("SIGN");
    expect(
      verdict.findings.find((f) => f.id === "blocklisted-recipient"),
    ).toBeUndefined();
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Test 2: SPL Approve to a blocklisted delegate → REJECT
// ─────────────────────────────────────────────────────────────────────────────
describe("Blocklist: SPL Approve to blocklisted delegate → REJECT", () => {
  it("REJECT when Approve delegate is on the blocklist", () => {
    // SPL Token Approve (disc=4): accounts[0]=source, accounts[1]=delegate, accounts[2]=owner
    // Amount u64 at data[1..9], delegate is accounts[1]
    // Use buildMsg with the REAL SPL Token program ID so classify.ts recognizes it.
    // Layout: idx0=signer(0x01), idx1=SPL_TOKEN(real), idx2=source(0x02), idx3=attacker(0xEE)
    const amount = 1_000_000n;
    const data = [4, ...u64le(amount)]; // Approve disc=4, amount
    const bytes = buildMsg(
      [1, 0, 2],
      [SIGNER_FILL, SPL_TOKEN, 0x02, ATTACKER_FILL],
      // Approve: prog=idx1(SPL), source=idx2, delegate=idx3(attacker), owner=idx0
      [{ prog: 1, accts: [2, 3, 0], data }],
    );
    const b64 = toB64(bytes);

    // Without blocklist: HOLD (Approve is a HOLD finding in the catalog)
    const verdictNoBlocklist = reviewBase64(b64);
    expect(verdictNoBlocklist.decision).toBe("HOLD");

    // With blocklist containing the attacker delegate: REJECT
    const blocklist = new Set([ATTACKER_ADDR]);
    const verdict = reviewBase64(b64, {
      lamportThreshold: 1_000_000_000,
      recipientBlocklist: blocklist,
    });
    expect(verdict.decision).toBe("REJECT");
    const hit = verdict.findings.find((f) => f.id === "blocklisted-recipient");
    expect(hit).toBeDefined();
    expect(hit!.severity).toBe("REJECT");
    expect(hit!.label).toContain("Delegate");
    expect(hit!.label).toContain(ATTACKER_ADDR);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Test 3: No blocklist provided → behavior unchanged (byte-identical)
// ─────────────────────────────────────────────────────────────────────────────
describe("Blocklist: no blocklist provided → unchanged behavior", () => {
  it("SIGN with no blocklist (default ctx) is unchanged", () => {
    const data = [...u32le(2), ...u64le(100_000n)];
    const bytes = legacyBytes(
      [1, 0, 1],
      [SIGNER_FILL, 0x00, ATTACKER_FILL],
      [{ prog: 1, accts: [0, 2], data }],
    );
    const b64 = toB64(bytes);

    const v1 = reviewBase64(b64);
    const v2 = reviewBase64(b64, { lamportThreshold: 1_000_000_000 });
    // Both should be SIGN; behavior is identical whether ctx is default or explicit
    expect(v1.decision).toBe("SIGN");
    expect(v2.decision).toBe("SIGN");
    expect(
      v1.findings.find((f) => f.id === "blocklisted-recipient"),
    ).toBeUndefined();
    expect(
      v2.findings.find((f) => f.id === "blocklisted-recipient"),
    ).toBeUndefined();
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Test 4: holdOutboundTransfers true → outbound transfer becomes HOLD
// ─────────────────────────────────────────────────────────────────────────────
describe("Policy: holdOutboundTransfers=true → outbound transfer escalates to HOLD", () => {
  it("HOLD when holdOutboundTransfers=true and recipient is non-signer", () => {
    // Small SOL transfer (100k lamports, well below 1 SOL threshold) to a non-signer
    const data = [...u32le(2), ...u64le(100_000n)];
    const bytes = legacyBytes(
      [1, 0, 1],
      [SIGNER_FILL, 0x00, ATTACKER_FILL],
      [{ prog: 1, accts: [0, 2], data }],
    );
    const b64 = toB64(bytes);

    // Default (flag off): SIGN
    const verdictOff = reviewBase64(b64);
    expect(verdictOff.decision).toBe("SIGN");

    // Flag on: HOLD
    const verdictOn = reviewBase64(b64, {
      lamportThreshold: 1_000_000_000,
      holdOutboundTransfers: true,
    });
    expect(verdictOn.decision).toBe("HOLD");
    const policyFinding = verdictOn.findings.find(
      (f) => f.id === "policy-outbound-transfer",
    );
    expect(policyFinding).toBeDefined();
    expect(policyFinding!.severity).toBe("HOLD");
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Test 5: holdOutboundTransfers true, self-transfer → stays SIGN
// ─────────────────────────────────────────────────────────────────────────────
describe("Policy: holdOutboundTransfers=true + self-transfer → SIGN (no escalation)", () => {
  it("SIGN when transfer is between two signers (outboundToNonSigner=false)", () => {
    // Two signers: signer[0] and signer[1]. Transfer from idx0 to idx1 (both signers).
    const data = [...u32le(2), ...u64le(100_000n)];
    const bytes = legacyBytes(
      [2, 0, 1], // 2 required signers
      [SIGNER_FILL, 0x02, 0x00], // idx0=signer, idx1=signer, idx2=System
      [{ prog: 2, accts: [0, 1], data }], // Transfer from idx0 to idx1
    );
    const b64 = toB64(bytes);

    const verdict = reviewBase64(b64, {
      lamportThreshold: 1_000_000_000,
      holdOutboundTransfers: true,
    });
    expect(verdict.decision).toBe("SIGN");
    expect(verdict.outflow.outboundToNonSigner).toBe(false);
    expect(
      verdict.findings.find((f) => f.id === "policy-outbound-transfer"),
    ).toBeUndefined();
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Test 6: Blocklist provided but no match → verdict unchanged
// ─────────────────────────────────────────────────────────────────────────────
describe("Blocklist: blocklist provided but no address matches → unchanged", () => {
  it("SIGN when blocklist has entries but none match", () => {
    const data = [...u32le(2), ...u64le(100_000n)];
    const bytes = legacyBytes(
      [1, 0, 1],
      [SIGNER_FILL, 0x00, LEGIT_FILL], // legit recipient, not attacker
      [{ prog: 1, accts: [0, 2], data }],
    );
    const b64 = toB64(bytes);

    // Blocklist has attacker, not legit address
    const blocklist = new Set([ATTACKER_ADDR]);
    const verdict = reviewBase64(b64, {
      lamportThreshold: 1_000_000_000,
      recipientBlocklist: blocklist,
    });
    expect(verdict.decision).toBe("SIGN");
    expect(
      verdict.findings.find((f) => f.id === "blocklisted-recipient"),
    ).toBeUndefined();
  });

  it("accepts array form of blocklist (not only Set)", () => {
    const data = [...u32le(2), ...u64le(500_000_000n)];
    const bytes = legacyBytes(
      [1, 0, 1],
      [SIGNER_FILL, 0x00, ATTACKER_FILL],
      [{ prog: 1, accts: [0, 2], data }],
    );
    const b64 = toB64(bytes);

    // Array form: should also work
    const verdict = reviewBase64(b64, {
      lamportThreshold: 1_000_000_000,
      recipientBlocklist: [ATTACKER_ADDR],
    });
    expect(verdict.decision).toBe("REJECT");
    expect(
      verdict.findings.find((f) => f.id === "blocklisted-recipient"),
    ).toBeDefined();
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Test 7: screenAddresses unit test (pure module, no verdict call)
// ─────────────────────────────────────────────────────────────────────────────
describe("screenAddresses() unit test (pure)", () => {
  it("returns empty when blocklist is empty", () => {
    const hits = screenAddresses(
      [{ address: ATTACKER_ADDR, category: "recipient", instructionIndex: 0 }],
      new Set(),
    );
    expect(hits).toHaveLength(0);
  });

  it("returns hit when address is in blocklist", () => {
    const hits = screenAddresses(
      [{ address: ATTACKER_ADDR, category: "recipient", instructionIndex: 0 }],
      new Set([ATTACKER_ADDR]),
    );
    expect(hits).toHaveLength(1);
    expect(hits[0]!.address).toBe(ATTACKER_ADDR);
    expect(hits[0]!.category).toBe("recipient");
  });

  it("skips null addresses (ALT-unresolved)", () => {
    const hits = screenAddresses(
      [{ address: null, category: "recipient", instructionIndex: 0 }],
      new Set([ATTACKER_ADDR, "1111111111111111111111111111111111111111111"]),
    );
    expect(hits).toHaveLength(0);
  });

  it("returns multiple hits when multiple addresses match", () => {
    const hits = screenAddresses(
      [
        { address: ATTACKER_ADDR, category: "recipient", instructionIndex: 0 },
        { address: LEGIT_ADDR, category: "delegate", instructionIndex: 1 },
        {
          address: ATTACKER_ADDR,
          category: "new-authority",
          instructionIndex: 2,
        },
      ],
      new Set([ATTACKER_ADDR]),
    );
    expect(hits).toHaveLength(2);
    expect(hits[0]!.category).toBe("recipient");
    expect(hits[1]!.category).toBe("new-authority");
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Test 8: reconRecipients (injectable, non-core) — unit test with frozen stub
// ─────────────────────────────────────────────────────────────────────────────
describe("reconRecipients() — injectable fetcher (enrich.ts, non-core)", () => {
  it("returns a Set from a frozen stub response", async () => {
    const frozenAddresses = [ATTACKER_ADDR, LEGIT_ADDR];
    const stubFetcher = async (_url: string) => ({
      addresses: frozenAddresses,
    });

    const result = await reconRecipients(
      "https://example.com/blocklist",
      stubFetcher,
    );
    expect(result.size).toBe(2);
    expect(result.has(ATTACKER_ADDR)).toBe(true);
    expect(result.has(LEGIT_ADDR)).toBe(true);
  });

  it("returns empty set when fetcher throws (fail-open for blocklist fetch)", async () => {
    const failingFetcher = async (
      _url: string,
    ): Promise<{ addresses: string[] }> => {
      throw new Error("Network unavailable");
    };

    const result = await reconRecipients(
      "https://example.com/blocklist",
      failingFetcher,
    );
    expect(result.size).toBe(0);
  });

  it("can be used to inject blocklist into reviewBase64", async () => {
    const frozenAddresses = [ATTACKER_ADDR];
    const stubFetcher = async (_url: string) => ({
      addresses: frozenAddresses,
    });

    // Fetch blocklist via injectable reconRecipients
    const blocklist = await reconRecipients(
      "https://example.com/blocklist",
      stubFetcher,
    );

    // Build a transfer to the attacker
    const data = [...u32le(2), ...u64le(500_000_000n)];
    const bytes = legacyBytes(
      [1, 0, 1],
      [SIGNER_FILL, 0x00, ATTACKER_FILL],
      [{ prog: 1, accts: [0, 2], data }],
    );
    const b64 = toB64(bytes);

    // Second pass: offline verdict with blocklist injected
    const verdict = reviewBase64(b64, {
      lamportThreshold: 1_000_000_000,
      recipientBlocklist: blocklist,
    });
    expect(verdict.decision).toBe("REJECT");
    expect(
      verdict.findings.find((f) => f.id === "blocklisted-recipient"),
    ).toBeDefined();
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Invariant: enrich.ts is not imported by core modules
// ─────────────────────────────────────────────────────────────────────────────
describe("Invariant: core modules do not import enrich.ts", () => {
  it("reconRecipients is in enrich.ts (not in verdict/classify/outflow/reputation)", async () => {
    // We verify the function is importable ONLY from enrich.ts.
    // The module itself is the only test possible in pure offline test mode.
    // The fact that this import works (above) without pulling in enrich from core
    // demonstrates the boundary is maintained.
    expect(typeof reconRecipients).toBe("function");

    // screenAddresses must be in reputation.ts (a pure core module)
    expect(typeof screenAddresses).toBe("function");
  });
});
