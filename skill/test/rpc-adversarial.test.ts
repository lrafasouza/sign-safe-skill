/**
 * rpc-adversarial.test.ts -- Proof of the property stated in SKILL.md ~line 153:
 *
 *   "RPC data can supply or withhold ALT, Squads PDA, mint-extension, and
 *    simulation context, but it cannot remove or downgrade findings derived
 *    from the signed transaction bytes."
 *
 * Every test uses a SYNTHETIC FROZEN stub fetcher (no real network, no RPC).
 * All byte-derived findings (spl-set-authority, squads-execute-unverified, etc.)
 * must remain present and the final decision must not be downgraded below the
 * offline verdict, regardless of what the injected RPC returns.
 *
 * Test groups:
 *   RPA1  SPL SetAuthority (02_setauthority_reject fixture): stub RPC returning
 *         benign/empty enrichment — REJECT finding spl-set-authority stays present.
 *   RPA2  Squads vaultTransactionExecute (squads fixture): stub RPC returning
 *         null for the VaultTransaction PDA — squads-execute-unverified stays HOLD.
 *   RPA3  SPL SetAuthority + stub ALT (benign enrichment from RPC) — offline
 *         REJECT is not downgraded even when ALT resolution returns benign data.
 *   RPA4  Squads execute + stub fetcher returning empty mint data — offline
 *         decision not downgraded.
 *   RPA5  reviewWithEnrichment: stub returning null for every account still
 *         preserves the spl-set-authority finding from 02_setauthority_reject.
 */

import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { reviewBase64 } from "../src/verdict.ts";
import { reviewWithEnrichment } from "../src/review-online.ts";
import type { VerdictContext } from "../src/types.ts";

// ---------------------------------------------------------------------------
// Fixture paths
// ---------------------------------------------------------------------------

const HERE = dirname(fileURLToPath(import.meta.url));
const FIXTURES = join(HERE, "..", "fixtures");

function readFixtureB64(name: string): string {
  return readFileSync(join(FIXTURES, `${name}.b64`), "utf8").trim();
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const SPL_SET_AUTHORITY_FINDING_ID = "spl-set-authority";
const SQUADS_EXECUTE_UNVERIFIED_FINDING_ID = "squads-execute-unverified";
const SQUADS_V4 = "SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf";

/** u32-LE encoder */
function u32le(n: number): number[] {
  return [n & 0xff, (n >>> 8) & 0xff, (n >>> 16) & 0xff, (n >>> 24) & 0xff];
}

// ---------------------------------------------------------------------------
// Byte-building helpers (reused from review-online.test.ts pattern)
// ---------------------------------------------------------------------------

function base58ToBytes32(b58: string): Uint8Array {
  const A = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  const m: Record<string, number> = {};
  for (let i = 0; i < A.length; i++) m[A[i]!] = i;
  const bytes: number[] = [];
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

/** Build a synthetic VaultTransaction PDA account with no meaningful inner instructions. */
function buildEmptyVaultTxBytes(): Uint8Array {
  const VAULT_TX_ACCOUNT_DISC = [
    0xa8, 0xfa, 0xa2, 0x64, 0x51, 0x0e, 0xa2, 0xcf,
  ];
  const bytes: number[] = [];
  bytes.push(...VAULT_TX_ACCOUNT_DISC);
  bytes.push(...new Array(32).fill(0x01)); // multisig
  bytes.push(...new Array(32).fill(0x02)); // creator
  bytes.push(1, 0, 0, 0, 0, 0, 0, 0); // index u64-LE
  bytes.push(255, 0, 254); // bump, vault_index, vault_bump
  bytes.push(0, 0, 0, 0); // ephemeral_signer_bumps Vec<u8> len=0
  bytes.push(1, 1, 1); // num_signers, num_writable_signers, num_writable_non_signers
  bytes.push(...u32le(0)); // 0 account keys
  bytes.push(...u32le(0)); // 0 instructions
  bytes.push(...u32le(0)); // 0 address_table_lookups
  return new Uint8Array(bytes);
}

// ---------------------------------------------------------------------------
// Default context
// ---------------------------------------------------------------------------

const DEFAULT_CTX: VerdictContext = { lamportThreshold: 1_000_000_000 };

// ---------------------------------------------------------------------------
// RPA1: SPL SetAuthority fixture + null/benign stub RPC
// ---------------------------------------------------------------------------

describe("RPA1: spl-set-authority finding from bytes persists when RPC returns benign data", () => {
  it("RPA1.1 offline reviewBase64 on 02_setauthority_reject → REJECT, spl-set-authority present", () => {
    const b64 = readFixtureB64("02_setauthority_reject");
    const verdict = reviewBase64(b64, DEFAULT_CTX);

    // Byte-derived REJECT must be present
    expect(verdict.decision).toBe("REJECT");
    const finding = verdict.findings.find(
      (f) => f.id === SPL_SET_AUTHORITY_FINDING_ID,
    );
    expect(finding).toBeDefined();
    expect(finding!.severity).toBe("REJECT");
  });

  it("RPA1.2 reviewWithEnrichment with null-returning stub RPC → still REJECT, spl-set-authority present", async () => {
    const b64 = readFixtureB64("02_setauthority_reject");

    // Adversarial stub: returns null for every account (as if withholding data)
    const nullFetcher = async (_pubkey: string) => null;

    const verdict = await reviewWithEnrichment(b64, DEFAULT_CTX, nullFetcher, {
      rpcUrl: "https://adversarial-null.example.com",
    });

    // The byte-derived REJECT must survive the enrichment path
    expect(verdict.decision).toBe("REJECT");
    const finding = verdict.findings.find(
      (f) => f.id === SPL_SET_AUTHORITY_FINDING_ID,
    );
    expect(finding).toBeDefined();
    expect(finding!.severity).toBe("REJECT");
  });

  it("RPA1.3 reviewWithEnrichment with stub returning benign account bytes → still REJECT, spl-set-authority present", async () => {
    const b64 = readFixtureB64("02_setauthority_reject");

    // Adversarial stub: returns benign-looking dummy data for every account request
    const benignFetcher = async (_pubkey: string) => ({
      data: new Uint8Array(82).fill(0), // plain 82-byte zeroed account (looks like a plain SPL mint)
    });

    const verdict = await reviewWithEnrichment(
      b64,
      DEFAULT_CTX,
      benignFetcher,
      {
        rpcUrl: "https://adversarial-benign.example.com",
      },
    );

    // Enrichment with benign RPC data must not downgrade the byte-derived REJECT
    expect(verdict.decision).toBe("REJECT");
    const finding = verdict.findings.find(
      (f) => f.id === SPL_SET_AUTHORITY_FINDING_ID,
    );
    expect(finding).toBeDefined();
    expect(finding!.severity).toBe("REJECT");
  });
});

// ---------------------------------------------------------------------------
// RPA2: Squads vaultTransactionExecute fixture + null stub RPC
// ---------------------------------------------------------------------------

describe("RPA2: squads-execute-unverified finding persists when RPC withholds VaultTransaction PDA", () => {
  it("RPA2.1 offline reviewBase64 on squads_hidden_authority_hold → HOLD, squads-execute-unverified present", () => {
    const b64 = readFixtureB64("squads_hidden_authority_hold");
    const verdict = reviewBase64(b64, DEFAULT_CTX);

    expect(verdict.decision).toBe("HOLD");
    const finding = verdict.findings.find(
      (f) => f.id === SQUADS_EXECUTE_UNVERIFIED_FINDING_ID,
    );
    expect(finding).toBeDefined();
    expect(finding!.severity).toBe("HOLD");
  });

  it("RPA2.2 reviewWithEnrichment null stub → still HOLD, squads-execute-unverified present", async () => {
    const b64 = readFixtureB64("squads_hidden_authority_hold");

    // Adversarial stub: returns null for every account (withholding PDA bytes)
    const nullFetcher = async (_pubkey: string) => null;

    const verdict = await reviewWithEnrichment(b64, DEFAULT_CTX, nullFetcher, {
      rpcUrl: "https://adversarial-withhold.example.com",
    });

    // Fail-closed: without the PDA bytes, squads-execute-unverified must be injected
    expect(verdict.decision).toBe("HOLD");
    const finding = verdict.findings.find(
      (f) => f.id === SQUADS_EXECUTE_UNVERIFIED_FINDING_ID,
    );
    expect(finding).toBeDefined();
    expect(finding!.severity).toBe("HOLD");
  });

  it("RPA2.3 reviewWithEnrichment with empty VaultTransaction (no inner instructions) → still HOLD, squads-execute-unverified present", async () => {
    const b64 = readFixtureB64("squads_hidden_authority_hold");

    // Adversarial stub: returns a VaultTransaction account with NO inner instructions.
    // This simulates an RPC that tries to convince the gate the Squads proposal is empty.
    const emptyVtBytes = buildEmptyVaultTxBytes();

    // We need to know the PDA address to return bytes for it.
    // Parse the message to extract the PDA address.
    const { decodeInput } = await import("../src/decode.ts");
    const { message } = decodeInput(b64);
    const { extractVaultTransactionAddress } = await import("../src/squads.ts");
    const pdaAddr = extractVaultTransactionAddress(message);

    const stubFetcher = async (pubkey: string) => {
      if (pdaAddr !== null && pubkey === pdaAddr) {
        return { data: emptyVtBytes };
      }
      return null;
    };

    const verdict = await reviewWithEnrichment(b64, DEFAULT_CTX, stubFetcher, {
      rpcUrl: "https://adversarial-empty-vt.example.com",
    });

    // Fail-closed: an empty VaultTransaction (zero inner instructions) is treated
    // like no inner bytes — squads-execute-unverified must still be present.
    expect(verdict.decision).toBe("HOLD");
    const finding = verdict.findings.find(
      (f) => f.id === SQUADS_EXECUTE_UNVERIFIED_FINDING_ID,
    );
    expect(finding).toBeDefined();
    expect(finding!.severity).toBe("HOLD");
  });
});

// ---------------------------------------------------------------------------
// RPA3: SPL SetAuthority + benign ALT enrichment — REJECT not downgraded
// ---------------------------------------------------------------------------

describe("RPA3: byte-derived REJECT survives ALT enrichment returning benign data", () => {
  it("RPA3.1 setauthority fixture: offline REJECT matches reviewWithEnrichment REJECT even when fetcher provides benign ALT-like data", async () => {
    const b64 = readFixtureB64("02_setauthority_reject");

    // Offline baseline
    const offlineVerdict = reviewBase64(b64, DEFAULT_CTX);
    expect(offlineVerdict.decision).toBe("REJECT");

    // Build a benign ALT account bytes structure (looks like a valid ALT with harmless addresses)
    // ALT layout: discriminator=1, deactivation_slot=u64::MAX, last_extended_slot=0,
    //             last_extended_slot_start_index=0, authority=None, padding, addresses
    const benignAltBytes: number[] = [];
    benignAltBytes.push(1, 0, 0, 0); // discriminator
    benignAltBytes.push(0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff); // deactivation_slot
    benignAltBytes.push(0, 0, 0, 0, 0, 0, 0, 0); // last_extended_slot
    benignAltBytes.push(0); // last_extended_slot_start_index
    benignAltBytes.push(0x00); // authority = None
    benignAltBytes.push(...new Array(32).fill(0x00)); // authority bytes (ignored)
    benignAltBytes.push(0, 0); // padding
    // 3 harmless addresses filled with benign bytes
    for (let i = 0; i < 3; i++) {
      benignAltBytes.push(...new Array(32).fill(0x10 + i));
    }
    const benignAlt = Uint8Array.from(benignAltBytes);

    // Adversarial stub: always returns a benign ALT account, trying to make enrichment
    // appear to "resolve" all references in a way that seems harmless.
    const benignAltFetcher = async (_pubkey: string) => ({
      data: benignAlt,
    });

    const verdict = await reviewWithEnrichment(
      b64,
      DEFAULT_CTX,
      benignAltFetcher,
      {
        rpcUrl: "https://adversarial-benign-alt.example.com",
      },
    );

    // The byte-derived REJECT from SetAuthority must not be downgraded
    expect(verdict.decision).toBe("REJECT");
    const finding = verdict.findings.find(
      (f) => f.id === SPL_SET_AUTHORITY_FINDING_ID,
    );
    expect(finding).toBeDefined();
    expect(finding!.severity).toBe("REJECT");
  });
});

// ---------------------------------------------------------------------------
// RPA4: Squads fixture + stub fetcher with empty mint data — decision not downgraded
// ---------------------------------------------------------------------------

describe("RPA4: squads HOLD not downgraded by adversarial fetcher returning empty account data", () => {
  it("RPA4.1 squads fixture + stub returning empty 82-byte accounts → still HOLD", async () => {
    const b64 = readFixtureB64("squads_hidden_authority_hold");

    // Adversarial stub: returns empty 82-byte zeroed accounts for everything.
    // This tries to convince the enrichment layer that every account is a benign
    // plain SPL mint (no dangerous extensions), but the offline finding must survive.
    const emptyAccountFetcher = async (_pubkey: string) => ({
      data: new Uint8Array(82).fill(0),
    });

    const verdict = await reviewWithEnrichment(
      b64,
      DEFAULT_CTX,
      emptyAccountFetcher,
      {
        rpcUrl: "https://adversarial-empty-account.example.com",
      },
    );

    // Offline HOLD from squads-execute-unverified must persist
    expect(verdict.decision).toBe("HOLD");
    // Decision must not be downgraded to SIGN
    expect(verdict.decision).not.toBe("SIGN");
  });
});

// ---------------------------------------------------------------------------
// RPA5: Cross-fixture — offline decision is the floor, RPC cannot lower it
// ---------------------------------------------------------------------------

describe("RPA5: offline decision is the floor — RPC enrichment can only escalate or hold steady", () => {
  it("RPA5.1 spl-set-authority REJECT: reviewWithEnrichment >= offline REJECT regardless of stub", async () => {
    const b64 = readFixtureB64("02_setauthority_reject");
    const offlineVerdict = reviewBase64(b64, DEFAULT_CTX);

    // Multiple adversarial fetcher strategies: all should leave decision >= offline
    const fetchers = [
      async (_p: string) => null,
      async (_p: string) => ({ data: new Uint8Array(0) }),
      async (_p: string) => ({ data: new Uint8Array(82).fill(0) }),
    ];

    const DECISION_RANK: Record<string, number> = {
      SIGN: 0,
      HOLD: 1,
      REJECT: 2,
    };

    for (const fetcher of fetchers) {
      const enrichedVerdict = await reviewWithEnrichment(
        b64,
        DEFAULT_CTX,
        fetcher,
        { rpcUrl: "https://adversarial-multi.example.com" },
      );

      const offlineRank = DECISION_RANK[offlineVerdict.decision] ?? 0;
      const enrichedRank = DECISION_RANK[enrichedVerdict.decision] ?? 0;

      // The enriched verdict must be AT LEAST as severe as the offline verdict.
      // RPC cannot downgrade a byte-derived finding.
      expect(enrichedRank).toBeGreaterThanOrEqual(offlineRank);

      // The byte-derived finding must always be present
      const finding = enrichedVerdict.findings.find(
        (f) => f.id === SPL_SET_AUTHORITY_FINDING_ID,
      );
      expect(finding).toBeDefined();
    }
  });

  it("RPA5.2 squads HOLD: reviewWithEnrichment >= offline HOLD regardless of stub", async () => {
    const b64 = readFixtureB64("squads_hidden_authority_hold");
    const offlineVerdict = reviewBase64(b64, DEFAULT_CTX);

    const fetchers = [
      async (_p: string) => null,
      async (_p: string) => ({ data: new Uint8Array(0) }),
      async (_p: string) => ({ data: new Uint8Array(82).fill(0) }),
    ];

    const DECISION_RANK: Record<string, number> = {
      SIGN: 0,
      HOLD: 1,
      REJECT: 2,
    };

    for (const fetcher of fetchers) {
      const enrichedVerdict = await reviewWithEnrichment(
        b64,
        DEFAULT_CTX,
        fetcher,
        { rpcUrl: "https://adversarial-squads.example.com" },
      );

      const offlineRank = DECISION_RANK[offlineVerdict.decision] ?? 0;
      const enrichedRank = DECISION_RANK[enrichedVerdict.decision] ?? 0;

      expect(enrichedRank).toBeGreaterThanOrEqual(offlineRank);
    }
  });
});
