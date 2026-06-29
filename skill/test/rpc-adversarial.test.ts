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
 *   RPA3  SPL SetAuthority + an injected ALT fetcher. 02_setauthority_reject
 *         carries no ALT references, so the fetcher is never consulted (the
 *         legacy fixture carries no addressTableLookups), proving the enrichment
 *         ENTRY POINT cannot downgrade the offline REJECT. Does NOT exercise ALT
 *         decoding (the fetcher call count stays 0 for this fixture).
 *   RPA4  Squads execute + an injected PDA fetcher returning undecodable bytes.
 *         Exercises the real Squads PDA fetch + decode-failure path; HOLD stands
 *         (no Token-2022 mints present, so mint screening is not reached).
 *   RPA5  reviewWithEnrichment: stub returning null for every account still
 *         preserves the spl-set-authority finding from 02_setauthority_reject.
 *   RPA6  v0 tx (13_v0_alt_setauthority) + a call-counting ALT fetcher: proves
 *         the ALT enrichment path is genuinely exercised (fetcher.calls > 0),
 *         that the offline spl-set-authority finding is not removed, and that
 *         the enriched decision is not downgraded below the offline verdict.
 *   RPA7  Token-2022 TransferChecked tx (14_token2022_permanent_delegate) + a
 *         benign mint fetcher: proves the mint-extension enrichment path is
 *         genuinely exercised (fetcher.calls > 0) and that the decision is not
 *         downgraded to SIGN.
 *   RPA8  Forged ALT fetcher on 13_v0_alt_setauthority returning attacker-
 *         controlled addresses in the ALT slot — decision must still be not SIGN
 *         (the byte-derived spl-set-authority finding is preserved regardless of
 *         what the enricher resolves).
 */

import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { reviewBase64 } from "../src/verdict.ts";
import { reviewWithEnrichment } from "../src/review-online.ts";
import type { AccountFetcher } from "../src/enrich.ts";
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

describe("RPA3: byte-derived REJECT survives the ALT-enrichment entry point", () => {
  it("RPA3.1 setauthority fixture: offline REJECT matches reviewWithEnrichment REJECT with an ALT fetcher injected (fixture has no ALT refs, so it is not consulted)", async () => {
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

    // Adversarial stub that WOULD return a benign ALT account if consulted. This fixture
    // has no ALT references, so it is never invoked; the assertion below proves the
    // enrichment entry point cannot downgrade the byte-derived REJECT.
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

// ---------------------------------------------------------------------------
// ALT byte builder (reused across RPA6 and RPA8)
// ---------------------------------------------------------------------------

/**
 * Build a syntactically valid on-chain ALT account buffer that decodeAddressLookupTable
 * accepts. The ALT contains a single address (32-byte payload).
 *
 * Layout (matches alt.ts LOOKUP_TABLE_META_SIZE = 56):
 *   [0..4)   discriminator u32-LE = 1
 *   [4..12)  deactivation_slot u64-LE = u64::MAX (active)
 *   [12..20) last_extended_slot u64-LE = 0
 *   [20]     last_extended_slot_start_index u8 = 0
 *   [21]     authority option tag = 0x01 (Some)
 *   [22..54) authority pubkey (32 bytes)
 *   [54..56) padding u16
 *   [56..88) single address (32 bytes)
 */
function buildAltBytes(address32: Uint8Array): Uint8Array {
  const buf: number[] = [];
  // discriminator = 1 (LookupTable), u32-LE
  buf.push(1, 0, 0, 0);
  // deactivation_slot = u64::MAX (active)
  buf.push(0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff);
  // last_extended_slot = 0, u64-LE
  buf.push(0, 0, 0, 0, 0, 0, 0, 0);
  // last_extended_slot_start_index = 0
  buf.push(0);
  // authority = Some; any 32-byte pubkey as authority
  buf.push(0x01);
  buf.push(...new Array(32).fill(0xaa)); // authority bytes (unused by decoder beyond tag)
  // padding u16
  buf.push(0, 0);
  // addresses: the single 32-byte entry
  buf.push(...Array.from(address32));
  return Uint8Array.from(buf);
}

// ---------------------------------------------------------------------------
// RPA6: v0 ALT fixture — fetcher IS consulted, spl-set-authority finding
//        survives, enriched decision not below offline
// ---------------------------------------------------------------------------

describe("RPA6: v0+ALT fixture (13_v0_alt_setauthority) — ALT fetcher is genuinely exercised", () => {
  it("RPA6.1 offline verdict is REJECT (spl-set-authority from instruction bytes)", () => {
    const b64 = readFixtureB64("13_v0_alt_setauthority");
    const verdict = reviewBase64(b64, DEFAULT_CTX);
    expect(verdict.decision).toBe("REJECT");
    expect(verdict.flags.altLookupsPresent).toBe(true);
    expect(verdict.flags.rolesUnverified).toBe(true);
    const finding = verdict.findings.find(
      (f) => f.id === SPL_SET_AUTHORITY_FINDING_ID,
    );
    expect(finding).toBeDefined();
    expect(finding!.severity).toBe("REJECT");
  });

  it("RPA6.2 reviewWithEnrichment: fetcher IS consulted (calls>0), decision not SIGN, spl-set-authority present", async () => {
    const b64 = readFixtureB64("13_v0_alt_setauthority");

    // A call-counting ALT fetcher that returns valid, benign ALT bytes.
    // The ALT contains a single address (all-0xee filler) at writable slot 0.
    let fetcherCallCount = 0;
    const benignAltBytes = buildAltBytes(
      Uint8Array.from(new Array(32).fill(0xee)),
    );
    const countingFetcher: AccountFetcher = async (_pubkey: string) => {
      fetcherCallCount++;
      return { data: benignAltBytes };
    };

    const offlineVerdict = reviewBase64(b64, DEFAULT_CTX);
    const enrichedVerdict = await reviewWithEnrichment(
      b64,
      DEFAULT_CTX,
      countingFetcher,
      { rpcUrl: "https://adversarial-alt-counting.example.com" },
    );

    // The ALT enrichment path must have been entered: the fixture has an
    // addressTableLookup, so reviewWithEnrichment calls fetcher(altAccountKey).
    expect(fetcherCallCount).toBeGreaterThan(0);

    // The byte-derived spl-set-authority finding must survive enrichment.
    const finding = enrichedVerdict.findings.find(
      (f) => f.id === SPL_SET_AUTHORITY_FINDING_ID,
    );
    expect(finding).toBeDefined();
    expect(finding!.severity).toBe("REJECT");

    // Enriched decision must not be downgraded below the offline verdict.
    const DECISION_RANK: Record<string, number> = {
      SIGN: 0,
      HOLD: 1,
      REJECT: 2,
    };
    expect(DECISION_RANK[enrichedVerdict.decision] ?? 0).toBeGreaterThanOrEqual(
      DECISION_RANK[offlineVerdict.decision] ?? 0,
    );

    // Specifically: must NOT be SIGN.
    expect(enrichedVerdict.decision).not.toBe("SIGN");
  });
});

// ---------------------------------------------------------------------------
// RPA7: Token-2022 TransferChecked fixture — mint fetcher IS consulted
// ---------------------------------------------------------------------------

describe("RPA7: Token-2022 TransferChecked fixture (14_token2022_permanent_delegate) — mint fetcher is genuinely exercised", () => {
  it("RPA7.1 offline verdict is HOLD (oversized token transfer)", () => {
    const b64 = readFixtureB64("14_token2022_permanent_delegate");
    const verdict = reviewBase64(b64, DEFAULT_CTX);
    // Offline HOLD due to oversized-token-transfer; no ALT lookups.
    expect(verdict.decision).toBe("HOLD");
    expect(verdict.flags.altLookupsPresent).toBe(false);
    expect(verdict.flags.rolesUnverified).toBe(false);
  });

  it("RPA7.2 reviewWithEnrichment with benign mint fetcher: fetcher IS consulted (calls>0), decision not SIGN", async () => {
    const b64 = readFixtureB64("14_token2022_permanent_delegate");

    // Benign mint fetcher: returns an 82-byte zeroed SPL-style account (no extensions).
    // The enricher will call this for the mint at accountIndexes[1].
    let fetcherCallCount = 0;
    const benignMintFetcher: AccountFetcher = async (_pubkey: string) => {
      fetcherCallCount++;
      return { data: new Uint8Array(82).fill(0) };
    };

    const enrichedVerdict = await reviewWithEnrichment(
      b64,
      DEFAULT_CTX,
      benignMintFetcher,
      { rpcUrl: "https://adversarial-mint-benign.example.com" },
    );

    // The mint-extension enrichment path must have been entered: the fixture has
    // a TransferChecked (disc=12) on TOKEN_2022 with a static mint address.
    expect(fetcherCallCount).toBeGreaterThan(0);

    // Even with a benign mint (no extensions), the offline HOLD from
    // oversized-token-transfer must not be removed (fail-closed).
    expect(enrichedVerdict.decision).not.toBe("SIGN");
  });

  it("RPA7.3 reviewWithEnrichment with permanent-delegate mint fetcher: fetcher IS consulted and decision escalated to HOLD", async () => {
    const b64 = readFixtureB64("14_token2022_permanent_delegate");

    // A mint fetcher returning Token-2022 account data with a PermanentDelegate extension.
    // Token-2022 mint layout (tlv.ts ACCOUNT_TYPE_OFFSET = 165):
    //   [0..165)  base bytes (must reach offset 165 for account_type to be read)
    //   [165]     account_type = 0x01 (Mint)
    //   [166..)   TLV: [type u16-LE][length u16-LE][value bytes...]
    // ExtensionType 12 (PermanentDelegate): 32-byte delegate pubkey value
    let fetcherCallCount = 0;
    const delegateAddr = new Uint8Array(32).fill(0x55); // non-zero delegate
    const mintDataWithDelegate: number[] = [
      ...new Array(165).fill(0x00), // 165 base bytes (ACCOUNT_TYPE_OFFSET)
      0x01, // account_type = Mint at offset 165
      0x0c,
      0x00, // ExtensionType 12 (PermanentDelegate) u16-LE
      0x20,
      0x00, // length 32 u16-LE
      ...Array.from(delegateAddr), // delegate pubkey (32 bytes)
    ];
    const pdMintFetcher: AccountFetcher = async (_pubkey: string) => {
      fetcherCallCount++;
      return { data: Uint8Array.from(mintDataWithDelegate) };
    };

    const enrichedVerdict = await reviewWithEnrichment(
      b64,
      DEFAULT_CTX,
      pdMintFetcher,
      { rpcUrl: "https://adversarial-mint-delegate.example.com" },
    );

    expect(fetcherCallCount).toBeGreaterThan(0);
    expect(enrichedVerdict.decision).not.toBe("SIGN");

    // The enriched verdict should now include the token2022-permanent-delegate finding.
    const delegateFinding = enrichedVerdict.findings.find(
      (f) => f.id === "token2022-permanent-delegate",
    );
    expect(delegateFinding).toBeDefined();
    expect(delegateFinding!.severity).toBe("HOLD");
  });
});

// ---------------------------------------------------------------------------
// RPA8: Forged ALT fetcher — attacker returns fake addresses, still not SIGN
// ---------------------------------------------------------------------------

describe("RPA8: forged ALT fetcher on 13_v0_alt_setauthority — fail-closed even with attacker-controlled ALT data", () => {
  it("RPA8.1 forged ALT bytes with attacker address at slot 0 — decision still not SIGN, spl-set-authority preserved", async () => {
    const b64 = readFixtureB64("13_v0_alt_setauthority");

    // Forged ALT: returns attacker-controlled address at writable slot 0 instead
    // of the real MINT. The classifier sees the instruction discriminator (disc=6
    // on SPL_TOKEN) and fires spl-set-authority from the instruction bytes alone —
    // the resolved account address is irrelevant to the finding.
    let fetcherCallCount = 0;
    const attackerControlledAddr = new Uint8Array(32).fill(0xf0); // forged address
    const forgedAltBytes = buildAltBytes(attackerControlledAddr);
    const forgedFetcher: AccountFetcher = async (_pubkey: string) => {
      fetcherCallCount++;
      return { data: forgedAltBytes };
    };

    const enrichedVerdict = await reviewWithEnrichment(
      b64,
      DEFAULT_CTX,
      forgedFetcher,
      { rpcUrl: "https://adversarial-forged-alt.example.com" },
    );

    // Fetcher was consulted (ALT resolution attempted).
    expect(fetcherCallCount).toBeGreaterThan(0);

    // Fail-closed: even with forged ALT bytes the gate must not be bypassed.
    expect(enrichedVerdict.decision).not.toBe("SIGN");

    // The spl-set-authority finding (byte-derived) must be present regardless
    // of what the ALT resolves to — it fires from instruction discriminator alone.
    const finding = enrichedVerdict.findings.find(
      (f) => f.id === SPL_SET_AUTHORITY_FINDING_ID,
    );
    expect(finding).toBeDefined();
    expect(finding!.severity).toBe("REJECT");
  });

  it("RPA8.2 ALT fetcher returning null (withheld table) — decision still not SIGN, finding preserved", async () => {
    const b64 = readFixtureB64("13_v0_alt_setauthority");

    // Worst-case: ALT fetcher returns null for the table.
    // The enricher silently omits the unresolvable table (fail-closed).
    let fetcherCallCount = 0;
    const nullAltFetcher: AccountFetcher = async (_pubkey: string) => {
      fetcherCallCount++;
      return null;
    };

    const enrichedVerdict = await reviewWithEnrichment(
      b64,
      DEFAULT_CTX,
      nullAltFetcher,
      { rpcUrl: "https://adversarial-null-alt.example.com" },
    );

    expect(fetcherCallCount).toBeGreaterThan(0);
    expect(enrichedVerdict.decision).not.toBe("SIGN");

    const finding = enrichedVerdict.findings.find(
      (f) => f.id === SPL_SET_AUTHORITY_FINDING_ID,
    );
    expect(finding).toBeDefined();
  });
});
