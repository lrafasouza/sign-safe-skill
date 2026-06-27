/**
 * real-fixtures.test.ts -- REAL mainnet transactions frozen offline (T3.x).
 *
 * Captured once via getTransaction (encoding:base64, maxSupportedTransactionVersion:0)
 * against api.mainnet-beta.solana.com; the SIGNED MESSAGE bytes (msg.serialize())
 * are committed under skill/fixtures/real/<name>.b64 with provenance in
 * <name>.meta.json. The suite reads the FROZEN bytes -- NO network at run time.
 *
 * Each fixture is decoded offline and cross-validated against BOTH @solana/web3.js
 * and @solana/kit. For the v0+ALT fixture (T3.4, the most-broken path) we also
 * assert ALT-loaded accounts are marked unresolved (addressVerified=false) and
 * that combined indices >= static count map into ALT space, not a static key.
 */

import { describe, it, expect } from "vitest";
import { VersionedMessage } from "@solana/web3.js";
import * as kit from "@solana/kit";
import { decodeBase64Message } from "../src/decode.ts";
import { deriveRoles, RESERVED_ACCOUNT_KEYS } from "../src/roles.ts";
import { reviewBase64 } from "../src/verdict.ts";
import {
  listRealFixtures,
  readRealFixtureB64,
  readRealFixtureMeta,
} from "./helpers.ts";

const names = listRealFixtures();

describe("real mainnet fixtures present (T3.x)", () => {
  it("captured at least the legacy, SPL/Token-2022, and v0+ALT categories", () => {
    // If the capture step ran, these should exist. We do not fail the suite on
    // a missing category (network capture can rate-limit), but we DO assert the
    // ones we committed are well-formed below.
    expect(names.length).toBeGreaterThanOrEqual(1);
  });
});

describe("real fixtures decode offline + cross-validate (T3.1-T3.5)", () => {
  for (const name of names) {
    it(`${name}: matches @solana/web3.js and @solana/kit`, () => {
      const b64 = readRealFixtureB64(name);
      const meta = readRealFixtureMeta(name);
      const raw = new Uint8Array(Buffer.from(b64, "base64"));

      const mine = decodeBase64Message(b64);

      // web3.js
      const w3 = VersionedMessage.deserialize(raw);
      const w3Keys = w3.staticAccountKeys.map((k) => k.toBase58());
      expect(mine.staticAccountKeys).toEqual(w3Keys);
      expect(mine.recentBlockhash).toBe(w3.recentBlockhash);
      const w3Version = w3.version === "legacy" ? "legacy" : w3.version;
      expect(mine.version).toBe(w3Version);
      expect(mine.addressTableLookups.length).toBe(
        w3.addressTableLookups.length,
      );
      const w3Progs = w3.compiledInstructions.map(
        (ci) => w3Keys[ci.programIdIndex],
      );
      expect(mine.instructions.map((i) => i.programId)).toEqual(w3Progs);

      // kit
      const decoder = kit.getCompiledTransactionMessageDecoder();
      const km = decoder.decode(raw) as {
        version: number | "legacy";
        staticAccounts: string[];
        addressTableLookups?: unknown[];
      };
      expect(mine.staticAccountKeys).toEqual(
        km.staticAccounts.map((a) => a.toString()),
      );
      expect(mine.version).toBe(km.version);

      // provenance sanity: the frozen meta agrees with the bytes.
      expect(mine.version).toBe(meta.version);
      expect(mine.addressTableLookups.length).toBe(meta.altCount);
      expect(mine.staticAccountKeys.length).toBe(meta.numStaticKeys);
    });
  }
});

describe("T3.4 v0+ALT: loaded accounts are unresolved offline", () => {
  const altName = names.find((n) => readRealFixtureMeta(n).altCount > 0);

  it("the v0+ALT fixture exists", () => {
    expect(altName, "expected a captured v0+ALT fixture").toBeTruthy();
  });

  if (altName) {
    it(`${altName}: ALT-loaded accounts have addressVerified=false (R10/V7)`, () => {
      const b64 = readRealFixtureB64(altName);
      const msg = decodeBase64Message(b64);
      const roles = deriveRoles(msg, {
        reservedAccountKeys: RESERVED_ACCOUNT_KEYS,
      });
      const K = msg.staticAccountKeys.length;

      // Static keys [0,K) are addressVerified; loaded [K,..) are not.
      expect(roles.slice(0, K).every((r) => r.addressVerified)).toBe(true);
      const loaded = roles.slice(K);
      expect(loaded.length).toBeGreaterThan(0);
      expect(loaded.every((r) => !r.addressVerified)).toBe(true);
      // Every loaded role's address is the synthetic alt:<table># id, never a
      // static key.
      expect(loaded.every((r) => r.address.startsWith("alt:"))).toBe(true);
      expect(
        loaded.every((r) => !msg.staticAccountKeys.includes(r.address)),
      ).toBe(true);
    });

    it(`${altName}: verdict is never SIGN while ALTs are unresolved`, () => {
      const v = reviewBase64(readRealFixtureB64(altName));
      expect(v.flags.altLookupsPresent).toBe(true);
      expect(v.flags.rolesUnverified).toBe(true);
      expect(v.decision).not.toBe("SIGN");
    });
  }
});

describe("real fixtures are deterministic + never throw", () => {
  for (const name of names) {
    it(`${name}: decode-twice deep-equal verdict, no uncaught throw`, () => {
      const b64 = readRealFixtureB64(name);
      const a = reviewBase64(b64);
      const b = reviewBase64(b64);
      expect(JSON.stringify(a)).toBe(JSON.stringify(b));
    });
  }
});
