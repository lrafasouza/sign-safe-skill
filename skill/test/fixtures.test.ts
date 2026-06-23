/**
 * fixtures.test.ts -- golden verdicts (T11.2), differential cross-validation
 * against @solana/web3.js (T1.1) AND @solana/kit (T1.2), three-way disagreement
 * fail-closed (T1.3/V10), determinism (T11.1), and the no-network assertion
 * (T11.3).
 */

import { describe, it, expect } from "vitest";
import { VersionedMessage } from "@solana/web3.js";
import * as kit from "@solana/kit";
import { reviewBase64, verdictToJson } from "../src/verdict.ts";
import { decodeBase64Message, decodeMessageBytes } from "../src/decode.ts";
import {
  listFixtures,
  readFixtureB64,
  readFixtureGolden,
} from "./helpers.ts";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { dirname } from "node:path";

const names = listFixtures();
const HERE = dirname(fileURLToPath(import.meta.url));

describe("T11.2 golden verdicts (our core vs committed verdict.json)", () => {
  for (const name of names) {
    it(`${name}`, () => {
      const actual = JSON.parse(verdictToJson(reviewBase64(readFixtureB64(name))));
      expect(actual).toEqual(readFixtureGolden(name));
    });
  }
});

describe("T1.1 differential vs @solana/web3.js (every fixture)", () => {
  for (const name of names) {
    it(`${name}`, () => {
      const raw = new Uint8Array(Buffer.from(readFixtureB64(name), "base64"));
      const w3 = VersionedMessage.deserialize(raw);
      const mine = decodeMessageBytes(raw);

      const w3Keys = w3.staticAccountKeys.map((k) => k.toBase58());
      expect(mine.staticAccountKeys).toEqual(w3Keys);

      const w3Progs = w3.compiledInstructions.map((ci) => w3Keys[ci.programIdIndex]);
      expect(mine.instructions.map((i) => i.programId)).toEqual(w3Progs);

      const w3Version = w3.version === "legacy" ? "legacy" : w3.version;
      expect(mine.version).toBe(w3Version);
      expect(mine.addressTableLookups.length).toBe(w3.addressTableLookups.length);
      expect(mine.recentBlockhash).toBe(w3.recentBlockhash);

      // per-instruction account indexes + data
      w3.compiledInstructions.forEach((ci, i) => {
        expect(mine.instructions[i]!.accountIndexes).toEqual(Array.from(ci.accountKeyIndexes));
        expect(Buffer.from(mine.instructions[i]!.data).toString("hex")).toBe(
          Buffer.from(ci.data).toString("hex"),
        );
      });
    });
  }
});

describe("T1.2 differential vs @solana/kit (second independent reference)", () => {
  const decoder = kit.getCompiledTransactionMessageDecoder();
  for (const name of names) {
    it(`${name}`, () => {
      const raw = new Uint8Array(Buffer.from(readFixtureB64(name), "base64"));
      const km = decoder.decode(raw) as {
        version: number | "legacy";
        staticAccounts: string[];
        instructions: Array<{ programAddressIndex: number }>;
        addressTableLookups?: unknown[];
      };
      const mine = decodeMessageBytes(raw);
      const kitKeys = km.staticAccounts.map((a) => a.toString());
      expect(mine.staticAccountKeys).toEqual(kitKeys);
      expect(mine.instructions.map((i) => i.programId)).toEqual(
        km.instructions.map((i) => kitKeys[i.programAddressIndex]),
      );
      expect(mine.version).toBe(km.version);
      expect(mine.addressTableLookups.length).toBe(km.addressTableLookups?.length ?? 0);
    });
  }
});

describe("T1.3 three-way disagreement => fail closed (V10)", () => {
  /**
   * If web3.js and kit ever DISAGREE on a decode, our gate must not silently
   * pick one and return a benign verdict. We assert the invariant directly: for
   * every input, IF the two references disagree on the normalized shape, our
   * verdict must NOT be SIGN. We probe both the real fixtures (where they agree,
   * so our decode also agrees and the conjunction is vacuously satisfied) and a
   * synthetic near-ALT mutation designed to perturb one reference.
   */
  function refsAgree(raw: Uint8Array): boolean {
    let w3Keys: string[];
    let w3Version: string | number;
    let w3Alts: number;
    try {
      const w3 = VersionedMessage.deserialize(raw);
      w3Keys = w3.staticAccountKeys.map((k) => k.toBase58());
      w3Version = w3.version === "legacy" ? "legacy" : w3.version;
      w3Alts = w3.addressTableLookups.length;
    } catch {
      return false; // one threw => not an agreement
    }
    try {
      const decoder = kit.getCompiledTransactionMessageDecoder();
      const km = decoder.decode(raw) as {
        version: number | "legacy";
        staticAccounts: string[];
        addressTableLookups?: unknown[];
      };
      const kitKeys = km.staticAccounts.map((a) => a.toString());
      if (kitKeys.length !== w3Keys.length) return false;
      if (kitKeys.some((k, i) => k !== w3Keys[i])) return false;
      if (km.version !== w3Version) return false;
      if ((km.addressTableLookups?.length ?? 0) !== w3Alts) return false;
      return true;
    } catch {
      return false;
    }
  }

  for (const name of names) {
    it(`${name}: references agree AND our verdict is consistent`, () => {
      const b64 = readFixtureB64(name);
      const raw = new Uint8Array(Buffer.from(b64, "base64"));
      const agree = refsAgree(raw);
      const v = reviewBase64(b64);
      if (!agree) {
        // If the references disagree, our gate must NOT SIGN.
        expect(v.decision).not.toBe("SIGN");
      }
      // (when they agree, the golden/differential tests already pin correctness)
      expect(["SIGN", "HOLD", "REJECT"]).toContain(v.decision);
    });
  }

  it("a corrupted fixture that breaks at least one reference is never SIGN", () => {
    // Flip a byte in the middle of a v0 ALT fixture; at least one reference
    // (or our decoder) will reject/diverge. Our verdict must not be SIGN.
    const b64 = readFixtureB64("09_v0_alt_unverified");
    const raw = new Uint8Array(Buffer.from(b64, "base64"));
    const mutated = raw.slice();
    const mid = Math.floor(mutated.length / 2);
    mutated[mid] = (mutated[mid] ?? 0) ^ 0xff;
    const v = reviewBase64(Buffer.from(mutated).toString("base64"));
    expect(v.decision).not.toBe("SIGN");
  });
});

describe("T11.1 determinism (decode-twice deep-equal)", () => {
  for (const name of names) {
    it(`${name}`, () => {
      const b64 = readFixtureB64(name);
      expect(verdictToJson(reviewBase64(b64))).toBe(verdictToJson(reviewBase64(b64)));
    });
  }
});

describe("T11.3 no-network assertion (core modules are offline)", () => {
  it("core source files do not import http/https/net/fetch", () => {
    const coreFiles = [
      "decode.ts",
      "roles.ts",
      "classify.ts",
      "classify-inner.ts",
      "outflow.ts",
      "verdict.ts",
      "banned.ts",
      "tlv.ts",
      "types.ts",
      "squads.ts",
      "digest.ts",
      "registry.ts",
      "reputation.ts",
    ];
    const forbidden = [
      /from\s+["']node:(http|https|net|tls|dgram|dns)["']/,
      /from\s+["'](http|https|node-fetch|axios|undici)["']/,
      /\brequire\(\s*["']node:(http|https|net)["']\s*\)/,
      /\bfetch\s*\(/,
      /\bXMLHttpRequest\b/,
    ];
    for (const f of coreFiles) {
      const src = readFileSync(join(HERE, "..", "src", f), "utf8");
      for (const re of forbidden) {
        expect(re.test(src), `${f} must not match ${re}`).toBe(false);
      }
    }
  });
});
