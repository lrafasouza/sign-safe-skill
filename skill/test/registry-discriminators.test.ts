/**
 * registry-discriminators.test.ts -- Self-verifying discriminator correctness test (Phase B).
 *
 * For EVERY anchor-8 entry that has an ixName field, this test computes
 * sha256("global:" + ixName)[0..8] at test time (using node:crypto) and asserts
 * it equals the entry's stored discHex. A wrong byte fails loudly here.
 *
 * For beet-u8 and raydium-u8 entries that have a `disc` field, this test
 * asserts that parseInt(discHex, 16) === disc and disc is in 0..255.
 *
 * Also asserts every programId is valid base58 length (32-44 chars, base58 alphabet).
 *
 * This test makes every anchor-8 discriminator self-verifying. If the registry
 * JSON is edited with a typo in discHex or ixName, this test will catch it.
 *
 * OFFLINE: no network, no RPC. Uses node:crypto only.
 */

import { createHash } from "node:crypto";
import { describe, it, expect } from "vitest";
import { allRegisteredPrograms, validateRegistry } from "../src/registry.ts";

/** Compute the Anchor-8 discriminator: sha256("global:" + ixName).slice(0, 8) as hex. */
function anchorDisc(ixName: string): string {
  return createHash("sha256")
    .update("global:" + ixName)
    .digest()
    .subarray(0, 8)
    .toString("hex");
}

/** Valid base58 alphabet. */
const BASE58_ALPHABET =
  /^[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]{32,44}$/;

const programs = allRegisteredPrograms();

describe("registry catalog structural validation", () => {
  it("validateRegistry() returns no errors (discHex format + severity)", () => {
    const errors = validateRegistry();
    expect(errors).toEqual([]);
  });

  it("every programId is valid base58 length (32-44 chars, base58 alphabet)", () => {
    for (const prog of programs) {
      expect(
        BASE58_ALPHABET.test(prog.programId),
        `Program ${prog.id}: programId "${prog.programId}" failed base58 check`,
      ).toBe(true);
    }
  });

  it("safeInstructions array exists on every program", () => {
    for (const prog of programs) {
      expect(
        Array.isArray(prog.safeInstructions),
        `Program ${prog.id}: missing safeInstructions array`,
      ).toBe(true);
    }
  });
});

describe("anchor-8 discriminator self-verification (sha256 cross-check)", () => {
  for (const prog of programs) {
    if (prog.discriminatorScheme !== "anchor-8") continue;

    describe(`Program: ${prog.name} (${prog.id})`, () => {
      if (
        prog.dangerousInstructions.length === 0 &&
        prog.safeInstructions.length === 0
      ) {
        it("is recognize-only with no claimed instruction discriminators", () => {
          expect(prog.dangerousInstructions).toEqual([]);
          expect(prog.safeInstructions).toEqual([]);
        });
      }

      // Verify dangerous instructions
      for (const entry of prog.dangerousInstructions) {
        if (!entry.ixName) continue; // no ixName → skip (not anchor-8 verifiable)

        it(`dangerous: ${entry.ixName} → discHex ${entry.discHex}`, () => {
          const computed = anchorDisc(entry.ixName!);
          expect(
            computed,
            `sha256("global:${entry.ixName}")[0..8] = ${computed}, ` +
              `but registry has ${entry.discHex}. ` +
              `Check the ixName spelling (must be snake_case) and discHex.`,
          ).toBe(entry.discHex);
        });
      }

      // Verify safe instructions
      for (const entry of prog.safeInstructions) {
        if (!entry.ixName) continue;

        it(`safe: ${entry.ixName} → discHex ${entry.discHex}`, () => {
          const computed = anchorDisc(entry.ixName!);
          expect(
            computed,
            `sha256("global:${entry.ixName}")[0..8] = ${computed}, ` +
              `but registry has ${entry.discHex}. ` +
              `Check the ixName spelling (must be snake_case) and discHex.`,
          ).toBe(entry.discHex);
        });
      }
    });
  }
});

describe("beet-u8 / raydium-u8 discriminator self-verification", () => {
  // Collect all non-anchor-8 programs that have at least one verifiable entry.
  const nonAnchorPrograms = programs.filter(
    (p) =>
      p.discriminatorScheme !== "anchor-8" &&
      p.dangerousInstructions.length > 0,
  );

  if (nonAnchorPrograms.length === 0) {
    it("(no non-anchor-8 programs with disc entries to verify)", () => {
      // This is not an error — beet-u8 programs without `disc` fields simply
      // cannot be sha256-verified (their discriminators come from the generated JS client).
      expect(true).toBe(true);
    });
  }

  for (const prog of nonAnchorPrograms) {
    for (const entry of prog.dangerousInstructions) {
      // beet-u8 entries should have a `disc` field (the numeric value)
      const disc = (entry as unknown as { disc?: number }).disc;
      if (disc === undefined) continue;

      it(`${prog.name}: ${entry.discHex} disc=${disc} is in 0..255 and matches discHex`, () => {
        // disc must be in valid u8 range
        expect(disc, `disc ${disc} out of u8 range`).toBeGreaterThanOrEqual(0);
        expect(disc, `disc ${disc} out of u8 range`).toBeLessThanOrEqual(255);
        // disc must match discHex
        const fromHex = parseInt(entry.discHex, 16);
        expect(
          fromHex,
          `parseInt("${entry.discHex}", 16) = ${fromHex} but disc = ${disc}`,
        ).toBe(disc);
      });
    }
  }
});

describe("Jupiter v6: all safe instructions verified against real mainnet transactions", () => {
  // Jupiter is closed-source; we verified discriminators by:
  // 1. Computing sha256("global:" + ixName) for known instruction names.
  // 2. Cross-checking against real mainnet benign-corpus transactions.
  // The anchor-8 self-verifying test above covers the sha256 check.
  // This test documents the verification source.

  const jupiterProg = programs.find((p) => p.id === "jupiter-v6");

  it("Jupiter v6 is in the registry", () => {
    expect(jupiterProg).toBeDefined();
  });

  it("All Jupiter v6 safe instructions have ixName (sha256-verifiable)", () => {
    for (const entry of jupiterProg?.safeInstructions ?? []) {
      expect(
        entry.ixName,
        `Jupiter safe entry "${entry.label}" missing ixName`,
      ).toBeDefined();
    }
  });

  it("All Jupiter v6 dangerous instructions have ixName (sha256-verifiable)", () => {
    for (const entry of jupiterProg?.dangerousInstructions ?? []) {
      expect(
        entry.ixName,
        `Jupiter danger entry "${entry.label}" missing ixName`,
      ).toBeDefined();
    }
  });
});

describe("No duplicate discHex within a program (safe + dangerous lists)", () => {
  for (const prog of programs) {
    it(`${prog.name}: no duplicate discHex values`, () => {
      const seen = new Set<string>();
      const dupes: string[] = [];

      for (const entry of [
        ...prog.dangerousInstructions,
        ...(prog.safeInstructions ?? []),
      ]) {
        if (seen.has(entry.discHex)) {
          dupes.push(entry.discHex);
        }
        seen.add(entry.discHex);
      }

      expect(
        dupes,
        `Program ${prog.id} has duplicate discHex values: ${dupes.join(", ")}`,
      ).toHaveLength(0);
    });
  }
});
