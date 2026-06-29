/**
 * fuzz-fail-closed.test.ts -- Property-based fuzz test for the fail-closed gate.
 *
 * Property: byte-mutating the bytes of an authority-transfer fixture
 * (02_setauthority_reject) must NEVER yield SIGN. Any mutation that produces
 * a SIGN decision is a real fail-closed bug -- the classifier/decoder must be
 * fixed; this test must NEVER be weakened to pass.
 *
 * DECISION rank: SIGN < HOLD < REJECT.
 *
 * Strategy:
 *   For each (index, byteValue) pair drawn by fast-check, flip one byte in
 *   the decoded fixture bytes and call reviewBase64 on the result. The gate
 *   must never return SIGN for any single-byte mutation of a fixture whose
 *   offline verdict is REJECT.
 *
 * Seed: 42 (pinned for reproducibility). Runs: ~2000.
 */

import { describe, it } from "vitest";
import { expect } from "vitest";
import fc from "fast-check";
import { readFixtureB64 } from "./helpers.ts";
import { reviewBase64 } from "../src/verdict.ts";
import type { VerdictContext } from "../src/types.ts";

const DEFAULT_CTX: VerdictContext = { lamportThreshold: 1_000_000_000 };

describe("FUZZ: single-byte mutation of 02_setauthority_reject must never yield SIGN", () => {
  it("FC1 any single-byte mutation of the authority-transfer fixture does not produce SIGN", () => {
    // Read the fixture and decode to raw bytes.
    const b64 = readFixtureB64("02_setauthority_reject");
    const fixtureBytes = Buffer.from(b64, "base64");
    const len = fixtureBytes.length;

    // Confirm the unmodified fixture is REJECT (sanity baseline).
    const baseline = reviewBase64(b64, DEFAULT_CTX);
    expect(baseline.decision).toBe("REJECT");

    // Property: for any (index in [0, len-1], byteValue in [0, 255]),
    // flip that byte and assert the verdict is not SIGN.
    fc.assert(
      fc.property(
        fc.integer({ min: 0, max: len - 1 }),
        fc.integer({ min: 0, max: 255 }),
        (index, byteValue) => {
          // Clone bytes and mutate a single byte.
          const mutated = Buffer.from(fixtureBytes);
          mutated[index] = byteValue;
          const mutatedB64 = mutated.toString("base64");

          const verdict = reviewBase64(mutatedB64, DEFAULT_CTX);

          // The gate MUST be fail-closed: no mutation may produce SIGN.
          // If this assertion fires, that is a real fail-closed bug in the
          // decoder or classifier and MUST be fixed -- never weaken this test.
          expect(verdict.decision).not.toBe("SIGN");
        },
      ),
      { seed: 42, numRuns: 2000 },
    );
  });
});
