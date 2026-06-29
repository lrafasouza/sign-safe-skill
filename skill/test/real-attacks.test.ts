import { readFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import { reviewBase64 } from "../src/verdict.ts";

/**
 * Real documented attack transactions, replayed offline.
 *
 * Fixtures under skill/corpus/malicious/*.json are the RAW on-chain bytes of
 * publicly-documented exploits (captured once by capture-malicious.ts; provenance
 * in each file's meta + docs/real-attacks.md). The honest floor: a documented
 * attack transaction must never be auto-signed (decision !== SIGN).
 */
const HERE = dirname(fileURLToPath(import.meta.url));
const MALICIOUS_DIR = join(HERE, "..", "corpus", "malicious");

interface Frozen {
  signature: string;
  slot: number;
  b64: string;
  meta: {
    incident: string;
    title: string;
    threat_class: string;
    explorer: string;
  };
}

const files = readdirSync(MALICIOUS_DIR).filter(
  (f) => f.endsWith(".json") && f !== "INCIDENTS.json",
);

describe("real documented attack transactions — never SIGN", () => {
  it("ships at least one real captured attack fixture", () => {
    expect(files.length).toBeGreaterThan(0);
  });

  for (const f of files) {
    const entry = JSON.parse(
      readFileSync(join(MALICIOUS_DIR, f), "utf8"),
    ) as Frozen;
    it(`${entry.meta.incident} ${entry.signature.slice(0, 8)}… (${entry.meta.threat_class}) → HOLD/REJECT`, () => {
      const verdict = reviewBase64(entry.b64);
      expect(verdict.decision).not.toBe("SIGN");
    });
  }
});
