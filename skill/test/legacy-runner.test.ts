/**
 * legacy-runner.test.ts -- runs the standalone node smoke runner (run.ts) as
 * part of `npm test`, so the project keeps a single, dependency-light runner
 * (usable without vitest, e.g. in a minimal review checkout) AND it is gated by
 * the main suite. The runner exits nonzero on any failure; we assert exit 0.
 */

import { describe, it, expect } from "vitest";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const HERE = dirname(fileURLToPath(import.meta.url));

describe("standalone node runner (test:fixtures)", () => {
  it("run.ts exits 0 (all green)", () => {
    const runner = join(HERE, "run.ts");
    let out = "";
    let code = 0;
    try {
      out = execFileSync(process.execPath, ["--import", "tsx", runner], {
        cwd: join(HERE, "..", ".."),
        encoding: "utf8",
        stdio: ["ignore", "pipe", "pipe"],
      });
    } catch (e) {
      const err = e as { status?: number; stdout?: string; stderr?: string };
      code = err.status ?? 1;
      out = (err.stdout ?? "") + (err.stderr ?? "");
    }
    expect(out, out).toContain("RESULT: ALL GREEN");
    expect(code).toBe(0);
  });
});
