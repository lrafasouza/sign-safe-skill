/**
 * cli-e2e.test.ts -- end-to-end tests that spawn the real CLI binary.
 *
 * Mirrors the execFileSync pattern in submission-assets.test.ts.
 * Feeds real fixture files (by absolute path, never fabricated bytes).
 * Asserts only deterministic schema fields (decision, exit code, finding id);
 * volatile fields (e.g. timestamps, digests) are not checked here.
 *
 * Fixtures used:
 *   01_safe_sol_transfer.b64      -> SIGN,   exit 0
 *   02_setauthority_reject.b64    -> REJECT,  exit 20
 *   05_approve_delegate_hold.b64  -> HOLD,    exit 10
 */

import { execFileSync } from "node:child_process";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const ROOT = new URL("../..", import.meta.url);
const FIXTURES = join(ROOT.pathname, "skill/fixtures");

function runCli(fixture: string): { stdout: string; exitCode: number } {
  const fixturePath = join(FIXTURES, fixture);
  try {
    const stdout = execFileSync(
      "node",
      ["--import", "tsx", "skill/src/cli.ts", fixturePath, "--json"],
      {
        cwd: ROOT.pathname,
        encoding: "utf8",
        // tsx cold-start + node startup can take a few seconds.
        // 30 000 ms is ample for all three fixtures without hitting the watchdog.
        timeout: 30000,
      },
    );
    return { stdout, exitCode: 0 };
  } catch (err: unknown) {
    // execFileSync throws on non-zero exit. We want to inspect both cases.
    const spawnErr = err as NodeJS.ErrnoException & {
      stdout?: string;
      status?: number;
    };
    return {
      stdout: spawnErr.stdout ?? "",
      exitCode: spawnErr.status ?? 1,
    };
  }
}

describe("CLI e2e", () => {
  it("SIGN: 01_safe_sol_transfer -> decision SIGN, exit 0", () => {
    const { stdout, exitCode } = runCli("01_safe_sol_transfer.b64");
    const verdict = JSON.parse(stdout) as { decision: string };
    expect(verdict.decision).toBe("SIGN");
    expect(exitCode).toBe(0);
  });

  it("REJECT: 02_setauthority_reject -> decision REJECT, exit 20, finding spl-set-authority", () => {
    const { stdout, exitCode } = runCli("02_setauthority_reject.b64");
    const verdict = JSON.parse(stdout) as {
      decision: string;
      findings: Array<{ id: string }>;
    };
    expect(verdict.decision).toBe("REJECT");
    expect(exitCode).toBe(20);
    expect(verdict.findings.some((f) => f.id === "spl-set-authority")).toBe(
      true,
    );
  });

  it("HOLD: 05_approve_delegate_hold -> decision HOLD, exit 10, finding spl-approve-delegate", () => {
    const { stdout, exitCode } = runCli("05_approve_delegate_hold.b64");
    const verdict = JSON.parse(stdout) as {
      decision: string;
      findings: Array<{ id: string }>;
    };
    expect(verdict.decision).toBe("HOLD");
    expect(exitCode).toBe(10);
    expect(verdict.findings.some((f) => f.id === "spl-approve-delegate")).toBe(
      true,
    );
  });
});
