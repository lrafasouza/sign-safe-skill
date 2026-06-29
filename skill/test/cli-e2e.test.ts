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
import {
  existsSync,
  mkdtempSync,
  realpathSync,
  rmSync,
  symlinkSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

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

// Regression: the PUBLISHED binary is invoked by its bin name (npx sign-safe /
// node_modules/.bin/sign-safe -> symlink -> dist/src/cli.js). argv[1] is then
// ".../sign-safe", not "...cli.js". A prior guard keyed only on the "cli.js"
// suffix, so the bin ran nothing and exited 0 for EVERY transaction (the
// exit-code gate silently broke). This block runs the COMPILED entry through a
// bin-named symlink and asserts the verdict exit codes survive.
describe("CLI e2e — published bin (compiled, invoked by bin name)", () => {
  const distCli = join(ROOT.pathname, "dist/src/cli.js");
  let binDir: string;
  let binPath: string;

  beforeAll(() => {
    if (!existsSync(distCli)) {
      execFileSync("npm", ["run", "build"], {
        cwd: ROOT.pathname,
        timeout: 120000,
        stdio: "ignore",
      });
    }
    binDir = mkdtempSync(join(tmpdir(), "sign-safe-bin-"));
    binPath = join(binDir, "sign-safe"); // bin NAME, mimicking node_modules/.bin/sign-safe
    symlinkSync(realpathSync(distCli), binPath);
  });

  afterAll(() => {
    if (binDir) rmSync(binDir, { recursive: true, force: true });
  });

  function runBin(fixture: string): number {
    try {
      execFileSync("node", [binPath, join(FIXTURES, fixture), "--json"], {
        encoding: "utf8",
        timeout: 30000,
      });
      return 0;
    } catch (err: unknown) {
      return (err as { status?: number }).status ?? 1;
    }
  }

  it("REJECT via bin name -> exit 20 (regression: bin must run main(), not exit 0)", () => {
    expect(runBin("02_setauthority_reject.b64")).toBe(20);
  });

  it("SIGN via bin name -> exit 0", () => {
    expect(runBin("01_safe_sol_transfer.b64")).toBe(0);
  });

  it("HOLD via bin name -> exit 10", () => {
    expect(runBin("05_approve_delegate_hold.b64")).toBe(10);
  });
});
