import { execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import packageJson from "../../package.json" with { type: "json" };

const ROOT = new URL("../..", import.meta.url);

function rootPath(path: string): string {
  return join(ROOT.pathname, path);
}

function readRoot(path: string): string {
  return readFileSync(rootPath(path), "utf8");
}

describe("submission proof assets", () => {
  it("registers one-command verification and attack replay scripts", () => {
    expect(packageJson.scripts["verify:all"]).toBe(
      "node scripts/verify-all.mjs",
    );
    expect(packageJson.scripts["demo:attack-pack"]).toBe(
      "npm run build && node scripts/demo-attack-pack.mjs",
    );
  });

  it("ships judge-facing security, submission, and rubric documents", () => {
    for (const path of ["SECURITY.md", "SUBMISSION.md", "RUBRIC_CHECKLIST.md"]) {
      expect(existsSync(rootPath(path)), `${path} should exist`).toBe(true);
    }
  });

  it("documents the precise security boundary without overclaiming on-chain enforcement", () => {
    const security = readRoot("SECURITY.md");
    expect(security).toContain("pre-signing");
    expect(security).toContain("does not custody funds");
    expect(security).toContain("does not enforce limits on-chain");
    expect(security).toContain("responsible disclosure");
  });

  it("submission packet reflects the current local evidence", () => {
    const submission = readRoot("SUBMISSION.md");
    expect(submission).toContain("755 tests across 38 files");
    expect(submission).toContain("36% SIGN / 64% HOLD / 0% false-REJECT");
    expect(submission).toContain("npm run verify:all");
    expect(submission).toContain("npm run demo:attack-pack");
  });

  it("rubric checklist maps bounty claims to concrete evidence", () => {
    const rubric = readRoot("RUBRIC_CHECKLIST.md");
    expect(rubric).toContain("Agent-wallet relevance");
    expect(rubric).toContain("Reproducibility");
    expect(rubric).toContain("Limitations");
    expect(rubric).toContain("Evidence");
  });

  it("attack replay pack proves malicious fixtures do not SIGN", () => {
    const out = execFileSync("npm", ["run", "demo:attack-pack"], {
      cwd: ROOT.pathname,
      encoding: "utf8",
    });
    expect(out).toContain("Attack replay pack");
    expect(out).toContain("Offline pre-sign replay");
    expect(out).toContain("False SIGN: 0");
    expect(out).toContain(
      "RESULT: 37/37 attack fixtures held or rejected before signing",
    );
  });
});
