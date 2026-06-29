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
    for (const path of [
      "SECURITY.md",
      "SUBMISSION.md",
      "RUBRIC_CHECKLIST.md",
    ]) {
      expect(existsSync(rootPath(path)), `${path} should exist`).toBe(true);
    }
  });

  it("ships evaluator demo, transcript, and guarded signing example", () => {
    for (const path of [
      "DEMO.md",
      "docs/evaluator-transcript.md",
      "examples/guarded-sign-reject.ts",
    ]) {
      expect(existsSync(rootPath(path)), `${path} should exist`).toBe(true);
    }

    expect(packageJson.files).toContain("DEMO.md");
    expect(packageJson.files).toContain("docs/precision-report.md");
    expect(packageJson.files).toContain("docs/evaluator-transcript.md");
    expect(packageJson.files).toContain("examples/");
  });

  it("keeps the README evaluator path short without competitor comparisons", () => {
    const readme = readRoot("README.md");
    expect(readme).toContain("## Judge in 3 minutes");
    expect(readme).toContain("npm ci");
    expect(readme).toContain("npm run verify:all");
    expect(readme).toContain("npm run demo:attack-pack");
    expect(readme).toContain("False SIGN: 0");
    expect(readme).toContain("SIGN is not a universal safety guarantee");

    for (const competitorName of [
      "Cerberus",
      "solana-tx-guard",
      "tx-risk",
      "squads-treasury",
      "competitor",
    ]) {
      expect(readme).not.toContain(competitorName);
    }
  });

  it("documents safe bounty claims and claims to avoid", () => {
    const demo = readRoot("DEMO.md");
    expect(demo).toContain("Scenario 1: benign transfer");
    expect(demo).toContain("Scenario 2: authority transfer");
    expect(demo).toContain("Scenario 3: hidden proposal risk");

    const transcript = readRoot("docs/evaluator-transcript.md");
    expect(transcript).toContain("verify:all passed");
    expect(transcript).toContain("False SIGN: 0");
    expect(transcript).toContain("Boundaries");
    expect(transcript).toContain("SIGN does not mean safe");
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
    expect(submission).toContain("777 tests across 40 files");
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
