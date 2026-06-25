/**
 * run-report.ts -- Offline harness: runs benign + malicious corpus through
 * reviewWithEnrichment with frozen fetchers, computes confusion matrix, and
 * writes docs/precision-report.md.
 *
 * Run with: node --import tsx skill/corpus/run-report.ts
 * Produces: docs/precision-report.md
 *
 * Fully offline — no network, only reads committed JSON fixtures.
 */

import { readFileSync, readdirSync, writeFileSync, mkdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import { reviewWithEnrichment } from "../src/review-online.ts";
import type { AccountFetcher } from "../src/enrich.ts";
import type { Decision, Verdict } from "../src/types.ts";
import { decodeInput } from "../src/decode.ts";
import { MALICIOUS_CORPUS, type MaliciousFixture } from "./malicious.ts";

const HERE = dirname(fileURLToPath(import.meta.url));
const BENIGN_DIR = join(HERE, "benign");
const DOCS_DIR = join(HERE, "..", "..", "docs");

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface BenignFixture {
  slot: number;
  index: number;
  version: "legacy" | 0;
  txB64: string;
  accounts: Record<string, string>;
  programIds: string[];
}

interface BenignResult {
  filename: string;
  slot: number;
  index: number;
  version: string;
  programIds: string[];
  decision: Decision;
  hasAlt: boolean;
  altResolved: boolean;
  verdict: Verdict;
}

interface MaliciousResult {
  family: string;
  note: string;
  expectedDecision: string;
  decision: Decision;
  caught: boolean;
}

// ---------------------------------------------------------------------------
// Frozen fetcher factory
// ---------------------------------------------------------------------------

function makeFrozenFetcher(accounts: Record<string, string>): AccountFetcher {
  return async (pubkey: string) => {
    const b64 = accounts[pubkey];
    if (!b64) return null;
    return { data: new Uint8Array(Buffer.from(b64, "base64")) };
  };
}

function makeEmptyFetcher(): AccountFetcher {
  return async () => null;
}

// ---------------------------------------------------------------------------
// Load benign fixtures
// ---------------------------------------------------------------------------

function loadBenignFixtures(): BenignFixture[] {
  let files: string[];
  try {
    files = readdirSync(BENIGN_DIR).filter(
      (f) => f.endsWith(".json") && f !== "manifest.json",
    );
  } catch {
    console.error("No benign corpus found. Run capture-benign.ts first.");
    return [];
  }
  files.sort();
  return files.map(
    (f) =>
      JSON.parse(readFileSync(join(BENIGN_DIR, f), "utf8")) as BenignFixture,
  );
}

// ---------------------------------------------------------------------------
// Run corpus functions
// ---------------------------------------------------------------------------

export async function runBenignCorpus(
  fixtures: BenignFixture[],
): Promise<BenignResult[]> {
  const results: BenignResult[] = [];

  for (const fixture of fixtures) {
    const fetcher = makeFrozenFetcher(fixture.accounts);
    let decoded: ReturnType<typeof decodeInput> | null = null;
    try {
      decoded = decodeInput(fixture.txB64);
    } catch {
      // Will be reflected in verdict
    }

    const hasAlt = decoded
      ? decoded.message.addressTableLookups.length > 0
      : false;
    const altResolved =
      hasAlt &&
      Object.keys(fixture.accounts).some((k) =>
        decoded?.message.addressTableLookups.some((l) => l.accountKey === k),
      );

    const verdict = await reviewWithEnrichment(
      fixture.txB64,
      { lamportThreshold: 1_000_000_000 },
      fetcher,
    );

    const filename = `${fixture.slot}-${fixture.index}.json`;
    results.push({
      filename,
      slot: fixture.slot,
      index: fixture.index,
      version: String(fixture.version),
      programIds: fixture.programIds,
      decision: verdict.decision,
      hasAlt,
      altResolved,
      verdict,
    });
  }

  return results;
}

export async function runMaliciousCorpus(
  fixtures: MaliciousFixture[],
): Promise<MaliciousResult[]> {
  const results: MaliciousResult[] = [];

  for (const fixture of fixtures) {
    const accounts = fixture.accounts ?? {};
    const fetcher = makeFrozenFetcher(accounts);

    let vaultTxBytes: Uint8Array | undefined;
    if (fixture.vaultTxBytes) {
      vaultTxBytes = new Uint8Array(fixture.vaultTxBytes);
    }

    let verdict: Verdict;
    try {
      // reviewWithEnrichment doesn't accept vaultTxBytes directly —
      // we need to pass it via reviewBase64. Use reviewBase64 when vaultTxBytes is present.
      if (vaultTxBytes) {
        const { reviewBase64 } = await import("../src/verdict.ts");
        verdict = reviewBase64(
          fixture.txB64,
          { lamportThreshold: 1_000_000_000 },
          vaultTxBytes,
        );
      } else {
        verdict = await reviewWithEnrichment(
          fixture.txB64,
          { lamportThreshold: 1_000_000_000 },
          fetcher,
        );
      }
    } catch (e) {
      // Shouldn't happen — verdict never throws, but guard anyway
      console.error(
        `  Error running malicious fixture (${fixture.family}): ${e}`,
      );
      results.push({
        family: fixture.family,
        note: fixture.note,
        expectedDecision: fixture.expectedDecision,
        decision: "SIGN", // worst case: failed to detect
        caught: false,
      });
      continue;
    }

    // "caught" means HOLD or REJECT (not SIGN)
    const caught = verdict.decision === "HOLD" || verdict.decision === "REJECT";

    results.push({
      family: fixture.family,
      note: fixture.note,
      expectedDecision: fixture.expectedDecision,
      decision: verdict.decision,
      caught,
    });
  }

  return results;
}

// ---------------------------------------------------------------------------
// ALT sub-test: compare with vs without resolved ALTs
// ---------------------------------------------------------------------------

async function runAltSubTest(
  benignResults: BenignResult[],
  benignFixtures: BenignFixture[],
): Promise<
  Array<{
    filename: string;
    withResolution: Decision;
    withoutResolution: Decision;
    hasAlt: boolean;
  }>
> {
  // Pick up to 5 benign v0+ALT fixtures
  const v0AltResults = benignResults
    .filter((r) => r.hasAlt && r.version === "0")
    .slice(0, 5);

  const subTestResults: Array<{
    filename: string;
    withResolution: Decision;
    withoutResolution: Decision;
    hasAlt: boolean;
  }> = [];

  for (const result of v0AltResults) {
    const fixture = benignFixtures.find(
      (f) => `${f.slot}-${f.index}.json` === result.filename,
    );
    if (!fixture) continue;

    // With resolution (frozen fetcher with ALT accounts)
    const withResolution = result.decision;

    // Without resolution (empty fetcher — ALTs unresolved)
    const emptyFetcher = makeEmptyFetcher();
    const withoutVerdict = await reviewWithEnrichment(
      fixture.txB64,
      { lamportThreshold: 1_000_000_000 },
      emptyFetcher,
    );

    subTestResults.push({
      filename: result.filename,
      withResolution,
      withoutResolution: withoutVerdict.decision,
      hasAlt: result.hasAlt,
    });
  }

  return subTestResults;
}

// ---------------------------------------------------------------------------
// Report generation
// ---------------------------------------------------------------------------

function severityOrder(d: Decision): number {
  if (d === "REJECT") return 2;
  if (d === "HOLD") return 1;
  return 0;
}

function generateReport(
  benignResults: BenignResult[],
  maliciousResults: MaliciousResult[],
  altSubTest: Array<{
    filename: string;
    withResolution: Decision;
    withoutResolution: Decision;
    hasAlt: boolean;
  }>,
): string {
  const lines: string[] = [];

  lines.push("# Sign-Safe Precision Report");
  lines.push("");
  lines.push(`Generated: ${new Date().toISOString()}`);
  lines.push(`Pinned slots: 428290000, 428289500`);
  lines.push("");

  // ---- Benign Summary ----
  const benignSign = benignResults.filter((r) => r.decision === "SIGN");
  const benignHold = benignResults.filter((r) => r.decision === "HOLD");
  const benignReject = benignResults.filter((r) => r.decision === "REJECT");
  const maliciousSign = maliciousResults.filter((r) => r.decision === "SIGN");
  const signPrecisionDenominator = benignSign.length + maliciousSign.length;

  lines.push("## 1. Signing Precision and Review Rate");
  lines.push("");
  lines.push(`Total benign fixtures: **${benignResults.length}**`);
  lines.push(
    `Benign SIGN precision: **${pct(benignSign.length, signPrecisionDenominator)}** (${benignSign.length}/${signPrecisionDenominator} SIGN decisions across this corpus were benign).`,
  );
  lines.push(
    `Benign HOLD rate: **${pct(benignHold.length, benignResults.length)}** (${benignHold.length}/${benignResults.length}).`,
  );
  lines.push("");
  lines.push(
    "These are corpus measurements, not population-wide guarantees. A zero false-REJECT count is useful calibration evidence, but zero false positives is not the optimization target for a fail-closed signing gate; the HOLD rate shows the review cost directly.",
  );
  lines.push("");
  lines.push("| Decision | Count | Pct |");
  lines.push("|----------|-------|-----|");
  const total = benignResults.length;
  lines.push(
    `| SIGN     | ${benignSign.length.toString().padStart(5)} | ${pct(benignSign.length, total)} |`,
  );
  lines.push(
    `| HOLD     | ${benignHold.length.toString().padStart(5)} | ${pct(benignHold.length, total)} |`,
  );
  lines.push(
    `| REJECT   | ${benignReject.length.toString().padStart(5)} | ${pct(benignReject.length, total)} |`,
  );
  lines.push("");

  // ---- Category breakdown ----
  lines.push("### Category Breakdown (benign)");
  lines.push("");
  lines.push("| Version | HasALT | Count |");
  lines.push("|---------|--------|-------|");

  const cats = new Map<string, number>();
  for (const r of benignResults) {
    const cat = `${r.version} / ${r.hasAlt ? "with-ALT" : "no-ALT"}`;
    cats.set(cat, (cats.get(cat) ?? 0) + 1);
  }
  for (const [cat, count] of [...cats.entries()].sort()) {
    const [v, a] = cat.split(" / ");
    lines.push(`| ${v} | ${a} | ${count} |`);
  }
  lines.push("");

  // ---- False-REJECT list ----
  lines.push("## 2. False-REJECTs (Benign REJECTs — Target: 0)");
  lines.push("");
  if (benignReject.length === 0) {
    lines.push(
      "**None.** Zero false-REJECTs. All benign transactions were classified SIGN or HOLD.",
    );
  } else {
    lines.push(
      `**WARNING: ${benignReject.length} false-REJECT(s) detected. These require Opus reviewer judgment.**`,
    );
    lines.push("");
    lines.push("| Fixture | Slot | Version | ProgramIds | Findings |");
    lines.push("|---------|------|---------|------------|----------|");
    for (const r of benignReject) {
      const pids = r.programIds.join(", ");
      const findings = r.verdict.findings
        .filter((f) => f.severity === "REJECT")
        .map((f) => `${f.id}(${f.severity})`)
        .join("; ");
      lines.push(
        `| ${r.filename} | ${r.slot} | ${r.version} | ${pids} | ${findings} |`,
      );
    }
  }
  lines.push("");

  // ---- Over-HOLD Analysis ----
  lines.push("## 3. Benign HOLD Analysis");
  lines.push("");

  const holdWithUnresolvedAlt = benignHold.filter(
    (r) => r.hasAlt && !r.altResolved,
  );
  const holdWithResolvedAlt = benignHold.filter(
    (r) => r.hasAlt && r.altResolved,
  );
  const holdOther = benignHold.filter((r) => !r.hasAlt);

  lines.push(`Total benign HOLDs: **${benignHold.length}**`);
  lines.push("");
  lines.push("| Category | Count | Explanation |");
  lines.push("|----------|-------|-------------|");
  lines.push(
    `| Has unresolved ALT | ${holdWithUnresolvedAlt.length} | ALT accounts could not be resolved (fail-closed HOLD) |`,
  );
  lines.push(
    `| Has resolved ALT   | ${holdWithResolvedAlt.length} | ALT resolved but other HOLD finding present |`,
  );
  lines.push(
    `| No ALT (other)     | ${holdOther.length} | HOLD from non-ALT finding (large transfer, nonce, etc.) |`,
  );
  lines.push("");

  if (holdOther.length > 0) {
    lines.push("### Benign HOLDs (non-ALT causes) — review findings:");
    lines.push("");
    for (const r of holdOther) {
      const holdFindings = r.verdict.findings
        .filter((f) => f.severity === "HOLD")
        .map((f) => `${f.id}`)
        .join(", ");
      lines.push(
        `- **${r.filename}** (slot=${r.slot}): programIds=[${r.programIds.join(", ")}] findings=[${holdFindings}]`,
      );
    }
    lines.push("");
  }

  // ---- ALT Sub-test ----
  lines.push("## 4. ALT Sub-test (A2 Win: Resolution vs Empty Fetcher)");
  lines.push("");
  lines.push(
    "Comparing 5 benign v0+ALT fixtures: decision WITH resolved ALTs vs WITHOUT (empty fetcher).",
  );
  lines.push("");
  lines.push(
    "| Fixture | With Resolution | Without Resolution | Improvement |",
  );
  lines.push("|---------|-----------------|-------------------|-------------|");

  let altImprovementCount = 0;
  for (const r of altSubTest) {
    const improved =
      severityOrder(r.withoutResolution) > severityOrder(r.withResolution);
    if (improved) altImprovementCount++;
    const improvement = improved
      ? "YES — less conservative with resolution"
      : "no change";
    lines.push(
      `| ${r.filename} | ${r.withResolution} | ${r.withoutResolution} | ${improvement} |`,
    );
  }

  lines.push("");
  lines.push(
    `ALT resolution improvements: **${altImprovementCount}/${altSubTest.length}** fixtures showed reduced severity with resolved ALTs.`,
  );
  lines.push("");

  // ---- Malicious Recall ----
  lines.push("## 5. Malicious Corpus Recall");
  lines.push("");
  lines.push(`Total malicious fixtures: **${maliciousResults.length}**`);
  lines.push("");
  lines.push(
    "Caveat: this is a curated, mostly synthetic illustrative set designed around known loss primitives. Its recall measures coverage of these fixtures only; it does not mean the gate catches every malicious transaction. Adding independently sourced real mainnet malicious signatures would materially strengthen this evaluation.",
  );
  lines.push("");

  const families = [...new Set(maliciousResults.map((r) => r.family))];

  lines.push("| Family | Total | Caught (HOLD+REJECT) | Recall |");
  lines.push("|--------|-------|---------------------|--------|");

  let totalCaught = 0;
  const familyRecall = new Map<string, { caught: number; total: number }>();

  for (const family of families) {
    const familyItems = maliciousResults.filter((r) => r.family === family);
    const caught = familyItems.filter((r) => r.caught).length;
    totalCaught += caught;
    familyRecall.set(family, { caught, total: familyItems.length });
    const recallPct = pct(caught, familyItems.length);
    lines.push(
      `| ${family} | ${familyItems.length} | ${caught} | ${recallPct} |`,
    );
  }

  lines.push(
    `| **TOTAL** | **${maliciousResults.length}** | **${totalCaught}** | **${pct(totalCaught, maliciousResults.length)}** |`,
  );
  lines.push("");

  // Detail missed malicious
  const missed = maliciousResults.filter((r) => !r.caught);
  if (missed.length > 0) {
    lines.push("### Missed Malicious Fixtures (GOT SIGN — investigate!)");
    lines.push("");
    for (const r of missed) {
      lines.push(
        `- **${r.family}** (expected ${r.expectedDecision}, got ${r.decision}): ${r.note}`,
      );
    }
    lines.push("");
  } else {
    lines.push(
      "All curated malicious fixtures were caught (HOLD or REJECT). No fixture in this illustrative set received SIGN.",
    );
    lines.push("");
  }

  // Detail per-family
  lines.push("### Per-Fixture Detail (Malicious)");
  lines.push("");
  lines.push("| Family | Expected | Got | Caught | Note |");
  lines.push("|--------|----------|-----|--------|------|");
  for (const r of maliciousResults) {
    const status = r.caught ? "YES" : "**MISSED**";
    lines.push(
      `| ${r.family} | ${r.expectedDecision} | ${r.decision} | ${status} | ${r.note.slice(0, 80)} |`,
    );
  }
  lines.push("");

  // ---- Summary Box ----
  lines.push("## 6. Summary");
  lines.push("");
  lines.push("| Metric | Value |");
  lines.push("|--------|-------|");
  lines.push(`| Benign corpus size | ${total} transactions |`);
  lines.push(
    `| Benign SIGN precision | ${pct(benignSign.length, signPrecisionDenominator)} (${benignSign.length}/${signPrecisionDenominator}) |`,
  );
  lines.push(`| Benign SIGN rate | ${pct(benignSign.length, total)} |`);
  lines.push(`| Benign false-REJECT | ${benignReject.length} |`);
  lines.push(`| Benign HOLD rate | ${pct(benignHold.length, total)} |`);
  lines.push(`| HOLDs with unresolved ALT | ${holdWithUnresolvedAlt.length} |`);
  lines.push(`| HOLDs without ALT | ${holdOther.length} |`);
  lines.push(`| Malicious corpus size | ${maliciousResults.length} fixtures |`);
  lines.push(
    `| Curated malicious-set recall | ${pct(totalCaught, maliciousResults.length)} (${totalCaught}/${maliciousResults.length}) |`,
  );
  lines.push(
    `| ALT sub-test wins | ${altImprovementCount}/${altSubTest.length} |`,
  );

  const aaFamilies = [
    "SetAuthority-AccountOwner",
    "System-Assign",
    "SPL-Approve",
  ];
  for (const f of aaFamilies) {
    const { caught: c, total: t } = familyRecall.get(f) ?? {
      caught: 0,
      total: 0,
    };
    lines.push(`| ${f} recall | ${pct(c, t)} (${c}/${t}) |`);
  }
  lines.push("");

  return lines.join("\n");
}

function pct(n: number, d: number): string {
  if (d === 0) return "0%";
  return `${((n / d) * 100).toFixed(1)}%`;
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main(): Promise<void> {
  console.log("Loading benign corpus...");
  const benignFixtures = loadBenignFixtures();
  console.log(`  ${benignFixtures.length} fixtures loaded`);

  console.log("Running benign corpus (frozen fetchers)...");
  const benignResults = await runBenignCorpus(benignFixtures);

  console.log("Running ALT sub-test...");
  const altSubTest = await runAltSubTest(benignResults, benignFixtures);

  console.log("Running malicious corpus...");
  const maliciousResults = await runMaliciousCorpus(MALICIOUS_CORPUS);

  console.log("Generating report...");
  const report = generateReport(benignResults, maliciousResults, altSubTest);

  mkdirSync(DOCS_DIR, { recursive: true });
  const reportPath = join(DOCS_DIR, "precision-report.md");
  writeFileSync(reportPath, report);
  console.log(`Report written: ${reportPath}`);

  // Print summary to stdout
  const benignSign = benignResults.filter((r) => r.decision === "SIGN").length;
  const benignHold = benignResults.filter((r) => r.decision === "HOLD").length;
  const benignReject = benignResults.filter(
    (r) => r.decision === "REJECT",
  ).length;
  const caught = maliciousResults.filter((r) => r.caught).length;

  console.log("\n=== PRECISION SUMMARY ===");
  console.log(`Benign  SIGN: ${benignSign} / ${benignResults.length}`);
  console.log(`Benign  HOLD: ${benignHold} / ${benignResults.length}`);
  console.log(
    `Benign  REJECT (false): ${benignReject} / ${benignResults.length}`,
  );
  console.log(`Malicious caught: ${caught} / ${maliciousResults.length}`);
  console.log(
    `ALT sub-test improvements: ${altSubTest.filter((r) => severityOrder(r.withoutResolution) > severityOrder(r.withResolution)).length} / ${altSubTest.length}`,
  );

  if (benignReject > 0) {
    console.log(
      "\n!!! WARNING: FALSE REJECTS DETECTED — see report for details !!!",
    );
    const rejectItems = benignResults.filter((r) => r.decision === "REJECT");
    for (const r of rejectItems) {
      console.log(`  ${r.filename}: programIds=${r.programIds.join(", ")}`);
    }
  }
}

main().catch((e) => {
  console.error("FATAL:", e);
  process.exit(1);
});
