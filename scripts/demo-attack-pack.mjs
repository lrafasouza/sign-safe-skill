#!/usr/bin/env node

import { MALICIOUS_CORPUS } from "../dist/corpus/malicious.js";
import { reviewWithEnrichment } from "../dist/src/review-online.js";
import { reviewBase64 } from "../dist/src/verdict.js";

function makeFrozenFetcher(accounts) {
  return async (pubkey) => {
    const b64 = accounts[pubkey];
    if (!b64) return null;
    return { data: new Uint8Array(Buffer.from(b64, "base64")) };
  };
}

function emptyStats() {
  return { total: 0, caught: 0, sign: 0, hold: 0, reject: 0 };
}

function recordDecision(stats, decision) {
  stats.total++;
  if (decision === "SIGN") stats.sign++;
  if (decision === "HOLD") {
    stats.hold++;
    stats.caught++;
  }
  if (decision === "REJECT") {
    stats.reject++;
    stats.caught++;
  }
}

function pad(value, width) {
  if (value.length >= width) return value;
  return value + " ".repeat(width - value.length);
}

async function reviewFixture(fixture) {
  if (fixture.vaultTxBytes) {
    return reviewBase64(
      fixture.txB64,
      { lamportThreshold: 1_000_000_000 },
      new Uint8Array(fixture.vaultTxBytes),
    );
  }
  return reviewWithEnrichment(
    fixture.txB64,
    { lamportThreshold: 1_000_000_000 },
    makeFrozenFetcher(fixture.accounts ?? {}),
  );
}

async function main() {
  const byFamily = new Map();
  const misses = [];
  const decisionTotals = emptyStats();

  for (const fixture of MALICIOUS_CORPUS) {
    const verdict = await reviewFixture(fixture);
    const family = byFamily.get(fixture.family) ?? emptyStats();
    byFamily.set(fixture.family, family);
    recordDecision(family, verdict.decision);
    recordDecision(decisionTotals, verdict.decision);
    if (verdict.decision === "SIGN") {
      misses.push(`${fixture.family}: ${fixture.note}`);
    }
  }

  console.log("sign-safe Attack replay pack");
  console.log("Offline pre-sign replay; no RPC, no devnet submission.");
  console.log(
    "This proves the signer gate holds or rejects these curated attack fixtures before a key is touched.",
  );
  console.log("");
  console.log(
    `${pad("Family", 32)} ${pad("Caught", 9)} ${pad("REJECT", 6)} ${pad("HOLD", 5)} SIGN`,
  );
  console.log(
    `${"-".repeat(32)} ${"-".repeat(9)} ${"-".repeat(6)} ${"-".repeat(5)} ----`,
  );
  for (const [family, stats] of [...byFamily.entries()].sort()) {
    console.log(
      `${pad(family, 32)} ${pad(`${stats.caught}/${stats.total}`, 9)} ${pad(String(stats.reject), 6)} ${pad(String(stats.hold), 5)} ${stats.sign}`,
    );
  }
  console.log("");
  console.log(`Total attack fixtures: ${decisionTotals.total}`);
  console.log(
    `Caught before signing: ${decisionTotals.caught}/${decisionTotals.total}`,
  );
  console.log(`False SIGN: ${decisionTotals.sign}`);

  if (misses.length > 0) {
    console.log("");
    console.log("Misses:");
    for (const miss of misses) console.log(`- ${miss}`);
    process.exitCode = 1;
    return;
  }

  console.log(
    `RESULT: ${decisionTotals.caught}/${decisionTotals.total} attack fixtures held or rejected before signing`,
  );
}

main().catch((err) => {
  console.error(err instanceof Error ? err.stack || err.message : String(err));
  process.exitCode = 1;
});
