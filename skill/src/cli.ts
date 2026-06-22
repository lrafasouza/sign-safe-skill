/**
 * cli.ts -- thin node entry point. Reads a base64 message from a .b64 file
 * argument or from stdin, runs the OFFLINE core, and prints a human verdict
 * table plus the machine-readable verdict.json.
 *
 * Usage:
 *   node --import tsx skill/src/cli.ts <file.b64>
 *   cat msg.b64 | node --import tsx skill/src/cli.ts
 *   node --import tsx skill/src/cli.ts <file.b64> --threshold 5000000000
 *   node --import tsx skill/src/cli.ts <file.b64> --json   # JSON only
 *
 * Guardrails: this tool NEVER requests a private key, NEVER signs, and NEVER
 * broadcasts. It only decodes and classifies bytes.
 */

import { readFileSync } from "node:fs";
import { DEFAULT_CONTEXT, type Verdict, type VerdictContext } from "./types.ts";
import { reviewBase64, verdictToJson, rejectVerdict } from "./verdict.ts";

function parseArgs(argv: string[]): {
  file?: string;
  threshold: number;
  jsonOnly: boolean;
} {
  let file: string | undefined;
  let threshold = DEFAULT_CONTEXT.lamportThreshold;
  let jsonOnly = false;
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--json") jsonOnly = true;
    else if (a === "--threshold") {
      const v = argv[++i];
      if (v === undefined || !/^\d+$/.test(v)) {
        throw new Error("--threshold requires an integer lamport value");
      }
      // Reject thresholds that cannot be represented exactly as a JS number.
      // Silently rounding the gate threshold would be a correctness hole, so we
      // fail-closed instead (the CLI catch turns this into a REJECT verdict).
      const parsed = Number(v);
      if (!Number.isSafeInteger(parsed)) {
        throw new Error(
          `--threshold ${v} exceeds the safe integer range (max ${Number.MAX_SAFE_INTEGER})`,
        );
      }
      threshold = parsed;
    } else if (!a?.startsWith("--")) {
      file = a;
    }
  }
  return { file, threshold, jsonOnly };
}

function readInput(file: string | undefined): string {
  if (file) return readFileSync(file, "utf8");
  // stdin fallback
  try {
    return readFileSync(0, "utf8");
  } catch {
    throw new Error("no input: pass a .b64 file path or pipe base64 on stdin");
  }
}

function badge(decision: Verdict["decision"]): string {
  switch (decision) {
    case "SIGN":
      return "[ SIGN ]";
    case "HOLD":
      return "[ HOLD ]";
    case "REJECT":
      return "[ REJECT ]";
  }
}

function printHuman(v: Verdict): void {
  const line = "=".repeat(64);
  process.stdout.write(`\n${line}\n`);
  process.stdout.write(`${badge(v.decision)}  ${v.reason}\n`);
  process.stdout.write(`${line}\n`);
  if (v.inputWasFullTransaction) {
    process.stdout.write(
      `input           : full signed transaction (${v.signatureCount} signature slot(s) stripped, not verified)\n`,
    );
  }
  process.stdout.write(`message version : ${v.messageVersion}\n`);
  process.stdout.write(`worst severity  : ${v.worstSeverity}\n`);
  process.stdout.write(
    `static outflow  : ${v.outflow.lamports} lamports` +
      (v.outflow.splTransfers.length
        ? ` + ${v.outflow.splTransfers.length} SPL transfer(s)`
        : "") +
      "\n",
  );
  process.stdout.write(
    `flags           : unknownProgram=${v.flags.unknownProgramPresent} ` +
      `alt=${v.flags.altLookupsPresent} unverifiedRoles=${v.flags.rolesUnverified} ` +
      `decodeFailed=${v.flags.decodeFailed}\n`,
  );
  if (v.unknownPrograms.length) {
    process.stdout.write(`unknown programs: ${v.unknownPrograms.join(", ")}\n`);
  }
  process.stdout.write(`\nfindings (${v.findings.length}):\n`);
  if (v.findings.length === 0) {
    process.stdout.write("  (none)\n");
  } else {
    for (const f of v.findings) {
      process.stdout.write(
        `  - [${f.severity}] ix#${f.instructionIndex} ${f.label}\n` +
          `      ${f.detail}\n` +
          `      maps to loss: ${f.mapsToLoss}\n`,
      );
    }
  }
  process.stdout.write(`\nverdict.json:\n`);
}

function main(): void {
  // Fail-closed by construction: ANY error in argument parsing or input I/O
  // (bad --threshold, missing file, unreadable stdin) is converted into a
  // REJECT verdict, mirroring reviewBase64's contract. The signing gate must
  // never crash with a stack trace and an ambiguous exit -- a usage/IO failure
  // is treated as "could not establish what is being signed" => REJECT.
  let verdict: Verdict;
  let jsonOnly = false;
  try {
    const args = parseArgs(process.argv.slice(2));
    jsonOnly = args.jsonOnly;
    const ctx: VerdictContext = { lamportThreshold: args.threshold };
    const b64 = readInput(args.file);
    verdict = reviewBase64(b64, ctx);
  } catch (err) {
    const detail = err instanceof Error ? err.message : String(err);
    verdict = rejectVerdict(detail);
  }

  if (!jsonOnly) printHuman(verdict);
  process.stdout.write(verdictToJson(verdict) + "\n");

  // Exit code mirrors the verdict so scripts can gate on it.
  // 0 = SIGN, 10 = HOLD, 20 = REJECT.
  process.exitCode = verdict.decision === "SIGN" ? 0 : verdict.decision === "HOLD" ? 10 : 20;
}

main();
