#!/usr/bin/env node
/**
 * cli.ts -- thin node entry point. Reads a base64 message from a .b64 file
 * argument or from stdin, runs the OFFLINE core (or online enrichment when
 * --rpc is set), and prints a human verdict table plus the machine-readable
 * verdict.json.
 *
 * Usage:
 *   node --import tsx skill/src/cli.ts <file.b64>
 *   cat msg.b64 | node --import tsx skill/src/cli.ts
 *   node --import tsx skill/src/cli.ts <file.b64> --threshold 5000000000
 *   node --import tsx skill/src/cli.ts <file.b64> --json        # JSON only
 *   node --import tsx skill/src/cli.ts <file.b64> --rpc <url>   # online enrichment
 *   node --import tsx skill/src/cli.ts <file.b64> --rpc <url> --vault-pda <pubkey>
 *
 * Guardrails: this tool NEVER requests a private key, NEVER signs, and NEVER
 * broadcasts. It only decodes and classifies bytes.
 *
 * When --rpc is provided:
 *   - ALT accounts are fetched to resolve all account roles.
 *   - Squads VaultTransaction PDA is fetched for inner-instruction analysis.
 *   - Token-2022 mint accounts are fetched to confirm dangerous extensions.
 * Without --rpc the behavior is byte-identical to the pure offline path.
 *
 * When --vault-pda <pubkey> is provided alongside --rpc, that specific address
 * is fetched as the Squads VaultTransaction PDA (overrides the auto-extracted
 * address from the message). Without --rpc, --vault-pda is silently ignored.
 */

import { readFileSync, realpathSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { DEFAULT_CONTEXT, type Verdict, type VerdictContext } from "./types.ts";
import { reviewBase64, verdictToJson, rejectVerdict } from "./verdict.ts";
import { transactionDigest, TransactionDigestError } from "./digest.ts";

// ---------------------------------------------------------------------------
// parseArgs is exported so tests can import it without triggering main().
// ---------------------------------------------------------------------------

export interface ParsedArgs {
  file?: string;
  threshold: number;
  jsonOnly: boolean;
  digestOnly: boolean;
  /** JSON-RPC endpoint URL. When set, enables online enrichment. */
  rpcUrl?: string;
  /**
   * Optional override for the Squads VaultTransaction PDA address. When set
   * alongside --rpc, this address is fetched as the vault PDA instead of the
   * one auto-extracted from the message. Silently ignored without --rpc.
   */
  vaultPda?: string;
  /**
   * When true, enables the maximal fail-closed posture (strict mode).
   * Unknown programs writing to writable accounts REJECT (not HOLD).
   * Drift composite uses the broad formula (durable-nonce + any HOLD finding).
   * Suitable for institutional or high-value signers who prefer fail-closed.
   */
  strict?: boolean;
  /**
   * When true, run simulateTransaction to verify economic outcomes.
   * Requires --rpc. If --simulate is given without --rpc, the CLI REJECTS
   * with a clear message (fail-closed: simulation without an RPC is impossible).
   */
  simulate?: boolean;
}

/**
 * Build a fetcher that redirects lookups for `vtAddr` to the pre-fetched bytes
 * of the operator-supplied `vaultPdaAddr`. This is the testable pure-ish helper
 * extracted from the --vault-pda CLI path.
 *
 * When either `vtAddr` or `vaultPdaAccount` is null/undefined, the baseFetcher
 * is returned unchanged (the override is a no-op — the auto-extracted vtAddr
 * was null, meaning there is no Squads ix, or the PDA account was not found).
 *
 * @param b64              Base64 message to scan for the Squads vaultTx address.
 * @param vaultPdaAddr     The operator-supplied vault PDA address (--vault-pda).
 * @param vaultPdaAccount  Pre-fetched account for vaultPdaAddr (may be null).
 * @param vtAddr           Auto-extracted vault tx address from the message (may be null).
 * @param baseFetcher      The underlying real fetcher to delegate non-vtAddr queries to.
 * @returns                Wrapped fetcher (or baseFetcher when override is no-op).
 */
export function buildVaultPdaFetcher(
  vtAddr: string | null,
  vaultPdaAccount: { data: Uint8Array } | null,
  baseFetcher: (pubkey: string) => Promise<{ data: Uint8Array } | null>,
): (pubkey: string) => Promise<{ data: Uint8Array } | null> {
  if (vtAddr === null || vaultPdaAccount === null) {
    // No Squads ix or PDA account not found — override is a no-op.
    return baseFetcher;
  }
  const vaultBytes = vaultPdaAccount.data;
  return async (pubkey: string) => {
    if (pubkey === vtAddr) return { data: vaultBytes };
    return baseFetcher(pubkey);
  };
}

export function parseArgs(argv: string[]): ParsedArgs {
  let file: string | undefined;
  let threshold = DEFAULT_CONTEXT.lamportThreshold;
  let jsonOnly = false;
  let digestOnly = false;
  let rpcUrl: string | undefined;
  let vaultPda: string | undefined;
  let strict: boolean | undefined;
  let simulate: boolean | undefined;

  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--json") {
      jsonOnly = true;
    } else if (a === "--digest") {
      digestOnly = true;
    } else if (a === "--strict") {
      strict = true;
    } else if (a === "--simulate") {
      simulate = true;
    } else if (a === "--threshold") {
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
    } else if (a === "--rpc") {
      const v = argv[++i];
      if (v === undefined || v.startsWith("--")) {
        throw new Error(
          "--rpc requires a URL value (e.g. --rpc https://api.mainnet-beta.solana.com)",
        );
      }
      rpcUrl = v;
    } else if (a === "--vault-pda") {
      const v = argv[++i];
      if (v === undefined || v.startsWith("--")) {
        throw new Error("--vault-pda requires a base58 pubkey value");
      }
      vaultPda = v;
    } else if (!a?.startsWith("--")) {
      file = a;
    }
  }
  // Validate: --simulate requires --rpc. Fail-closed: reject before any network.
  if (simulate && rpcUrl === undefined) {
    throw new Error(
      "--simulate requires --rpc <url>: simulation needs a JSON-RPC endpoint to call simulateTransaction. " +
        "Provide --rpc <url> alongside --simulate.",
    );
  }

  return {
    file,
    threshold,
    jsonOnly,
    digestOnly,
    rpcUrl,
    vaultPda,
    strict,
    simulate,
  };
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

async function main(): Promise<void> {
  // Fail-closed by construction: ANY error in argument parsing or input I/O
  // (bad --threshold, missing file, unreadable stdin) is converted into a
  // REJECT verdict, mirroring reviewBase64's contract. The signing gate must
  // never crash with a stack trace and an ambiguous exit -- a usage/IO failure
  // is treated as "could not establish what is being signed" => REJECT.
  let verdict: Verdict;
  let jsonOnly = false;
  let digestOnly = false;

  try {
    const args = parseArgs(process.argv.slice(2));
    jsonOnly = args.jsonOnly;
    digestOnly = args.digestOnly;
    const b64 = readInput(args.file);

    // --digest: print the transaction digest and exit (no verdict).
    // This is a pure, offline operation; it does NOT replace the verdict.
    if (digestOnly) {
      try {
        const dig = transactionDigest(b64);
        process.stdout.write(`message version : ${dig.messageVersion}\n`);
        process.stdout.write(`sha256          : ${dig.sha256}\n`);
        process.stdout.write(`short code      : ${dig.shortCode}\n`);
        process.stdout.write(
          `\nVerify this short code independently on a second device to confirm the\n` +
            `transaction bytes have not been modified in transit.\n`,
        );
        process.exitCode = 0;
      } catch (err) {
        const detail = err instanceof Error ? err.message : String(err);
        process.stderr.write(`digest error: ${detail}\n`);
        process.exitCode = 20;
      }
      return;
    }

    const ctx: VerdictContext = {
      lamportThreshold: args.threshold,
      ...(args.strict ? { strict: true } : {}),
    };

    if (args.rpcUrl !== undefined) {
      // Online enrichment path: fetch ALT/Squads/mint accounts via RPC.
      // These imports are deferred here so they are NEVER loaded in the pure
      // offline path -- rpc.ts and review-online.ts are host-layer only.
      const { makeRpcAccountFetcher, makeRpcSimulator } =
        await import("./rpc.ts");
      const { reviewWithEnrichment } = await import("./review-online.ts");

      try {
        const fetcher = makeRpcAccountFetcher(args.rpcUrl);

        // --vault-pda override: decode the message to find the vtAddr that
        // review-online would extract, then pre-fetch the override PDA and
        // wrap the fetcher to redirect that vtAddr to the override bytes.
        // This allows the operator to specify a PDA address when the auto-
        // extracted one differs from the desired target.
        let activeFetcher = fetcher;
        if (args.vaultPda !== undefined) {
          const vaultPdaAddr = args.vaultPda;
          try {
            const { decodeInput } = await import("./decode.ts");
            const { extractVaultTransactionAddress } =
              await import("./squads.ts");
            const decoded = decodeInput(b64);
            const vtAddr = extractVaultTransactionAddress(decoded.message);
            const vaultPdaAccount = await fetcher(vaultPdaAddr);
            activeFetcher = buildVaultPdaFetcher(
              vtAddr,
              vaultPdaAccount,
              fetcher,
            );
          } catch {
            // If decode fails, review-online handles it gracefully (fail-closed).
          }
        }

        // Build simulate transport if --simulate flag was given.
        const simulateFn = args.simulate
          ? makeRpcSimulator(args.rpcUrl)
          : undefined;

        verdict = await reviewWithEnrichment(b64, ctx, activeFetcher, {
          simulate: args.simulate,
          simulateFn,
          // Pass rpcUrl for enrichment provenance.
          rpcUrl: args.rpcUrl,
        });
      } catch (err) {
        // Any uncaught error in the online path is REJECT (fail-closed).
        const detail = err instanceof Error ? err.message : String(err);
        verdict = rejectVerdict(`Online enrichment error: ${detail}`);
      }
    } else {
      // Offline path: byte-identical to the original CLI behavior.
      verdict = reviewBase64(b64, ctx);
    }
  } catch (err) {
    const detail = err instanceof Error ? err.message : String(err);
    verdict = rejectVerdict(detail);
  }

  if (!jsonOnly) printHuman(verdict!);
  process.stdout.write(verdictToJson(verdict!) + "\n");

  // Exit code mirrors the verdict so scripts can gate on it.
  // 0 = SIGN, 10 = HOLD, 20 = REJECT.
  process.exitCode =
    verdict!.decision === "SIGN" ? 0 : verdict!.decision === "HOLD" ? 10 : 20;
}

// Guard: run main() only when this module IS the entry point — run directly
// (node dist/src/cli.js), via tsx (node --import tsx skill/src/cli.ts), OR via
// the published bin (npx sign-safe / node_modules/.bin/sign-safe). It must NOT
// run when vitest imports the module.
//
// For the bin, argv[1] is the symlink path ".../sign-safe", which does NOT end
// with "cli.js" — the old endsWith() guard therefore left the published binary
// inert (printed nothing, exited 0 for every transaction). Resolve argv[1]
// through realpath (following the bin symlink) and compare to this module's own
// real path so the bin, the compiled entry, and the tsx entry all run main().
const _argv1 = typeof process !== "undefined" ? (process.argv[1] ?? "") : "";
let _isMain = _argv1.endsWith("cli.ts") || _argv1.endsWith("cli.js");
if (!_isMain && _argv1) {
  try {
    _isMain = realpathSync(_argv1) === fileURLToPath(import.meta.url);
  } catch {
    _isMain = false;
  }
}
if (_isMain) {
  main().catch((err) => {
    process.stderr.write(String(err) + "\n");
    process.exitCode = 20;
  });
}
