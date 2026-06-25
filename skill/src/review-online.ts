/**
 * review-online.ts -- HOST LAYER orchestration: decode + enrichment + offline verdict.
 *
 * ============================ HARD BOUNDARY ============================
 * This module is a HOST LAYER file. It imports from the core but NEVER calls
 * fetch directly. All network access is via the INJECTABLE `fetcher` callback
 * (AccountFetcher) and `simulateFn` (SimulateFn). Real fetch lives ONLY in
 * rpc.ts and cli.ts. Tests can supply a frozen stub; the deterministic core
 * modules are unchanged.
 * ======================================================================
 *
 * Flow:
 *   1. Decode the message with `decodeInput`. If it fails, fall back to the
 *      offline `reviewBase64` path (fail-closed).
 *   2. ALT enrichment: for each addressTableLookup in the message, fetch the
 *      table account and decode it. Build a `resolvedAltTables` map. Any table
 *      whose fetch returns null or whose decode throws is OMITTED (fail-closed:
 *      unresolved ALT stays unverified → HOLD gate preserved).
 *   3. Squads enrichment: call `extractVaultTransactionAddress(msg)` to find the
 *      VaultTransaction PDA address. Fetch it with `fetcher`. If null or the
 *      fetch throws, leave vaultTransactionBytes undefined (the existing HOLD path
 *      fires in reviewBase64: "squads-execute-unverified").
 *   4. Token-2022 mint enrichment: collect the mint address from each Token-2022
 *      TransferChecked instruction (accountIndexes[1] for disc=12). Fetch the
 *      mint account and decode with `decodeMintDangerExtensions`. On fetch null
 *      or decode throw, skip that mint (fail-closed: no downgrade). Build a
 *      `mintExtensions` map and pass to the verdict.
 *   5. Simulation (optional): when opts.simulate is true AND a simulateFn is
 *      provided, call simulateAssetDiff and attach the result as ctx.simulation.
 *      Fail-closed: any simulate error → ctx.simulation = {ok:false, err} → HOLD.
 *      Never skip silently when simulation was requested.
 *   6. Call reviewBase64 with the enriched ctx.
 *   7. Attach enrichment provenance to the returned verdict (host-layer only).
 */

import { decodeInput } from "./decode.ts";
import { deriveRoles, RESERVED_ACCOUNT_KEYS } from "./roles.ts";
import { reviewBase64 } from "./verdict.ts";
import { decodeAddressLookupTable } from "./alt.ts";
import { decodeMintDangerExtensions } from "./tlv.ts";
import { extractVaultTransactionAddress } from "./squads.ts";
import { simulateAssetDiff } from "./simulate.ts";
import type { SimulateFn } from "./simulate.ts";
import type { AccountFetcher } from "./enrich.ts";
import type { Verdict, VerdictContext } from "./types.ts";

const TOKEN_2022_PID = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";

/**
 * Options for reviewWithEnrichment.
 */
export interface ReviewEnrichmentOpts {
  /**
   * When true, run simulateTransaction after static analysis to verify
   * economic outcomes. Requires `simulateFn` to be provided.
   * Fail-closed: any simulate error → ctx.simulation = {ok:false, err} → HOLD.
   */
  simulate?: boolean;
  /**
   * Injectable SimulateFn transport for simulation. Required when simulate=true.
   * Production: makeRpcSimulator(rpcUrl). Tests: frozen stub.
   */
  simulateFn?: SimulateFn;
  /**
   * The RPC URL, used for enrichment provenance in verdict.enrichment.rpcUrl.
   * When provided, it is recorded in the verdict for auditability.
   */
  rpcUrl?: string;
}

function mergeSimulation(
  existing: VerdictContext["simulation"] | undefined,
  fresh: VerdictContext["simulation"] | undefined,
): VerdictContext["simulation"] | undefined {
  if (existing === undefined) return fresh;
  if (fresh === undefined) return existing;
  if (!existing.ok) return existing;
  if (!fresh.ok) return fresh;
  return {
    ok: true,
    signerSolDelta:
      existing.signerSolDelta < fresh.signerSolDelta
        ? existing.signerSolDelta
        : fresh.signerSolDelta,
    signerSolDeltas: [
      ...(existing.signerSolDeltas ?? []),
      ...(fresh.signerSolDeltas ?? []),
    ],
    tokenDeltas: [...existing.tokenDeltas, ...fresh.tokenDeltas],
    outflowsToNonSigner: [
      ...existing.outflowsToNonSigner,
      ...fresh.outflowsToNonSigner,
    ],
  };
}

/**
 * Review a base64-encoded transaction message with online enrichment.
 *
 * This is the HOST LAYER entry point. Unlike `reviewBase64`, it accepts an
 * injectable `fetcher` and performs on-chain fetches to:
 *   - Resolve ALT addresses so all roles can be verified.
 *   - Decode the Squads VaultTransaction PDA for inner-instruction analysis.
 *   - Confirm Token-2022 mint danger extensions for any TransferChecked mint.
 *   - Optionally run simulateTransaction to detect economic outflows (opts.simulate).
 *
 * FAIL-CLOSED: any individual enrichment failure (null account, decode error)
 * is isolated and omitted; it never degrades the verdict below the offline
 * baseline. The online path can only ADD information (escalate to more
 * conservative outcomes), never remove it.
 *
 * @param b64      Base64-encoded Solana message or signed transaction.
 * @param ctx      Verdict context (lamport threshold, etc.).
 * @param fetcher  Injectable AccountFetcher. No real fetch happens here.
 * @param opts     Optional: { simulate, simulateFn } for simulation support.
 * @returns        Promise<Verdict> — the enriched offline verdict, with
 *                 provenance in verdict.enrichment.
 */
export async function reviewWithEnrichment(
  b64: string,
  ctx: VerdictContext,
  fetcher: AccountFetcher,
  opts: ReviewEnrichmentOpts = {},
): Promise<Verdict> {
  // Step 1: Decode. If decode fails, fall back to offline path.
  let decoded: ReturnType<typeof decodeInput>;
  try {
    decoded = decodeInput(b64);
  } catch {
    // Fail-closed: offline reviewBase64 will return a REJECT verdict for the
    // same garbled input. We call it here explicitly so the caller always gets
    // a valid Verdict, never an exception.
    return reviewBase64(b64, ctx);
  }

  const { message: msg } = decoded;

  // Step 2: ALT enrichment.
  // For each v0 addressTableLookup, attempt to fetch and decode the table.
  // Missing/broken tables are silently omitted (fail-closed).
  const resolvedAltTables = new Map<string, readonly string[]>(
    ctx.resolvedAltTables ?? [],
  );
  let resolvedAltTablesFetched = 0;
  for (const lut of msg.addressTableLookups) {
    if (resolvedAltTables.has(lut.accountKey)) continue;
    try {
      const account = await fetcher(lut.accountKey);
      if (account === null) continue; // table not found → omit (fail-closed)
      const decodedLut = decodeAddressLookupTable(account.data);
      resolvedAltTables.set(lut.accountKey, decodedLut.addresses);
      resolvedAltTablesFetched++;
    } catch {
      // Decode threw: omit this table (fail-closed).
      continue;
    }
  }

  const enrichedRoles = deriveRoles(msg, {
    reservedAccountKeys: RESERVED_ACCOUNT_KEYS,
    resolvedAltTables:
      resolvedAltTables.size > 0 ? resolvedAltTables : undefined,
  });

  // Step 3: Squads enrichment.
  // Extract the VaultTransaction PDA address and fetch its bytes.
  let vaultTransactionBytes: Uint8Array | undefined;
  let squadsPdaFetched = false;
  const vtAddr = extractVaultTransactionAddress(msg);
  if (vtAddr !== null) {
    try {
      const account = await fetcher(vtAddr);
      if (account !== null) {
        vaultTransactionBytes = account.data;
        squadsPdaFetched = true;
      }
      // If null: leave vaultTransactionBytes undefined → existing HOLD path fires.
    } catch {
      // Fetch threw: fail-closed → leave vaultTransactionBytes undefined.
    }
  }

  // Step 4: Token-2022 mint enrichment.
  // Collect mint addresses from TransferChecked (disc=12) instructions on TOKEN_2022.
  // Layout: accounts[0]=source, accounts[1]=mint, accounts[2]=dest, accounts[3]=owner
  const mintExtensions = new Map<
    string,
    {
      permanentDelegate?: string;
      transferHook?: string;
      nonTransferable?: boolean;
    }
  >(ctx.mintExtensions ?? []);
  const candidateMints = new Set<string>();

  for (const ix of msg.instructions) {
    if (ix.programId !== TOKEN_2022_PID) continue;
    if (ix.data.length < 1) continue;
    const disc = ix.data[0] as number;
    if (disc !== 12) continue; // Only TransferChecked (disc=12)
    // mint is at accountIndexes[1]
    const mintIdx = ix.accountIndexes[1];
    if (mintIdx === undefined) continue;
    const mintRole = enrichedRoles[mintIdx];
    if (mintRole === undefined || !mintRole.addressVerified) continue;
    const mintAddr = mintRole.address;
    if (mintAddr !== undefined) candidateMints.add(mintAddr);
  }

  for (const mintAddr of candidateMints) {
    try {
      const account = await fetcher(mintAddr);
      if (account === null) continue; // not found → skip (fail-closed, no downgrade)
      const exts = decodeMintDangerExtensions(account.data);
      // Only add to map if there is at least one danger extension.
      if (
        exts.permanentDelegate !== undefined ||
        exts.transferHook !== undefined ||
        exts.nonTransferable === true
      ) {
        mintExtensions.set(mintAddr, exts);
      }
    } catch {
      // Decode threw: skip this mint (fail-closed, no downgrade).
      continue;
    }
  }

  // Step 5: Simulation enrichment (optional).
  // When opts.simulate is true, run simulateAssetDiff and attach to ctx.simulation.
  // Fail-closed: any error → ctx.simulation = {ok:false, err} → HOLD in verdict.ts.
  let simulated = false;
  let simulationResult: VerdictContext["simulation"] | undefined;

  if (opts.simulate) {
    simulated = true;
    if (opts.simulateFn === undefined) {
      // simulate was requested but no transport provided → fail-closed.
      simulationResult = {
        ok: false,
        err: "simulate requested but no simulateFn transport provided",
        signerSolDelta: 0n,
        tokenDeltas: [],
        outflowsToNonSigner: [],
      };
    } else {
      try {
        const signerPubkeys = enrichedRoles
          .filter(
            (r) => r.role === "signer-writable" || r.role === "signer-readonly",
          )
          .filter((r) => r.addressVerified)
          .map((r) => r.address);

        const simDiff = await simulateAssetDiff(
          b64,
          signerPubkeys,
          opts.simulateFn,
          fetcher,
          resolvedAltTables.size > 0 ? resolvedAltTables : undefined,
        );
        simulationResult = simDiff;
      } catch (err) {
        // Fail-closed: any uncaught error → simulation-failed HOLD.
        simulationResult = {
          ok: false,
          err: err instanceof Error ? err.message : String(err),
          signerSolDelta: 0n,
          tokenDeltas: [],
          outflowsToNonSigner: [],
        };
      }
    }
  }

  // Step 6: Assemble enriched context and call the offline verdict.
  const mergedSimulation = mergeSimulation(ctx.simulation, simulationResult);
  const enrichedCtx: VerdictContext = {
    ...ctx,
    ...(resolvedAltTables.size > 0 ? { resolvedAltTables } : {}),
    ...(mintExtensions.size > 0 ? { mintExtensions } : {}),
    ...(mergedSimulation !== undefined ? { simulation: mergedSimulation } : {}),
  };

  const verdict = reviewBase64(b64, enrichedCtx, vaultTransactionBytes);

  // Step 7: Attach enrichment provenance (host-layer only, never from pure core).
  // This is the ONLY place verdict.enrichment is populated.
  const rpcUrl = opts.rpcUrl ?? "unknown";

  verdict.enrichment = {
    rpcUrl,
    resolvedAltTables: resolvedAltTablesFetched,
    squadsPdaFetched,
    mintsScreened: candidateMints.size,
    simulated,
    trustNote:
      "Facts marked enriched were trusted from the RPC endpoint; a compromised RPC can affect this verdict. " +
      "The --digest short code covers message bytes only, NOT enrichment or simulation data.",
  };

  return verdict;
}
