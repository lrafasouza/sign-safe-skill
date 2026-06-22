/**
 * enrich.ts -- OPTIONAL, IMPURE runtime annotators. DO NOT IMPORT FROM CORE.
 *
 * ============================ HARD BOUNDARY ============================
 * Nothing in src/decode|roles|classify|outflow|verdict.ts and nothing in
 * skill/test/** may import this file. The deterministic core and its tests
 * must run fully offline. This module is a documented *runtime enhancement*
 * only: a host application (or an MCP-enabled agent) may call these to turn
 * "unverified" ALT references and PDA placeholders into concrete, confirmed
 * facts -- but the verdict gate never depends on them.
 * ======================================================================
 *
 * Each function below is a STUB with a clear interface and a TODO. Wiring them
 * up requires network/RPC access (or MCP tools such as the Helius account/chain
 * tools, or a Squads SDK), which is intentionally out of scope for the core.
 *
 * Intended use: run the offline core first to get a Verdict. If the verdict is
 * HOLD purely because of unresolved ALTs, an operator MAY run enrichAlt() to
 * resolve the table and re-run the core with the resolved keys spliced in as
 * static keys -- producing a *new, still-offline* verdict over fully-known
 * data. Enrichment never upgrades a verdict in place; it only produces better
 * input for another deterministic pass.
 */

import type { AddressTableLookup, Verdict } from "./types.ts";

export interface AltResolution {
  table: string;
  /** Resolved base58 addresses for the writable indexes, in order. */
  writable: string[];
  /** Resolved base58 addresses for the readonly indexes, in order. */
  readonly: string[];
}

/**
 * Resolve an Address Lookup Table's referenced indexes to concrete addresses.
 * IMPURE: requires an RPC getAccountInfo on the table account.
 *
 * TODO: implement on the modern @solana/kit stack -- fetch the table account
 * with a kit RPC (`createSolanaRpc(url).getAccountInfo(table, { encoding:
 * "base64" })`), decode its address list with the
 * @solana-program/address-lookup-table client (Codama-generated), and map the
 * lookup indexes to the resolved addresses. (A Helius heliusChain.getAccountInfo
 * MCP call is an equivalent transport.)
 */
export async function enrichAlt(
  _lookup: AddressTableLookup,
  _rpcUrl: string,
): Promise<AltResolution> {
  throw new Error(
    "enrichAlt is a runtime-only stub; wire it to an RPC/MCP before use. See enrich.ts docs.",
  );
}

export interface SquadsContext {
  multisig: string;
  threshold: number;
  members: string[];
  /** True if the reviewed message matches a known pending Squads proposal. */
  matchesPendingProposal: boolean;
}

/**
 * Fetch Squads multisig context for a proposal-style transaction.
 * IMPURE: requires reading the Squads PDA(s) over RPC.
 *
 * TODO: implement via the Squads SDK, or a kit RPC getAccountInfo plus the
 * Codama-generated Squads client to decode the multisig/proposal PDAs.
 */
export async function enrichSquads(
  _multisigPda: string,
  _rpcUrl: string,
): Promise<SquadsContext> {
  throw new Error(
    "enrichSquads is a runtime-only stub; wire it to the Squads SDK before use.",
  );
}

export interface MintExtensionInfo {
  mint: string;
  isToken2022: boolean;
  hasPermanentDelegate: boolean;
  hasTransferHook: boolean;
  permanentDelegate?: string;
}

/**
 * Confirm Token-2022 mint extensions live on-chain (e.g. whether a permanent
 * delegate is actually configured for a mint touched by the transaction).
 * IMPURE: requires getAccountInfo on the mint and extension parsing.
 *
 * TODO: implement on the modern @solana/kit stack via the
 * @solana-program/token-2022 client (Codama-generated): fetch the mint with a
 * kit RPC and decode its extension TLV (e.g. PermanentDelegate, TransferHook),
 * or use the Helius asset/account MCP tools as an equivalent transport.
 */
export async function confirmMintExtensions(
  _mint: string,
  _rpcUrl: string,
): Promise<MintExtensionInfo> {
  throw new Error(
    "confirmMintExtensions is a runtime-only stub; wire it to an RPC/MCP before use.",
  );
}

/**
 * Pretty-print enrichment annotations alongside an existing offline verdict,
 * WITHOUT mutating the verdict. Purely presentational; provided so hosts have
 * a consistent place to attach runtime context.
 */
export function annotateVerdict(
  verdict: Verdict,
  annotations: Record<string, unknown>,
): { verdict: Verdict; annotations: Record<string, unknown> } {
  return { verdict, annotations };
}
