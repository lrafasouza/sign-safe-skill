/**
 * rpc.ts -- HOST LAYER only. Real fetch may live here. Do NOT import from core.
 *
 * ============================ HARD BOUNDARY ============================
 * This file is a host-layer transport provider. It is the ONLY place in the
 * skill where actual `fetch` calls are made (besides cli.ts for I/O). The
 * deterministic core (decode, roles, classify, outflow, verdict, squads, alt,
 * tlv, digest) must NEVER import this file. All tests use an injected fetchImpl
 * so this module is fully mockable without touching the network.
 * ======================================================================
 *
 * Exports:
 *   makeRpcAccountFetcher(rpcUrl, fetchImpl?) -> AccountFetcher
 *
 * The returned AccountFetcher posts a `getAccountInfo` JSON-RPC call to `rpcUrl`,
 * decodes the base64 data field, and returns `{ data: Uint8Array }` or null when
 * the account is not found. Any HTTP error or RPC error object throws (the caller
 * is responsible for fail-closed handling).
 */

import type { AccountFetcher } from "./enrich.ts";

let requestIdCounter = 0;

/**
 * Create an injectable `AccountFetcher` backed by a JSON-RPC `getAccountInfo`
 * call to `rpcUrl`.
 *
 * @param rpcUrl      The Solana JSON-RPC endpoint URL.
 * @param fetchImpl   Injectable fetch implementation (defaults to globalThis.fetch).
 *                    Pass a stub in tests to avoid real network calls.
 * @returns           An AccountFetcher that resolves to `{ data: Uint8Array }` on
 *                    success, `null` when the account does not exist, and throws on
 *                    any HTTP or RPC-level error. The caller must handle throws with
 *                    fail-closed logic (never silently SIGN on a fetch failure).
 */
export function makeRpcAccountFetcher(
  rpcUrl: string,
  fetchImpl: typeof fetch = globalThis.fetch,
): AccountFetcher {
  return async function rpcAccountFetcher(pubkey: string): Promise<{ data: Uint8Array } | null> {
    const id = ++requestIdCounter;
    const body = JSON.stringify({
      jsonrpc: "2.0",
      id,
      method: "getAccountInfo",
      params: [pubkey, { encoding: "base64" }],
    });

    const response = await fetchImpl(rpcUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body,
    });

    if (!response.ok) {
      throw new Error(
        `RPC HTTP error for getAccountInfo(${pubkey}): ${response.status} ${response.statusText}`,
      );
    }

    // Parse JSON — let parse errors propagate as-is (caller's fail-closed catch).
    const json = (await response.json()) as {
      jsonrpc: string;
      id: number;
      result?: { value: null | { data: [string, string] } };
      error?: { code: number; message: string };
    };

    // RPC-level error object → throw.
    if (json.error !== undefined) {
      throw new Error(
        `RPC error for getAccountInfo(${pubkey}): code=${json.error.code} ${json.error.message}`,
      );
    }

    const value = json.result?.value;
    if (value === null || value === undefined) {
      // Account does not exist.
      return null;
    }

    // Decode the base64-encoded account data. data[0] is the base64 string;
    // data[1] is the encoding tag ("base64"). We requested "base64" so this is
    // always base64-encoded.
    const b64 = value.data[0];
    const raw = Buffer.from(b64, "base64");
    return { data: new Uint8Array(raw) };
  };
}
