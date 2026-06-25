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
 *   makeRpcAccountFetcher(rpcUrl, fetchImpl?, opts?) -> AccountFetcher
 *   makeRpcSimulator(rpcUrl, fetchImpl?, opts?)      -> SimulateFn
 *
 * The AccountFetcher posts a `getAccountInfo` JSON-RPC call to `rpcUrl`,
 * decodes the base64 data field, and returns `{ data: Uint8Array }` or null when
 * the account is not found.
 *
 * The SimulateFn posts a `simulateTransaction` JSON-RPC call and returns the
 * raw simulation result (accounts + logs + err) for simulateAssetDiff() to
 * interpret.
 *
 * Any HTTP error or RPC error object throws (the caller is responsible for
 * fail-closed handling).
 */

import type { AccountFetcher } from "./enrich.ts";
import type { SimulateFn, SimulateResult } from "./simulate.ts";

/** Options accepted by both makeRpcAccountFetcher and makeRpcSimulator. */
export interface RpcOpts {
  /**
   * AbortController timeout in milliseconds. Defaults to 10000 (10 s).
   * On timeout, the fetch is aborted and a clear error is thrown (callers
   * are already fail-closed: timeout → HOLD/REJECT, never silent SIGN).
   */
  timeoutMs?: number;
}

/** Validate that rpcUrl uses the http: or https: scheme. */
function validateRpcUrl(rpcUrl: string): void {
  let parsed: URL;
  try {
    parsed = new URL(rpcUrl);
  } catch {
    throw new Error(
      `Invalid RPC URL "${rpcUrl}": cannot be parsed as a URL. Must start with http:// or https://.`,
    );
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new Error(
      `Invalid RPC URL "${rpcUrl}": scheme must be http: or https: (got ${parsed.protocol}). ` +
        `Only HTTP(S) endpoints are supported.`,
    );
  }
}

let requestIdCounter = 0;

/**
 * Create an injectable `AccountFetcher` backed by a JSON-RPC `getAccountInfo`
 * call to `rpcUrl`.
 *
 * @param rpcUrl      The Solana JSON-RPC endpoint URL. Must use http: or https: scheme.
 * @param fetchImpl   Injectable fetch implementation (defaults to globalThis.fetch).
 *                    Pass a stub in tests to avoid real network calls.
 * @param opts        Optional: timeoutMs (default 10000). On timeout, the request
 *                    is aborted and a clear error is thrown (callers fail-closed).
 * @returns           An AccountFetcher that resolves to `{ data: Uint8Array }` on
 *                    success, `null` when the account does not exist, and throws on
 *                    any HTTP or RPC-level error. The caller must handle throws with
 *                    fail-closed logic (never silently SIGN on a fetch failure).
 */
export function makeRpcAccountFetcher(
  rpcUrl: string,
  fetchImpl: typeof fetch = globalThis.fetch,
  opts: RpcOpts = {},
): AccountFetcher {
  validateRpcUrl(rpcUrl);
  const timeoutMs = opts.timeoutMs ?? 10000;

  return async function rpcAccountFetcher(
    pubkey: string,
  ): Promise<{ data: Uint8Array } | null> {
    const id = ++requestIdCounter;
    const body = JSON.stringify({
      jsonrpc: "2.0",
      id,
      method: "getAccountInfo",
      params: [pubkey, { encoding: "base64" }],
    });

    const controller = new AbortController();

    // Race the fetch against a timeout. We use Promise.race so that a stub
    // fetchImpl that doesn't natively respect the AbortSignal (as in tests)
    // is still correctly cancelled by the timeout on the calling side.
    const timeoutPromise = new Promise<never>((_resolve, reject) =>
      setTimeout(
        () =>
          reject(
            new Error(
              `RPC timeout after ${timeoutMs}ms for getAccountInfo(${pubkey}): ` +
                `request was aborted. The caller is fail-closed (HOLD/REJECT) on timeout.`,
            ),
          ),
        timeoutMs,
      ),
    );

    let response: Response;
    try {
      response = await Promise.race([
        fetchImpl(rpcUrl, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body,
          signal: controller.signal,
        }),
        timeoutPromise,
      ]);
    } catch (err) {
      controller.abort(); // cancel the in-flight fetch if timeout fired
      throw err;
    }
    controller.abort(); // cancel if fetch won the race (frees signal listener)

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

/**
 * Create an injectable `SimulateFn` backed by a JSON-RPC `simulateTransaction`
 * call to `rpcUrl`.
 *
 * The returned function sends a simulateTransaction request with:
 *   - sigVerify: false (no need for valid signatures)
 *   - replaceRecentBlockhash: true (avoids blockhash-expired errors)
 *   - encoding: "base64"
 *   - innerInstructions: true
 *   - accounts.encoding: "jsonParsed"
 *   - accounts.addresses: the caller-supplied list of addresses to return
 *
 * This is injectable: pass a frozen stub in tests; production wires to a real
 * JSON-RPC endpoint.
 *
 * @param rpcUrl     The Solana JSON-RPC endpoint URL. Must use http: or https: scheme.
 * @param fetchImpl  Injectable fetch implementation (defaults to globalThis.fetch).
 * @param opts       Optional: timeoutMs (default 10000).
 * @returns          A SimulateFn that takes (b64, addresses) and returns SimulateResult.
 */
export function makeRpcSimulator(
  rpcUrl: string,
  fetchImpl: typeof fetch = globalThis.fetch,
  opts: RpcOpts = {},
): SimulateFn {
  validateRpcUrl(rpcUrl);
  const timeoutMs = opts.timeoutMs ?? 10000;

  return async function rpcSimulateFn(
    b64: string,
    addresses: string[],
  ): Promise<SimulateResult> {
    const id = ++requestIdCounter;
    const body = JSON.stringify({
      jsonrpc: "2.0",
      id,
      method: "simulateTransaction",
      params: [
        b64,
        {
          sigVerify: false,
          replaceRecentBlockhash: true,
          encoding: "base64",
          innerInstructions: true,
          accounts: {
            encoding: "jsonParsed",
            addresses,
          },
        },
      ],
    });

    const controller = new AbortController();

    // Race the fetch against a timeout (same pattern as makeRpcAccountFetcher).
    const timeoutPromise = new Promise<never>((_resolve, reject) =>
      setTimeout(
        () =>
          reject(
            new Error(
              `RPC timeout after ${timeoutMs}ms for simulateTransaction: ` +
                `request was aborted. The caller is fail-closed (HOLD) on timeout.`,
            ),
          ),
        timeoutMs,
      ),
    );

    let response: Response;
    try {
      response = await Promise.race([
        fetchImpl(rpcUrl, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body,
          signal: controller.signal,
        }),
        timeoutPromise,
      ]);
    } catch (err) {
      controller.abort();
      throw err;
    }
    controller.abort();

    if (!response.ok) {
      throw new Error(
        `RPC HTTP error for simulateTransaction: ${response.status} ${response.statusText}`,
      );
    }

    const json = (await response.json()) as {
      jsonrpc: string;
      id: number;
      result?: {
        value: {
          err: unknown;
          logs?: string[] | null;
          accounts?:
            | (null | {
                lamports: number;
                data:
                  | [string, string]
                  | {
                      program: string;
                      parsed: {
                        type: string;
                        info: {
                          mint?: string;
                          owner?: string;
                          tokenAmount?: {
                            amount?: string;
                          };
                        };
                      };
                      space: number;
                    };
                owner: string;
              })[]
            | null;
          innerInstructions?: SimulateResult["innerInstructions"] | null;
          preBalances?: number[] | null;
          postBalances?: number[] | null;
          preTokenBalances?: SimulateResult["preTokenBalances"] | null;
          postTokenBalances?: SimulateResult["postTokenBalances"] | null;
        };
      };
      error?: { code: number; message: string };
    };

    if (json.error !== undefined) {
      throw new Error(
        `RPC error for simulateTransaction: code=${json.error.code} ${json.error.message}`,
      );
    }

    const value = json.result?.value;
    if (value === undefined) {
      throw new Error("simulateTransaction RPC response missing result.value");
    }

    return {
      err: value.err !== null ? String(value.err) : null,
      logs: value.logs ?? [],
      accounts: (value.accounts ?? []).map((acc) => {
        if (acc === null) return null;
        if (!Array.isArray(acc.data)) {
          const info = acc.data.parsed.info;
          const mint = info.mint;
          const owner = info.owner;
          const amount = info.tokenAmount?.amount;
          return {
            lamports: BigInt(acc.lamports),
            data: Buffer.alloc(0),
            owner: acc.owner,
            ...(mint !== undefined &&
            owner !== undefined &&
            amount !== undefined
              ? { parsedToken: { mint, owner, amount: BigInt(amount) } }
              : {}),
          };
        }
        return {
          lamports: BigInt(acc.lamports),
          data: Buffer.from(acc.data[0], "base64"),
          owner: acc.owner,
        };
      }),
      innerInstructions: value.innerInstructions ?? [],
      preBalances: (value.preBalances ?? []).map((balance) => BigInt(balance)),
      postBalances: (value.postBalances ?? []).map((balance) =>
        BigInt(balance),
      ),
      preTokenBalances: value.preTokenBalances ?? [],
      postTokenBalances: value.postTokenBalances ?? [],
    };
  };
}
