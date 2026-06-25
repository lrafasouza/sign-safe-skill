/**
 * simulate.ts -- HOST LAYER: simulate a transaction and compute signer asset diffs.
 *
 * ============================ HARD BOUNDARY ============================
 * This file is a HOST LAYER module. It NEVER appears in the deterministic core
 * import graph. Tests import it ONLY with injected/frozen transports (no real
 * network calls). The core (verdict.ts) consumes only the plain SimDiff data
 * object placed in VerdictContext.simulation — the core never imports this file.
 * ======================================================================
 *
 * The single exported function `simulateAssetDiff` computes what the transaction
 * actually does to the SIGNER's balances, via an injectable SimulateFn transport.
 *
 * Flow:
 *   1. Call simulateFn(b64, addresses) with every static transaction account.
 *   2. Parse real CPI transfers from innerInstructions.
 *   3. Diff native pre/post balances and token balances by accountIndex.
 *   4. When a provider omits those arrays, decode returned token-account states
 *      and compare them with the injected pre-state AccountFetcher.
 *   5. Identify signer outflows and swap outputs owned by non-signers.
 *   6. Return a SimDiff plain object that verdict.ts folds into findings.
 *
 * Fail-closed: any error → SimDiff { ok: false, err, signerSolDelta: 0n, ... }.
 */

import type { AccountFetcher } from "./enrich.ts";
import { decodeInput } from "./decode.ts";

// ─────────────────────────────────────────────────────────────────────────────
// Public types
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Raw simulation result returned by SimulateFn.
 * Mirrors the relevant `simulateTransaction` JSON-RPC value fields.
 */
export interface SimulateResult {
  /** RPC-level simulation error string, or null on success. */
  err: string | null;
  logs: string[];
  /** Post-simulation account states, in the same order as the `addresses` array. */
  accounts: (null | {
    lamports: bigint;
    data: Buffer;
    owner: string;
    parsedToken?: {
      mint: string;
      owner: string;
      amount: bigint;
    };
  })[];
  innerInstructions?: {
    index: number;
    instructions: {
      program?: string;
      programId?: string;
      parsed?: {
        type: string;
        info: Record<string, unknown>;
      };
    }[];
  }[];
  preBalances?: bigint[];
  postBalances?: bigint[];
  preTokenBalances?: TokenBalance[];
  postTokenBalances?: TokenBalance[];
}

export interface TokenBalance {
  accountIndex: number;
  mint: string;
  owner?: string;
  uiTokenAmount: {
    amount: string;
  };
}

/**
 * Injectable simulation transport. Takes the base64 tx and the list of
 * addresses whose post-simulation balances are needed. Returns SimulateResult.
 * Production: makeRpcSimulator(rpcUrl). Tests: frozen stub.
 */
export type SimulateFn = (
  b64: string,
  addresses: string[],
) => Promise<SimulateResult>;

/** Net balance delta for a single token account observed in simulation. */
export interface TokenDelta {
  /** Base58 address of the token account. */
  account: string;
  /** Base58 mint address, if known from the token account data. */
  mint?: string;
  /** Base58 owner pubkey, if known from the token account data. */
  owner?: string;
  /** Post-sim balance minus pre-sim balance (in raw base units). Negative = loss. */
  delta: bigint;
}

/** An outflow observed during simulation (SOL or token) going to a non-signer. */
export interface SimOutflow {
  /** Base58 recipient address. */
  to: string;
  /** Amount gained by the recipient (in lamports for SOL, or base units for tokens). */
  amount: bigint;
  /** "sol" or "token". */
  kind: "sol" | "token";
}

/**
 * Result of simulateAssetDiff. Placed in VerdictContext.simulation by the host
 * and consumed (pure, offline) by verdict.ts to generate findings.
 */
export interface SimDiff {
  /** True when the simulation completed without error. */
  ok: boolean;
  /** Set when ok=false. */
  err?: string;
  /** Net SOL lamport change for the signer (sum across all signer keys). Negative = loss. */
  signerSolDelta: bigint;
  /** Per-token-account balance deltas observed in the simulation. */
  tokenDeltas: TokenDelta[];
  /**
   * SOL or token outflows that go to non-signer addresses. These are the amounts
   * that LEFT the signer's sphere of control during the simulation.
   */
  outflowsToNonSigner: SimOutflow[];
}

// ─────────────────────────────────────────────────────────────────────────────
// Token account layout constants (SPL Token / Token-2022)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * SPL Token account data layout (165 bytes):
 *   [0..32)  mint pubkey
 *   [32..64) owner pubkey
 *   [64..72) amount u64-LE
 *   ... (state, delegate info etc — we only read mint/owner/amount)
 *
 * Token-2022 base account data is the same 165-byte prefix; extensions follow.
 * We read only the first 72 bytes so this works for both program token accounts.
 */
const TOKEN_ACCOUNT_MIN_LEN = 72;

/** Read a u64 little-endian from a Buffer at the given offset. */
function readU64LEBuf(buf: Buffer, offset: number): bigint {
  let v = 0n;
  for (let i = 7; i >= 0; i--) {
    v = (v << 8n) | BigInt(buf[offset + i] ?? 0);
  }
  return v;
}

/** Decode mint/owner/amount from a raw SPL token account data buffer. */
function decodeTokenAccountData(
  data: Buffer,
): { mint: string; owner: string; amount: bigint } | null {
  if (data.length < TOKEN_ACCOUNT_MIN_LEN) return null;
  try {
    // Base58 encode the 32-byte slices using the same simple encoder.
    const mint = base58Encode(data.subarray(0, 32));
    const owner = base58Encode(data.subarray(32, 64));
    const amount = readU64LEBuf(data, 64);
    return { mint, owner, amount };
  } catch {
    return null;
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Base58 encoder (same alphabet as the core; duplicated to keep simulate.ts
// standalone within the host layer without importing from the core).
// ─────────────────────────────────────────────────────────────────────────────

const BASE58_ALPHABET =
  "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

function base58Encode(bytes: Uint8Array | Buffer): string {
  const buf = Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes);
  let leadingZeros = 0;
  for (let i = 0; i < buf.length && buf[i] === 0; i++) leadingZeros++;

  const digits = [0];
  for (let i = 0; i < buf.length; i++) {
    let carry = buf[i] as number;
    for (let j = 0; j < digits.length; j++) {
      carry += (digits[j] as number) * 256;
      digits[j] = carry % 58;
      carry = Math.floor(carry / 58);
    }
    while (carry > 0) {
      digits.push(carry % 58);
      carry = Math.floor(carry / 58);
    }
  }

  return (
    "1".repeat(leadingZeros) +
    digits
      .reverse()
      .map((d) => BASE58_ALPHABET[d])
      .join("")
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Main export
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Compute what the transaction actually does to the SIGNER's SOL and token balances.
 *
 * @param b64              Base64-encoded Solana message (or signed transaction).
 * @param signerPubkeys    Base58 addresses of the transaction's signers.
 * @param simulateFn       Injectable SimulateFn transport (frozen in tests, real in production).
 * @param getAccounts      Injectable AccountFetcher for pre-simulation balance reads.
 * @returns                SimDiff — ok=false with err on any error (fail-closed).
 */
export async function simulateAssetDiff(
  b64: string,
  signerPubkeys: string[],
  simulateFn: SimulateFn,
  getAccounts: AccountFetcher,
): Promise<SimDiff> {
  const failClosed = (err: unknown): SimDiff => ({
    ok: false,
    err: err instanceof Error ? err.message : String(err),
    signerSolDelta: 0n,
    tokenDeltas: [],
    outflowsToNonSigner: [],
  });

  try {
    if (signerPubkeys.length === 0) {
      return {
        ok: true,
        signerSolDelta: 0n,
        tokenDeltas: [],
        outflowsToNonSigner: [],
      };
    }

    const signerSet = new Set(signerPubkeys);
    const accountKeys = decodeInput(b64).message.staticAccountKeys;
    const simResult = await simulateFn(b64, accountKeys);

    if (simResult.err !== null) {
      return {
        ok: false,
        err: `simulateTransaction failed: ${simResult.err}`,
        signerSolDelta: 0n,
        tokenDeltas: [],
        outflowsToNonSigner: [],
      };
    }

    let signerSolDelta = 0n;
    if (
      simResult.preBalances !== undefined &&
      simResult.postBalances !== undefined
    ) {
      for (let i = 0; i < accountKeys.length; i++) {
        if (!signerSet.has(accountKeys[i]!)) continue;
        signerSolDelta +=
          (simResult.postBalances[i] ?? 0n) - (simResult.preBalances[i] ?? 0n);
      }
    }

    const outflowsToNonSigner: SimOutflow[] = [];
    const tokenDeltas: TokenDelta[] = [];
    const preTokenBalances = new Map(
      (simResult.preTokenBalances ?? []).map((balance) => [
        balance.accountIndex,
        balance,
      ]),
    );
    const postTokenBalances = new Map(
      (simResult.postTokenBalances ?? []).map((balance) => [
        balance.accountIndex,
        balance,
      ]),
    );
    const tokenIndexes = new Set([
      ...preTokenBalances.keys(),
      ...postTokenBalances.keys(),
    ]);

    for (const accountIndex of tokenIndexes) {
      const pre = preTokenBalances.get(accountIndex);
      const post = postTokenBalances.get(accountIndex);
      const delta =
        BigInt(post?.uiTokenAmount.amount ?? "0") -
        BigInt(pre?.uiTokenAmount.amount ?? "0");
      if (delta !== 0n) {
        const balance = post ?? pre;
        const tokenDelta: TokenDelta = {
          account: accountKeys[accountIndex] ?? `account-index:${accountIndex}`,
          delta,
        };
        if (balance?.mint !== undefined) tokenDelta.mint = balance.mint;
        if (balance?.owner !== undefined) tokenDelta.owner = balance.owner;
        tokenDeltas.push(tokenDelta);
      }
    }

    if (tokenIndexes.size === 0 && simResult.accounts.length > 0) {
      for (
        let accountIndex = 0;
        accountIndex < accountKeys.length;
        accountIndex++
      ) {
        const postAccount = simResult.accounts[accountIndex];
        if (postAccount === null || postAccount === undefined) continue;
        const post =
          postAccount.parsedToken ?? decodeTokenAccountData(postAccount.data);
        if (post === null) continue;
        const preAccount = await getAccounts(accountKeys[accountIndex]!);
        const pre =
          preAccount === null
            ? null
            : decodeTokenAccountData(Buffer.from(preAccount.data));
        const delta = post.amount - (pre?.amount ?? 0n);
        if (delta !== 0n) {
          tokenDeltas.push({
            account: accountKeys[accountIndex]!,
            mint: post.mint,
            owner: post.owner,
            delta,
          });
        }
      }
    }

    const tokenByAddress = new Map<string, TokenBalance>();
    for (const [accountIndex, balance] of [
      ...preTokenBalances,
      ...postTokenBalances,
    ]) {
      const address = accountKeys[accountIndex];
      if (address !== undefined) tokenByAddress.set(address, balance);
    }
    const tokenDeltaByAddress = new Map(
      tokenDeltas.map((delta) => [delta.account, delta]),
    );
    const outflowKeys = new Set<string>();

    if ((simResult.innerInstructions?.length ?? 0) === 0) {
      for (const destination of tokenDeltas) {
        if (
          destination.delta <= 0n ||
          destination.owner === undefined ||
          signerSet.has(destination.owner) ||
          destination.mint === undefined
        )
          continue;
        const nonSignerSource = tokenDeltas.some(
          (source) =>
            source.delta < 0n &&
            source.mint === destination.mint &&
            source.owner !== undefined &&
            !signerSet.has(source.owner),
        );
        if (nonSignerSource) {
          const key = `token:${destination.account}:${destination.delta}`;
          outflowKeys.add(key);
          outflowsToNonSigner.push({
            to: destination.account,
            amount: destination.delta,
            kind: "token",
          });
        }
      }
    }

    const hasPoolTokenOutput = (simResult.innerInstructions ?? []).some(
      (group) =>
        group.instructions.some((instruction) => {
          const info = instruction.parsed?.info;
          if (
            info === undefined ||
            (instruction.program !== "spl-token" &&
              instruction.program !== "spl-token-2022")
          )
            return false;
          const source =
            typeof info["source"] === "string" ? info["source"] : undefined;
          const sourceOwner =
            source === undefined
              ? undefined
              : tokenByAddress.get(source)?.owner;
          return sourceOwner !== undefined && !signerSet.has(sourceOwner);
        }),
    );

    for (const group of simResult.innerInstructions ?? []) {
      for (const instruction of group.instructions) {
        const parsed = instruction.parsed;
        if (parsed === undefined) continue;
        const info = parsed.info;

        if (instruction.program === "system" && parsed.type === "transfer") {
          const source =
            typeof info["source"] === "string" ? info["source"] : undefined;
          const destination =
            typeof info["destination"] === "string"
              ? info["destination"]
              : undefined;
          const lamports =
            typeof info["lamports"] === "number" ||
            typeof info["lamports"] === "string"
              ? BigInt(info["lamports"])
              : 0n;
          if (
            source !== undefined &&
            destination !== undefined &&
            signerSet.has(source) &&
            !signerSet.has(destination) &&
            lamports > 0n
          ) {
            const key = `sol:${destination}:${lamports}`;
            if (!outflowKeys.has(key)) {
              outflowKeys.add(key);
              outflowsToNonSigner.push({
                to: destination,
                amount: lamports,
                kind: "sol",
              });
            }
          }
          continue;
        }

        if (
          (instruction.program === "spl-token" ||
            instruction.program === "spl-token-2022") &&
          (parsed.type === "transfer" || parsed.type === "transferChecked")
        ) {
          const source =
            typeof info["source"] === "string" ? info["source"] : undefined;
          const destination =
            typeof info["destination"] === "string"
              ? info["destination"]
              : undefined;
          if (source === undefined || destination === undefined) continue;
          const sourceOwner = tokenByAddress.get(source)?.owner;
          const destinationOwner = tokenByAddress.get(destination)?.owner;
          const destinationDelta =
            tokenDeltaByAddress.get(destination)?.delta ?? 0n;
          const tokenAmount =
            typeof info["tokenAmount"] === "object" &&
            info["tokenAmount"] !== null
              ? (info["tokenAmount"] as Record<string, unknown>)["amount"]
              : undefined;
          const amountValue = info["amount"] ?? tokenAmount;
          const amount =
            typeof amountValue === "number" || typeof amountValue === "string"
              ? BigInt(amountValue)
              : destinationDelta;
          if (
            sourceOwner !== undefined &&
            destinationOwner !== undefined &&
            signerSet.has(sourceOwner) &&
            !signerSet.has(destinationOwner) &&
            !hasPoolTokenOutput &&
            destinationDelta > 0n &&
            amount > 0n
          ) {
            const key = `token:${destination}:${amount}`;
            if (!outflowKeys.has(key)) {
              outflowKeys.add(key);
              outflowsToNonSigner.push({
                to: destination,
                amount,
                kind: "token",
              });
            }
          }
          if (
            sourceOwner !== undefined &&
            destinationOwner !== undefined &&
            !signerSet.has(sourceOwner) &&
            !signerSet.has(destinationOwner) &&
            destinationDelta > 0n &&
            amount > 0n
          ) {
            const key = `token:${destination}:${amount}`;
            if (!outflowKeys.has(key)) {
              outflowKeys.add(key);
              outflowsToNonSigner.push({
                to: destination,
                amount,
                kind: "token",
              });
            }
          }
        }
      }
    }

    return {
      ok: true,
      signerSolDelta,
      tokenDeltas,
      outflowsToNonSigner,
    };
  } catch (err) {
    return failClosed(err);
  }
}
