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
 * INJECTABLE FETCH WRAPPERS: Every function that touches the network accepts
 * a fetcher callback. enrich.ts owns no global RPC URL and no global fetch
 * state. The host (CLI, agent, or test harness) supplies the transport.
 * This keeps each function fully mockable: unit-test by injecting a stub
 * that returns frozen bytes; deploy by injecting a real RPC call.
 *
 * /sign-review FLOW (Squads vaultTransactionExecute):
 *   1. Run reviewBase64(b64, ctx) offline. If verdict is HOLD because a
 *      Squads vaultTransactionExecute was detected but no inner bytes were
 *      supplied, the finding id is "squads-execute-unverified".
 *   2. Extract the VaultTransaction PDA address from the top-level message
 *      (it is the second account of the vaultTransactionExecute instruction).
 *   3. Call enrichSquads(vtAddress, getAccountInfo) to fetch the raw account
 *      bytes.
 *   4. Re-run reviewBase64(b64, ctx, vtBytes) offline with the fetched bytes.
 *      This produces a *new, still-offline* verdict over fully-known data,
 *      surfacing inner instructions (e.g. "Drift UpdateAdmin [inner, via
 *      Squads vault]" if the inner bytes contain that discriminator).
 *   5. Show the second verdict to the signer: they now see the clear-signed
 *      inner intent, not just the Squads shell.
 *
 * Enrichment never upgrades a verdict in place. It only produces better INPUT
 * for another deterministic offline pass.
 */

import type { AddressTableLookup, Verdict } from "./types.ts";

// ---------------------------------------------------------------------------
// Shared fetcher callback types
// ---------------------------------------------------------------------------

/**
 * Injectable account fetcher: given a base58 public key, returns the raw
 * account data bytes, or null if the account does not exist. The host is
 * responsible for supplying an implementation (RPC, MCP, cache, etc.).
 */
export type AccountFetcher = (pubkey: string) => Promise<{ data: Uint8Array } | null>;

// ---------------------------------------------------------------------------
// ALT resolution
// ---------------------------------------------------------------------------

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
 * @param lookup  The ALT entry from a DecodedMessage.addressTableLookups.
 * @param getAccountInfo  Injectable fetcher callback (see AccountFetcher).
 *
 * Usage with a real RPC:
 *   const rpc = createSolanaRpc("https://api.mainnet-beta.solana.com");
 *   const fetcher: AccountFetcher = async (pk) => {
 *     const res = await rpc.getAccountInfo(pk, { encoding: "base64" }).send();
 *     if (!res.value) return null;
 *     const raw = Buffer.from(res.value.data[0], "base64");
 *     return { data: new Uint8Array(raw) };
 *   };
 *   const resolved = await enrichAlt(lookup, fetcher);
 *
 * TODO: Decode the ALT account format (first 4 bytes are a type tag, followed
 * by last_extended_slot(8) + last_extended_slot_start_index(1) + authority
 * Option<Pubkey> + deactivation_slot(8), then the addresses Vec starting at
 * offset 56). The @solana-program/address-lookup-table Codama-generated client
 * is the canonical decoder; alternatively decode manually (each entry is 32
 * raw bytes, no prefix after the header).
 */
export async function enrichAlt(
  lookup: AddressTableLookup,
  getAccountInfo: AccountFetcher,
): Promise<AltResolution> {
  const account = await getAccountInfo(lookup.accountKey);
  if (account === null) {
    throw new Error(`enrichAlt: account ${lookup.accountKey} not found`);
  }
  // TODO: decode ALT account format and resolve writable/readonly indexes.
  // Until implemented, throw to prevent silent empty resolution.
  void account; // consumed above; silence unused-var lint
  throw new Error(
    "enrichAlt: ALT account decoding not yet implemented. Supply a decoded ALT resolver or use the @solana-program/address-lookup-table client.",
  );
}

// ---------------------------------------------------------------------------
// Squads VaultTransaction enrichment
// ---------------------------------------------------------------------------

/**
 * Fetch the raw bytes of a Squads v4 VaultTransaction PDA account.
 *
 * Call this when reviewBase64 returns a HOLD verdict with finding
 * "squads-execute-unverified". Pass the returned bytes as the third argument
 * to a second call to reviewBase64 to get the inner-decoded verdict.
 *
 * @param vtAddress   Base58 address of the VaultTransaction PDA.
 * @param getAccountInfo  Injectable fetcher callback (see AccountFetcher).
 * @returns Raw account data bytes, or null if the account was not found.
 *
 * Usage example:
 *   // 1. First pass: offline, no PDA bytes
 *   const verdict1 = reviewBase64(b64, ctx);
 *   // verdict1 might be HOLD with "squads-execute-unverified"
 *
 *   // 2. Fetch the VaultTransaction PDA
 *   const vtAddress = extractVaultTransactionAddress(msg); // from top-level ix accounts
 *   const vtBytes = await enrichSquads(vtAddress, myFetcher);
 *
 *   // 3. Second pass: offline, now with inner bytes -> clear-signed inner intent
 *   const verdict2 = reviewBase64(b64, ctx, vtBytes ?? undefined);
 *   // verdict2 now shows inner instructions (e.g. Drift UpdateAdmin)
 *
 * Note on PDA address extraction: the VaultTransaction PDA address is the
 * second account (index 1) in the vaultTransactionExecute instruction's
 * account list. The signed message's staticAccountKeys array at that index
 * gives you the address to fetch.
 */
export async function enrichSquads(
  vtAddress: string,
  getAccountInfo: AccountFetcher,
): Promise<Uint8Array | null> {
  const account = await getAccountInfo(vtAddress);
  if (account === null) return null;
  return account.data;
}

// ---------------------------------------------------------------------------
// Nonce account recon (durable-nonce detection)
// ---------------------------------------------------------------------------

export interface NonceAccountInfo {
  /** Base58 address of the nonce account. */
  address: string;
  /** Base58 authority (who can advance/withdraw the nonce). */
  authority: string;
  /** Current nonce value (base58). */
  nonce: string;
  /**
   * True if the authority is one of the signer keys in the transaction being
   * reviewed. When true, this nonce account is controlled by a signer and
   * lends non-expiry to any transaction using it.
   */
  signerControlled: boolean;
}

/**
 * Check whether a set of nonce accounts are controlled by the transaction
 * signers (durable-nonce recon).
 *
 * For each nonce account address, fetches the on-chain account and decodes the
 * authority. If the authority is in `signerPubkeys`, that nonce is flagged as
 * signer-controlled -- meaning the signers themselves can replay the
 * transaction at any future time.
 *
 * This enriches the offline durable-nonce HOLD finding: the offline core flags
 * AdvanceNonceAccount at ix0 as HOLD (or REJECT in governanceContext). This
 * function adds the concrete "authority is signer X" attribution that a
 * human needs to understand the non-expiry risk.
 *
 * @param nonceAddresses  Base58 addresses of nonce accounts found in the tx
 *                        (the account passed to AdvanceNonceAccount).
 * @param signerPubkeys   Base58 addresses of the transaction signers.
 * @param getAccountInfo  Injectable fetcher callback.
 *
 * TODO: decode the SystemProgram nonce account data format:
 *   [0..4)  version u32-LE (must be 1)
 *   [4..8)  state u32-LE (0=Uninitialized, 1=Initialized)
 *   [8..40) authority Pubkey (32 bytes)
 *   [40..72) blockhash Pubkey (32 bytes, the current nonce value)
 *   [72..80) lamports_per_signature u64-LE
 * Total: 80 bytes.
 */
export async function reconNonceAccounts(
  nonceAddresses: string[],
  signerPubkeys: string[],
  getAccountInfo: AccountFetcher,
): Promise<NonceAccountInfo[]> {
  const signerSet = new Set(signerPubkeys);
  const results: NonceAccountInfo[] = [];

  for (const addr of nonceAddresses) {
    const account = await getAccountInfo(addr);
    if (account === null) continue;

    const data = account.data;
    // SystemProgram nonce account: 80 bytes.
    // Layout: version(4) + state(4) + authority(32) + nonce(32) + lamportsPerSig(8)
    if (data.length < 80) continue;

    const stateU32 =
      (data[4]! | (data[5]! << 8) | (data[6]! << 16) | (data[7]! << 24)) >>> 0;
    if (stateU32 !== 1) continue; // Only Initialized nonces are useful

    // Import base58Encode from decode.ts would pull in a core module, but
    // enrich.ts is explicitly allowed to import from the core (it just cannot
    // go the other direction). However, to keep enrich.ts's dependency surface
    // minimal, we provide a small inline base58 encoder here rather than
    // importing decode.ts. This avoids any risk of accidental circular imports.
    const authorityBytes = data.subarray(8, 40);
    const nonceBytes = data.subarray(40, 72);

    const authority = base58EncodeInline(authorityBytes);
    const nonce = base58EncodeInline(nonceBytes);

    results.push({
      address: addr,
      authority,
      nonce,
      signerControlled: signerSet.has(authority),
    });
  }

  return results;
}

// ---------------------------------------------------------------------------
// Mint extension confirmation
// ---------------------------------------------------------------------------

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
 * @param mint            Base58 mint address.
 * @param getAccountInfo  Injectable fetcher callback.
 *
 * TODO: decode the Token-2022 mint account extension TLV:
 *   After the standard 82-byte SPL Mint layout, Token-2022 mints carry an
 *   "account type" byte and then a TLV (type-length-value) extension section.
 *   Type 3 = PermanentDelegate (32 bytes, the delegate pubkey).
 *   Type 4 = TransferHook (32+32 bytes, program id + extra account meta list).
 *   The @solana-program/token-2022 Codama-generated client decodes these; or
 *   use the Helius asset/account MCP tool as an equivalent transport.
 */
export async function confirmMintExtensions(
  mint: string,
  getAccountInfo: AccountFetcher,
): Promise<MintExtensionInfo> {
  const account = await getAccountInfo(mint);
  if (account === null) {
    throw new Error(`confirmMintExtensions: mint account ${mint} not found`);
  }
  // TODO: decode Token-2022 extension TLV.
  void account; // consumed above
  throw new Error(
    "confirmMintExtensions: Token-2022 extension decoding not yet implemented. Use the @solana-program/token-2022 client.",
  );
}

// ---------------------------------------------------------------------------
// Verdict annotation (presentational, no verdict mutation)
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Inline base58 encoder (avoids importing decode.ts here)
// ---------------------------------------------------------------------------

const B58_ALPHA = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

function base58EncodeInline(bytes: Uint8Array): string {
  if (bytes.length === 0) return "";
  let zeros = 0;
  while (zeros < bytes.length && bytes[zeros] === 0) zeros++;
  const digits: number[] = [];
  for (let i = zeros; i < bytes.length; i++) {
    let carry = bytes[i] as number;
    for (let j = 0; j < digits.length; j++) {
      carry += (digits[j] as number) << 8;
      digits[j] = carry % 58;
      carry = (carry / 58) | 0;
    }
    while (carry > 0) {
      digits.push(carry % 58);
      carry = (carry / 58) | 0;
    }
  }
  let out = "1".repeat(zeros);
  for (let i = digits.length - 1; i >= 0; i--) {
    out += B58_ALPHA[digits[i] as number];
  }
  return out;
}
