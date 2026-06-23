/**
 * reputation.ts -- PURE: address-reputation screening for drainer blocklists.
 *
 * ============================ OFFLINE CORE ============================
 * This module is PURE: no network, no RPC, no import of enrich.ts.
 * Same bytes in => same JSON out, forever.
 *
 * The blocklist is injected by the caller (via VerdictContext.recipientBlocklist
 * or by the host application). The core gate never fetches a blocklist itself.
 *
 * screenRecipients() checks whether any supplied address appears in the provided
 * blocklist set and returns a ScreenHit[] describing each match. An empty blocklist
 * (or no blocklist provided) results in an empty hit list — no-op by default,
 * so the existing verdict behavior is byte-identical when no blocklist is given.
 *
 * Address categories screened (all can move value or authority to an attacker):
 *   - Transfer recipients (SOL lamport transfers)
 *   - SPL transfer destination addresses
 *   - Approve delegates (SetAuthority new authority / Approve delegate)
 *   - SetAuthority new-owner / new-authority values
 * ======================================================================
 */

export type ScreenHitCategory =
  | "recipient"    // SPL or SOL transfer destination
  | "delegate"     // SPL Approve / ApproveChecked delegate
  | "new-authority" // SetAuthority new_authority value
  | "new-owner";   // System Assign / Assign-with-seed new owner

export interface ScreenHit {
  /** Base58 address that matched the blocklist. */
  address: string;
  /** What role this address plays in the transaction. */
  category: ScreenHitCategory;
  /** Instruction index where the address appeared (0-based). */
  instructionIndex: number;
}

/**
 * Screen a list of candidate addresses against a blocklist set.
 *
 * PURE. Deterministic. No network.
 *
 * @param candidates  Array of { address, category, instructionIndex } items
 *                    that are the candidate addresses to screen. null/undefined
 *                    addresses (ALT-unresolved) are skipped silently — they
 *                    cannot be screened offline.
 * @param blocklistSet A Set<string> of known-bad base58 addresses (e.g. from
 *                    Scam Sniffer or a community blocklist). If empty or not
 *                    provided, returns an empty array (no-op).
 * @returns           ScreenHit[] for every candidate address in the blocklist.
 *                    Empty when no match or when blocklistSet is empty.
 */
export function screenAddresses(
  candidates: Array<{
    address: string | null;
    category: ScreenHitCategory;
    instructionIndex: number;
  }>,
  blocklistSet: ReadonlySet<string>,
): ScreenHit[] {
  if (blocklistSet.size === 0) return [];
  const hits: ScreenHit[] = [];
  for (const candidate of candidates) {
    if (candidate.address === null) continue; // ALT-unresolved: skip
    if (blocklistSet.has(candidate.address)) {
      hits.push({
        address: candidate.address,
        category: candidate.category,
        instructionIndex: candidate.instructionIndex,
      });
    }
  }
  return hits;
}
