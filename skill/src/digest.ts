/**
 * digest.ts -- PURE: compute a deterministic transaction digest over message bytes.
 *
 * Offline core: no network, no RPC, no fetch, no enrich.ts imports.
 * Same bytes in => same result out.
 *
 * A signer can use the digest to confirm the EXACT bytes on a second device:
 *   1. Compute the digest on device A (the primary signer UI).
 *   2. Independently compute (or display) the digest on device B (cold storage,
 *      hardware wallet, or a trusted audit machine).
 *   3. If the two digests match, the bytes are identical -- the transaction has
 *      not been modified in transit.
 *
 * The short code is a human-verifiable representation: 5 groups of 4 hex
 * characters separated by hyphens (20 hex chars = 80 bits of the sha256).
 * Format: XXXX-XXXX-XXXX-XXXX-XXXX (case-insensitive for comparison).
 *
 * PURE: uses node:crypto (built-in, offline). No network.
 */

import { createHash } from "node:crypto";
import { decodeInput } from "./decode.ts";

export interface TransactionDigest {
  /** Full SHA-256 hex string (64 hex chars) of the raw message bytes. */
  sha256: string;
  /**
   * Human-verifiable short code: first 20 hex chars of sha256 grouped as
   * XXXX-XXXX-XXXX-XXXX-XXXX. Lowercase for canonical form.
   * Two messages with the same shortCode but different sha256 should not exist
   * in practice (80 bits makes collision astronomically unlikely), but if you
   * need maximum confidence always compare the full sha256.
   */
  shortCode: string;
  /** The message version detected from the bytes. */
  messageVersion: "legacy" | 0;
}

/**
 * Compute a deterministic digest over message bytes.
 *
 * Accepts a base64-encoded message (same format as reviewBase64). The bytes
 * passed to sha256 are the RAW message bytes after base64 decoding and, if
 * the input was a full signed transaction, after stripping the leading
 * signature slots (identical to how reviewBase64 processes the input, so the
 * digest covers the same bytes the verdict was computed over).
 *
 * FAIL-CLOSED: any decode error (malformed base64, unsupported version,
 * structural truncation) throws a TransactionDigestError rather than returning
 * a digest over garbage bytes. A caller that needs a verdict and a digest
 * should run both; the thrown error maps to REJECT in the verdict layer.
 *
 * @param b64 Base64-encoded message or full signed transaction.
 * @returns TransactionDigest with sha256, shortCode, and messageVersion.
 * @throws TransactionDigestError on malformed input.
 */
export function transactionDigest(b64: string): TransactionDigest {
  let messageBytes: Uint8Array;
  let version: "legacy" | 0;

  try {
    const { rawMessageBytes, message } = decodeInput(b64);
    messageBytes = rawMessageBytes;
    version = message.version;
  } catch (err) {
    const detail = err instanceof Error ? err.message : String(err);
    throw new TransactionDigestError(
      `digest: input could not be decoded: ${detail}`,
    );
  }

  const hashHex = createHash("sha256").update(messageBytes).digest("hex");

  // Build the short code: first 20 hex chars grouped as XXXX-XXXX-XXXX-XXXX-XXXX
  const raw = hashHex.slice(0, 20);
  const shortCode = `${raw.slice(0, 4)}-${raw.slice(4, 8)}-${raw.slice(8, 12)}-${raw.slice(12, 16)}-${raw.slice(16, 20)}`;

  return {
    sha256: hashHex,
    shortCode,
    messageVersion: version,
  };
}

/** Typed error for digest computation failures. */
export class TransactionDigestError extends Error {
  override name = "TransactionDigestError";
}
