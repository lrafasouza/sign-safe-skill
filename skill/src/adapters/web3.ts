import type { Transaction, VersionedTransaction } from "@solana/web3.js";
import { reviewBase64 } from "../verdict.ts";
import type { Verdict, VerdictContext } from "../types.ts";

export type Web3Transaction = Transaction | VersionedTransaction;

/**
 * Serialize a web3.js legacy or versioned transaction to base64.
 */
export function web3TransactionToBase64(transaction: Web3Transaction): string {
  const bytes =
    "version" in transaction
      ? transaction.serialize()
      : transaction.serialize({
          requireAllSignatures: false,
          verifySignatures: false,
        });
  return Buffer.from(bytes).toString("base64");
}

/**
 * Review a web3.js transaction with the deterministic offline core.
 */
export function reviewWeb3Transaction(
  transaction: Web3Transaction,
  ctx?: VerdictContext,
): Verdict {
  return reviewBase64(web3TransactionToBase64(transaction), ctx);
}
