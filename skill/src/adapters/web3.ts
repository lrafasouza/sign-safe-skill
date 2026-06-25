import type { Transaction, VersionedTransaction } from "@solana/web3.js";
import { reviewBase64 } from "../verdict.ts";
import type { Verdict, VerdictContext } from "../types.ts";
import { guardedSignTransaction } from "./guard.ts";
import type { GuardedSignPolicyOptions } from "./guard.ts";

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

/**
 * Review a web3.js transaction before delegating to the real signer.
 */
export function guardedSignWeb3Transaction<TSigned>(
  transaction: Web3Transaction,
  signTransaction: (transaction: Web3Transaction) => Promise<TSigned>,
  options: GuardedSignPolicyOptions<Web3Transaction>,
): Promise<TSigned> {
  return guardedSignTransaction(transaction, signTransaction, {
    ...options,
    transactionToBase64: web3TransactionToBase64,
  });
}
