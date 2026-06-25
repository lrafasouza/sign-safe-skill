import { reviewWithEnrichment } from "../review-online.ts";
import { reviewBase64 } from "../verdict.ts";
import { DEFAULT_CONTEXT } from "../types.ts";
import type { AccountFetcher } from "../enrich.ts";
import type { ReviewEnrichmentOpts } from "../review-online.ts";
import type { Verdict, VerdictContext } from "../types.ts";

export type TransactionToBase64<TTransaction> = (
  transaction: TTransaction,
) => string | Promise<string>;

export type HoldHandler<TTransaction> = (
  verdict: Verdict,
  transaction: TTransaction,
) => boolean | void | Promise<boolean | void>;

export type GuardedSignPolicyOptions<TTransaction> = {
  context?: VerdictContext;
  fetcher?: AccountFetcher;
  enrichment?: ReviewEnrichmentOpts;
} & (
  | {
      onHold: HoldHandler<TTransaction>;
      requireHumanReview?: boolean;
    }
  | {
      onHold?: HoldHandler<TTransaction>;
      requireHumanReview: true;
    }
);

export type GuardedSignOptions<TTransaction> =
  GuardedSignPolicyOptions<TTransaction> & {
    transactionToBase64: TransactionToBase64<TTransaction>;
  };

export interface MwaSignTransactionsInput<TTransaction> {
  transactions: readonly TTransaction[];
}

export interface MwaWallet<TTransaction, TSignedTransactions> {
  signTransactions(
    input: MwaSignTransactionsInput<TTransaction>,
  ): Promise<TSignedTransactions>;
}

export type MwaTransact<TWallet> = <TResult>(
  callback: (wallet: TWallet) => Promise<TResult>,
) => Promise<TResult>;

export class SignBlockedError extends Error {
  readonly verdict: Verdict;

  constructor(verdict: Verdict) {
    super(`sign-safe blocked signing: ${verdict.reason}`);
    this.name = "SignBlockedError";
    this.verdict = verdict;
  }
}

export class SignReviewRequiredError extends Error {
  readonly verdict: Verdict;

  constructor(verdict: Verdict) {
    super(`sign-safe requires human review: ${verdict.reason}`);
    this.name = "SignReviewRequiredError";
    this.verdict = verdict;
  }
}

async function reviewTransaction<TTransaction>(
  transaction: TTransaction,
  options: GuardedSignOptions<TTransaction>,
): Promise<Verdict> {
  const base64 = await options.transactionToBase64(transaction);
  return options.fetcher === undefined
    ? reviewBase64(base64, options.context)
    : reviewWithEnrichment(
        base64,
        options.context ?? DEFAULT_CONTEXT,
        options.fetcher,
        options.enrichment,
      );
}

async function enforceVerdict<TTransaction>(
  verdict: Verdict,
  transaction: TTransaction,
  options: GuardedSignOptions<TTransaction>,
): Promise<void> {
  if (verdict.decision === "REJECT") {
    throw new SignBlockedError(verdict);
  }

  if (verdict.decision === "HOLD") {
    const approved = await options.onHold?.(verdict, transaction);
    if (options.requireHumanReview === true || approved !== true) {
      throw new SignReviewRequiredError(verdict);
    }
  }
}

export async function guardedSignTransaction<TTransaction, TSigned>(
  transaction: TTransaction,
  signTransaction: (transaction: TTransaction) => Promise<TSigned>,
  options: GuardedSignOptions<TTransaction>,
): Promise<TSigned> {
  const verdict = await reviewTransaction(transaction, options);
  await enforceVerdict(verdict, transaction, options);
  return signTransaction(transaction);
}

export function guardedMwaTransact<
  TTransaction,
  TSignedTransactions,
  TWallet extends MwaWallet<TTransaction, TSignedTransactions>,
>(
  transact: MwaTransact<TWallet>,
  options: GuardedSignOptions<TTransaction>,
): MwaTransact<TWallet> {
  return (callback) =>
    transact(async (wallet) => {
      const guardedWallet = Object.create(wallet) as TWallet;
      guardedWallet.signTransactions = async (input) => {
        for (const transaction of input.transactions) {
          const verdict = await reviewTransaction(transaction, options);
          await enforceVerdict(verdict, transaction, options);
        }
        return wallet.signTransactions(input);
      };
      return callback(guardedWallet);
    });
}
