/**
 * Optional web3.js transaction serialization and review helpers.
 */
export {
  guardedSignWeb3Transaction,
  reviewWeb3Transaction,
  web3TransactionToBase64,
} from "./web3.ts";
export type { Web3Transaction } from "./web3.ts";

/**
 * Optional @solana/kit transaction serialization and review helpers.
 */
export { kitTransactionToBase64, reviewKitTransaction } from "./kit.ts";
export type { KitTransactionInput } from "./kit.ts";

/**
 * Review-before-signing gates for generic and Mobile Wallet Adapter flows.
 */
export {
  SignBlockedError,
  SignReviewRequiredError,
  guardedMwaTransact,
  guardedSignTransaction,
} from "./guard.ts";
export type {
  GuardedSignOptions,
  GuardedSignPolicyOptions,
  HoldHandler,
  MwaSignTransactionsInput,
  MwaTransact,
  MwaWallet,
  TransactionToBase64,
} from "./guard.ts";
