import type { CompilableTransactionMessage, Transaction } from "@solana/kit";
import { reviewBase64 } from "../verdict.ts";
import type { Verdict, VerdictContext } from "../types.ts";

export type KitTransactionInput = Transaction | CompilableTransactionMessage;

function isTransaction(input: KitTransactionInput): input is Transaction {
  return "messageBytes" in input && "signatures" in input;
}

/**
 * Compile or serialize an @solana/kit transaction input to base64.
 */
export async function kitTransactionToBase64(
  input: KitTransactionInput,
): Promise<string> {
  const { compileTransaction, getBase64EncodedWireTransaction } =
    await import("@solana/kit");
  const transaction = isTransaction(input) ? input : compileTransaction(input);
  return getBase64EncodedWireTransaction(transaction);
}

/**
 * Review an @solana/kit transaction or compilable message with the offline core.
 */
export async function reviewKitTransaction(
  input: KitTransactionInput,
  ctx?: VerdictContext,
): Promise<Verdict> {
  return reviewBase64(await kitTransactionToBase64(input), ctx);
}
