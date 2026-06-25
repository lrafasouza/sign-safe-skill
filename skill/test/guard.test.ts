import { describe, expect, it, vi } from "vitest";
import {
  SignBlockedError,
  SignReviewRequiredError,
  guardedMwaTransact,
  guardedSignTransaction,
} from "../src/adapters/index.ts";
import { readFixtureB64 } from "./helpers.ts";

describe("guarded signing adapters", () => {
  it("blocks a REJECT verdict before calling signTransaction", async () => {
    const transaction = readFixtureB64("02_setauthority_reject");
    const signTransaction = vi.fn(async () => "signed");

    await expect(
      guardedSignTransaction(transaction, signTransaction, {
        transactionToBase64: (input) => input,
        requireHumanReview: true,
      }),
    ).rejects.toBeInstanceOf(SignBlockedError);
    expect(signTransaction).not.toHaveBeenCalled();
  });

  it("passes a SIGN transaction through and returns the signed result", async () => {
    const transaction = readFixtureB64("01_safe_sol_transfer");
    const signed = { transaction, signature: "mock-signature" };
    const signTransaction = vi.fn(async () => signed);

    await expect(
      guardedSignTransaction(transaction, signTransaction, {
        transactionToBase64: (input) => input,
        requireHumanReview: true,
      }),
    ).resolves.toBe(signed);
    expect(signTransaction).toHaveBeenCalledOnce();
    expect(signTransaction).toHaveBeenCalledWith(transaction);
  });

  it("blocks HOLD after onHold unless review explicitly approves signing", async () => {
    const transaction = readFixtureB64("05_approve_delegate_hold");
    const calls: string[] = [];
    const onHold = vi.fn(async (verdict) => {
      calls.push(`hold:${verdict.decision}`);
    });
    const signTransaction = vi.fn(async () => {
      calls.push("sign");
      return "signed";
    });

    await expect(
      guardedSignTransaction(transaction, signTransaction, {
        transactionToBase64: (input) => input,
        onHold,
      }),
    ).rejects.toBeInstanceOf(SignReviewRequiredError);
    expect(onHold).toHaveBeenCalledOnce();
    expect(signTransaction).not.toHaveBeenCalled();
    expect(calls).toEqual(["hold:HOLD"]);
  });

  it("signs a HOLD only when onHold returns affirmative approval", async () => {
    const transaction = readFixtureB64("05_approve_delegate_hold");
    const onHold = vi.fn(async () => true);
    const signTransaction = vi.fn(async () => "signed");

    await expect(
      guardedSignTransaction(transaction, signTransaction, {
        transactionToBase64: (input) => input,
        onHold,
      }),
    ).resolves.toBe("signed");
    expect(onHold).toHaveBeenCalledOnce();
    expect(signTransaction).toHaveBeenCalledOnce();
  });

  it("gates an MWA transact signTransactions flow before signing the batch", async () => {
    const signTransactions = vi.fn(
      async ({ transactions }: { transactions: readonly string[] }) =>
        transactions,
    );
    const transact = async <TResult>(
      callback: (wallet: {
        signTransactions: typeof signTransactions;
      }) => Promise<TResult>,
    ): Promise<TResult> => callback({ signTransactions });
    const guardedTransact = guardedMwaTransact(transact, {
      transactionToBase64: (input: string) => input,
      requireHumanReview: true,
    });

    await expect(
      guardedTransact((wallet) =>
        wallet.signTransactions({
          transactions: [readFixtureB64("02_setauthority_reject")],
        }),
      ),
    ).rejects.toBeInstanceOf(SignBlockedError);
    expect(signTransactions).not.toHaveBeenCalled();
  });
});
