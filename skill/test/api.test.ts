import { describe, expect, it } from "vitest";
import {
  Transaction,
  VersionedMessage,
  VersionedTransaction,
} from "@solana/web3.js";
import * as kit from "@solana/kit";
import {
  DEFAULT_CONTEXT,
  decodeInput,
  reviewBase64,
  type Finding,
  type Verdict,
  type VerdictContext,
} from "../src/index.ts";
import {
  SignBlockedError,
  guardedSignWeb3Transaction,
  kitTransactionToBase64,
  reviewKitTransaction,
  reviewWeb3Transaction,
  web3TransactionToBase64,
} from "../src/adapters/index.ts";
import { encodeCompactU16, readFixtureB64 } from "./helpers.ts";

function wrapUnsignedTransaction(messageBase64: string): Uint8Array {
  const messageBytes = new Uint8Array(Buffer.from(messageBase64, "base64"));
  const signatureCount =
    decodeInput(messageBase64).message.header.numRequiredSignatures;
  return Uint8Array.from([
    ...encodeCompactU16(signatureCount),
    ...new Uint8Array(signatureCount * 64),
    ...messageBytes,
  ]);
}

describe("public programmatic API", () => {
  const messageBase64 = readFixtureB64("01_safe_sol_transfer");
  const unsignedTransactionBytes = wrapUnsignedTransaction(messageBase64);

  it("reviews a known base64 transaction through the public barrel", () => {
    const ctx: VerdictContext = DEFAULT_CONTEXT;
    const verdict: Verdict = reviewBase64(messageBase64, ctx);
    const findings: Finding[] = verdict.findings;

    expect(verdict.decision).toBe("SIGN");
    expect(findings).toEqual([]);
  });

  it("reviews a web3.js VersionedTransaction through the adapter", () => {
    const message = VersionedMessage.deserialize(
      new Uint8Array(Buffer.from(messageBase64, "base64")),
    );
    const transaction = new VersionedTransaction(message);

    expect(web3TransactionToBase64(transaction)).toBe(
      Buffer.from(transaction.serialize()).toString("base64"),
    );
    expect(reviewWeb3Transaction(transaction).decision).toBe("SIGN");
  });

  it("guards web3.js signing with the adapter serializer", async () => {
    const rejectMessageBase64 = readFixtureB64("02_setauthority_reject");
    const message = VersionedMessage.deserialize(
      new Uint8Array(Buffer.from(rejectMessageBase64, "base64")),
    );
    const transaction = new VersionedTransaction(message);
    let signCalls = 0;

    await expect(
      guardedSignWeb3Transaction(
        transaction,
        async () => {
          signCalls++;
          return transaction;
        },
        { requireHumanReview: true },
      ),
    ).rejects.toBeInstanceOf(SignBlockedError);
    expect(signCalls).toBe(0);
  });

  it("reviews a legacy web3.js Transaction through the adapter", () => {
    const transaction = Transaction.from(unsignedTransactionBytes);

    expect(web3TransactionToBase64(transaction)).toBe(
      Buffer.from(
        transaction.serialize({
          requireAllSignatures: false,
          verifySignatures: false,
        }),
      ).toString("base64"),
    );
    expect(reviewWeb3Transaction(transaction).decision).toBe("SIGN");
  });

  it("reviews @solana/kit transactions and transaction messages through the adapter", async () => {
    const transaction = kit
      .getTransactionDecoder()
      .decode(unsignedTransactionBytes);
    const compiledMessage = kit
      .getCompiledTransactionMessageDecoder()
      .decode(new Uint8Array(Buffer.from(messageBase64, "base64")));
    const transactionMessage = kit.decompileTransactionMessage(compiledMessage);

    expect(await kitTransactionToBase64(transaction)).toBe(
      Buffer.from(unsignedTransactionBytes).toString("base64"),
    );
    expect((await reviewKitTransaction(transaction)).decision).toBe("SIGN");
    expect((await reviewKitTransaction(transactionMessage)).decision).toBe(
      "SIGN",
    );
  });
});
