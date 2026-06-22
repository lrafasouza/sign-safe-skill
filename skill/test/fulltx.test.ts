/**
 * fulltx.test.ts -- full signed-transaction input handling (rules §7 / W011).
 *
 * A caller may paste a full `signatures || message` blob instead of a bare
 * message. The tool must strip the (never-verified) signature slots, analyze the
 * inner message, report `inputWasFullTransaction` + `signatureCount`, and reach
 * the SAME verdict as the bare message -- while a bare message keeps its exact
 * verdict shape, a mismatched signature count fails closed, and non-canonical
 * garbage never silently SIGNs.
 */

import { describe, it, expect } from "vitest";
import {
  decodeInput,
  decodeMessageBytes,
  tryDecodeFullTransaction,
} from "../src/decode.ts";
import { reviewBase64, verdictToJson } from "../src/verdict.ts";
import { encodeCompactU16, readFixtureB64, toB64 } from "./helpers.ts";

function bytesOf(b64: string): Uint8Array {
  return new Uint8Array(Buffer.from(b64, "base64"));
}

/** Wrap message bytes as a full transaction with `sigCount` zero-filled sigs. */
function wrapAsTransaction(msgBytes: Uint8Array, sigCount: number): Uint8Array {
  const prefix = encodeCompactU16(sigCount);
  const sigs = new Array(sigCount * 64).fill(0);
  return Uint8Array.from([...prefix, ...sigs, ...msgBytes]);
}

const BARE = "01_safe_sol_transfer";

describe("full signed-transaction input", () => {
  const msgB64 = readFixtureB64(BARE);
  const msgBytes = bytesOf(msgB64);
  const decoded = decodeMessageBytes(msgBytes);
  const n = decoded.header.numRequiredSignatures;
  const fullB64 = toB64(wrapAsTransaction(msgBytes, n));

  it("a bare message keeps the unchanged verdict shape (no full-tx fields)", () => {
    const v = reviewBase64(msgB64);
    expect(v.inputWasFullTransaction).toBeUndefined();
    expect(v.signatureCount).toBeUndefined();
  });

  it("decodeInput flags a bare message as not-a-full-transaction", () => {
    const r = decodeInput(msgB64);
    expect(r.inputWasFullTransaction).toBe(false);
    expect(r.signatureCount).toBe(0);
  });

  it("decodeInput strips signatures and recovers the identical inner message", () => {
    const r = decodeInput(fullB64);
    expect(r.inputWasFullTransaction).toBe(true);
    expect(r.signatureCount).toBe(n);
    expect(r.message.staticAccountKeys).toEqual(decoded.staticAccountKeys);
    expect(r.message.recentBlockhash).toBe(decoded.recentBlockhash);
  });

  it("a full transaction reaches the SAME decision as its bare message", () => {
    const bare = reviewBase64(msgB64);
    const full = reviewBase64(fullB64);
    expect(full.decision).toBe(bare.decision);
    expect(full.inputWasFullTransaction).toBe(true);
    expect(full.signatureCount).toBe(n);
    expect(full.reason).toContain("full signed transaction");
    // signatures are never claimed to be verified
    expect(full.reason).toContain("not verified");
  });

  it("is deterministic for a full-transaction input", () => {
    expect(verdictToJson(reviewBase64(fullB64))).toBe(
      verdictToJson(reviewBase64(fullB64)),
    );
  });

  it("tryDecodeFullTransaction returns null for a bare message", () => {
    expect(tryDecodeFullTransaction(msgBytes)).toBeNull();
  });

  it("fails closed when signature count != required signers", () => {
    const mismatched = toB64(wrapAsTransaction(msgBytes, n + 1));
    const v = reviewBase64(mismatched);
    expect(v.decision).toBe("REJECT");
    expect(v.flags.decodeFailed).toBe(true);
  });

  it("short garbage (neither message nor transaction) fails closed", () => {
    const v = reviewBase64(toB64(Uint8Array.from([1, 2, 3, 4, 5])));
    expect(v.decision).toBe("REJECT");
    expect(v.flags.decodeFailed).toBe(true);
  });

  it("never emits SIGN from a full-transaction wrapper around an unknown blob", () => {
    // 1 sig slot + a deliberately malformed 'message' => must REJECT, not SIGN.
    const junkMsg = Uint8Array.from(new Array(40).fill(0xff));
    const v = reviewBase64(toB64(wrapAsTransaction(junkMsg, 1)));
    expect(v.decision).toBe("REJECT");
  });
});
