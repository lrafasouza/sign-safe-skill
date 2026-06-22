/**
 * catalog-coverage.test.ts -- negative-space regression guard.
 *
 * Closes the false-negative SIGN gaps found by adversarial review:
 *   F1  Token-2022 Approve / CloseAccount were catalogued only for Tokenkeg, so
 *       a Token-2022 delegate-grant / close SIGNed clean.
 *   F2  System WithdrawNonceAccount (a SOL drain) was uncatalogued and invisible
 *       to outflow, so it SIGNed clean.
 *   F3  FreezeAccount / MintTo (both token programs) and large CreateAccount
 *       funding were not flagged.
 *
 * The load-bearing assertion is simple and permanent: each of these executable,
 * dangerous transaction shapes must NEVER return SIGN. The two Token-2022 cases
 * use the exact base64 that reproduced the original false SIGN.
 */

import { describe, it, expect } from "vitest";
import { reviewBase64 } from "../src/verdict.ts";
import { base58DecodeFixed } from "../src/decode.ts";
import { encodeCompactU16, u32le, u64le, toB64 } from "./helpers.ts";

const SYSTEM = "11111111111111111111111111111111";
const SPL = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const T22 = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";

/**
 * Build a minimal valid legacy message that invokes `programB58` with `data`.
 * header [1,0,1] -> 1 writable signer (fee payer, index 0) + 1 readonly program
 * (index 1). Distinct static keys, canonical, decodes cleanly.
 */
function msg(programB58: string, data: number[], accts: number[] = [0]): string {
  const out: number[] = [];
  out.push(1, 0, 1); // numReqSig=1, numRoSigned=0, numRoUnsigned=1
  out.push(...encodeCompactU16(2)); // 2 static keys
  out.push(...new Array(32).fill(9)); // key0: writable signer / fee payer
  out.push(...Array.from(base58DecodeFixed(programB58, 32))); // key1: the program
  out.push(...new Array(32).fill(250)); // recent blockhash
  out.push(...encodeCompactU16(1)); // 1 instruction
  out.push(1); // programIdIndex -> key1
  out.push(...encodeCompactU16(accts.length));
  out.push(...accts);
  out.push(...encodeCompactU16(data.length));
  out.push(...data);
  return toB64(Uint8Array.from(out));
}

// Real base64 from the adversarial review that originally SIGNed (F1).
const T22_APPROVE_B64 =
  "AQACBAEHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcBAgcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwIDBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHAwbd9uHudY/eGEJdvORszdq2GvxNg7kNJ/69+SjYoYv8+vr6+vr6+vr6+vr6+vr6+vr6+vr6+vr6+vr6+vr6+voBAwMBAgAJBEBCDwAAAAAA";
const T22_CLOSE_B64 =
  "AQABBAEHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcBAgcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwIDBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHAwbd9uHudY/eGEJdvORszdq2GvxNg7kNJ/69+SjYoYv8+vr6+vr6+vr6+vr6+vr6+vr6+vr6+vr6+vr6+vr6+voBAwMBAgABCQ==";

describe("catalog coverage — dangerous shapes must never SIGN", () => {
  const cases: Array<[string, string, string?]> = [
    // [name, base64, expected catalog finding id (optional)]
    ["Token-2022 Approve (delegate grant) [F1]", T22_APPROVE_B64, "token2022-approve-delegate"],
    ["Token-2022 CloseAccount [F1]", T22_CLOSE_B64, "token2022-close-account"],
    ["System WithdrawNonceAccount (SOL drain) [F2]", msg(SYSTEM, [...u32le(5), ...u64le(7_000_000_000n)]), "system-withdraw-nonce"],
    ["SPL FreezeAccount [F3]", msg(SPL, [10]), "spl-freeze-account"],
    ["Token-2022 FreezeAccount [F3]", msg(T22, [10]), "token2022-freeze-account"],
    ["SPL MintTo [F3]", msg(SPL, [7]), "spl-mint-to"],
    ["Token-2022 MintTo [F3]", msg(T22, [7]), "token2022-mint-to"],
    // CreateAccount funding 5 SOL -> over the 1 SOL threshold -> HOLD via outflow
    ["large System CreateAccount funding [F3]", msg(SYSTEM, [...u32le(0), ...u64le(5_000_000_000n), ...u64le(0n), ...new Array(32).fill(0)]), undefined],
  ];

  for (const [name, b64, findingId] of cases) {
    it(`${name} is never SIGN`, () => {
      const v = reviewBase64(b64);
      expect(v.decision).not.toBe("SIGN");
      expect(v.flags.decodeFailed).toBe(false); // it decoded; it's flagged on merit
      if (findingId) {
        expect(v.findings.some((f) => f.id === findingId)).toBe(true);
      }
    });
  }

  it("positive control: a small plain SPL Token transfer still SIGNs (no over-flagging)", () => {
    const v = reviewBase64(msg(SPL, [3, ...u64le(1_000n)]));
    expect(v.decision).toBe("SIGN");
  });

  it("positive control: a small System CreateAccount (under threshold) still SIGNs", () => {
    const v = reviewBase64(msg(SYSTEM, [...u32le(0), ...u64le(2_000_000n), ...u64le(0n), ...new Array(32).fill(0)]));
    expect(v.decision).toBe("SIGN");
  });
});
