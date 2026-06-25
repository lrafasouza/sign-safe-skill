import { describe, it, expect } from "vitest";
import { base58DecodeFixed, base58Encode } from "../src/decode.ts";
import { reviewBase64 } from "../src/verdict.ts";
import { encodeCompactU16, key, toB64, u32le, u64le } from "./helpers.ts";

const STAKE_PROGRAM = "Stake11111111111111111111111111111111111111";

function stakeMessage(
  data: number[],
  accounts: number[],
  extraKeys: number[],
): string {
  const out: number[] = [];
  out.push(1, 0, 1);
  out.push(...encodeCompactU16(2 + extraKeys.length));
  out.push(...key(1));
  out.push(...base58DecodeFixed(STAKE_PROGRAM, 32));
  for (const extraKey of extraKeys) out.push(...key(extraKey));
  out.push(...key(250));
  out.push(1);
  out.push(1);
  out.push(...encodeCompactU16(accounts.length));
  out.push(...accounts);
  out.push(...encodeCompactU16(data.length));
  out.push(...data);
  return toB64(Uint8Array.from(out));
}

describe("Native Stake program", () => {
  it("Authorize transferring Withdrawer authority is REJECT", () => {
    const newAuthority = key(7);
    const verdict = reviewBase64(
      stakeMessage(
        [...u32le(1), ...newAuthority, ...u32le(1)],
        [2, 3, 0],
        [20, 21],
      ),
    );
    const finding = verdict.findings.find((f) => f.id === "stake-authorize");
    expect(verdict.decision).toBe("REJECT");
    expect(finding).toBeTruthy();
    expect(finding!.detail).toContain("Withdrawer");
    expect(finding!.detail).toContain(
      base58Encode(Uint8Array.from(newAuthority)),
    );
  });

  it("AuthorizeChecked transferring Staker authority is REJECT", () => {
    const newAuthority = key(8);
    const verdict = reviewBase64(
      stakeMessage([...u32le(10), ...u32le(0)], [2, 3, 0, 4], [20, 21, 8]),
    );
    const finding = verdict.findings.find((f) => f.id === "stake-authorize");
    expect(verdict.decision).toBe("REJECT");
    expect(finding).toBeTruthy();
    expect(finding!.detail).toContain("Staker");
    expect(finding!.detail).toContain(
      base58Encode(Uint8Array.from(newAuthority)),
    );
  });

  it("AuthorizeWithSeed transferring authority is REJECT", () => {
    const newAuthority = key(9);
    const data = [
      ...u32le(8),
      ...newAuthority,
      ...u32le(0),
      ...u64le(4n),
      ...Buffer.from("seed"),
      ...key(10),
    ];
    const verdict = reviewBase64(stakeMessage(data, [2, 0, 3], [20, 21]));
    const finding = verdict.findings.find((f) => f.id === "stake-authorize");
    expect(verdict.decision).toBe("REJECT");
    expect(finding).toBeTruthy();
    expect(finding!.detail).toContain("Staker");
    expect(finding!.detail).toContain(
      base58Encode(Uint8Array.from(newAuthority)),
    );
  });

  it("Withdraw surfaces the SOL drain and respects default versus strict mode", () => {
    const amount = 2_000_000_000n;
    const b64 = stakeMessage(
      [...u32le(4), ...u64le(amount)],
      [2, 3, 4, 5, 0],
      [20, 30, 31, 32],
    );
    const defaultVerdict = reviewBase64(b64);
    const strictVerdict = reviewBase64(b64, {
      lamportThreshold: 1_000_000_000,
      strict: true,
    });
    const finding = defaultVerdict.findings.find(
      (f) => f.id === "stake-withdraw",
    );
    expect(defaultVerdict.decision).toBe("HOLD");
    expect(strictVerdict.decision).toBe("REJECT");
    expect(finding).toBeTruthy();
    expect(finding!.detail).toContain(amount.toString());
    expect(defaultVerdict.outflow.lamportTransfers[0]!.amount).toBe(
      amount.toString(),
    );
    expect(defaultVerdict.outflow.lamportTransfers[0]!.to).toBe(
      base58Encode(Uint8Array.from(key(30))),
    );
  });

  it.each([
    ["DelegateStake", 2],
    ["Deactivate", 5],
  ])("%s is recognized without being over-flagged", (_name, tag) => {
    const verdict = reviewBase64(
      stakeMessage(u32le(tag), [2, 3, 4, 5, 0], [20, 21, 22, 23]),
    );
    expect(verdict.decision).toBe("HOLD");
    expect(verdict.findings.some((f) => f.severity === "REJECT")).toBe(false);
    expect(verdict.unknownPrograms).not.toContain(STAKE_PROGRAM);
  });

  it("undecodable Stake instruction is HOLD", () => {
    const verdict = reviewBase64(stakeMessage([1, 0], [2, 3, 0], [20, 21]));
    expect(verdict.decision).toBe("HOLD");
    expect(verdict.unknownPrograms).not.toContain(STAKE_PROGRAM);
  });
});
