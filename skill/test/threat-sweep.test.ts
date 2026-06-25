import { describe, expect, it } from "vitest";
import { base58DecodeFixed, base58Encode, decodeInput } from "../src/decode.ts";
import { reviewWithEnrichment } from "../src/review-online.ts";
import { DEFAULT_CONTEXT } from "../src/types.ts";
import { reviewBase64 } from "../src/verdict.ts";
import { encodeCompactU16, key, legacyBytes, toB64, u64le } from "./helpers.ts";

const SPL_TOKEN = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const TOKEN_2022 = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";
const BPF_LOADER = "BPFLoaderUpgradeab1e11111111111111111111111";
const STAKE = "Stake11111111111111111111111111111111111111";
const MARGINFI = "MFv2hWf31Z9kbCa1snEPYctwafyhdvnV7FZnsebVacA";

function buildProgramMessage(programId: string, data: number[]): string {
  const out: number[] = [];
  out.push(1, 0, 1);
  out.push(4);
  out.push(...key(1));
  out.push(...key(2));
  out.push(...key(3));
  out.push(...base58DecodeFixed(programId, 32));
  out.push(...key(250));
  out.push(1);
  out.push(3);
  out.push(3, 1, 2, 0);
  out.push(...encodeCompactU16(data.length));
  out.push(...data);
  return toB64(Uint8Array.from(out));
}

function buildAltBytes(addresses: Uint8Array[]): Uint8Array {
  const out: number[] = [];
  out.push(1, 0, 0, 0);
  out.push(0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff);
  out.push(0, 0, 0, 0, 0, 0, 0, 0);
  out.push(0, 0);
  out.push(...new Array(32).fill(0));
  out.push(0, 0);
  for (const address of addresses) out.push(...address);
  return Uint8Array.from(out);
}

function buildMintWithPermanentDelegate(delegateFill: number): Uint8Array {
  const out = new Array(166).fill(0);
  out[165] = 1;
  out.push(12, 0, 32, 0);
  out.push(...new Array(32).fill(delegateFill));
  out.push(14, 0, 64, 0);
  out.push(...new Array(32).fill(0));
  out.push(...new Array(32).fill(0xef));
  return Uint8Array.from(out);
}

function buildTransferCheckedWithAltMint(): string {
  const out: number[] = [];
  out.push(0x80);
  out.push(1, 0, 1);
  out.push(4);
  out.push(...key(1));
  out.push(...key(2));
  out.push(...key(3));
  out.push(...base58DecodeFixed(TOKEN_2022, 32));
  out.push(...key(250));
  out.push(1);
  out.push(3);
  out.push(4, 1, 4, 2, 0);
  out.push(10, 12, ...u64le(100n), 6);
  out.push(1);
  out.push(...key(0xbb));
  out.push(0);
  out.push(1, 5);
  return toB64(Uint8Array.from(out));
}

describe("final adversarial threat sweep regressions", () => {
  it("never SIGNs a max-u64 SPL transfer to a non-signer", () => {
    const verdict = reviewBase64(
      buildProgramMessage(SPL_TOKEN, [3, ...u64le(0xffff_ffff_ffff_ffffn)]),
    );

    expect(verdict.decision).not.toBe("SIGN");
  });

  it("screens Token-2022 danger extensions when the mint is ALT-resolved", async () => {
    const b64 = buildTransferCheckedWithAltMint();
    const message = decodeInput(b64).message;
    const tableAddress = message.addressTableLookups[0]!.accountKey;
    const mintBytes = new Uint8Array(32).fill(0xdd);
    const mintAddress = base58Encode(mintBytes);
    const altAddresses = Array.from({ length: 6 }, (_, index) =>
      new Uint8Array(32).fill(index === 5 ? 0xdd : index),
    );
    const altBytes = buildAltBytes(altAddresses);
    const mintAccount = buildMintWithPermanentDelegate(0xee);
    const fetcher = async (pubkey: string) => {
      if (pubkey === tableAddress) return { data: altBytes };
      if (pubkey === mintAddress) return { data: mintAccount };
      return null;
    };

    const verdict = await reviewWithEnrichment(b64, DEFAULT_CONTEXT, fetcher);

    expect(verdict.decision).toBe("HOLD");
    expect(
      verdict.findings.some(
        (finding) => finding.id === "token2022-permanent-delegate",
      ),
    ).toBe(true);
    expect(
      verdict.findings.some(
        (finding) => finding.id === "token2022-transfer-hook",
      ),
    ).toBe(true);
  });

  it("treats an empty successful simulation response as unverified", async () => {
    const b64 = toB64(
      legacyBytes(
        [1, 0, 1],
        [1, 0],
        [{ prog: 1, accts: [0, 0], data: [2, 0, 0, 0, ...u64le(0n)] }],
      ),
    );
    const verdict = await reviewWithEnrichment(
      b64,
      DEFAULT_CONTEXT,
      async () => null,
      {
        simulate: true,
        simulateFn: async () => ({
          err: null,
          logs: [],
          accounts: [],
        }),
      },
    );

    expect(verdict.decision).toBe("HOLD");
    expect(
      verdict.findings.some((finding) => finding.id === "simulation-failed"),
    ).toBe(true);
  });

  it("rejects every SPL and Token-2022 SetAuthority AuthorityType variant", () => {
    for (const authorityType of [0, 1, 2, 3]) {
      const verdict = reviewBase64(
        buildProgramMessage(SPL_TOKEN, [6, authorityType, 1, ...key(9)]),
      );
      expect(verdict.decision, `SPL AuthorityType ${authorityType}`).toBe(
        "REJECT",
      );
    }
    for (let authorityType = 0; authorityType <= 17; authorityType++) {
      const verdict = reviewBase64(
        buildProgramMessage(TOKEN_2022, [6, authorityType, 1, ...key(9)]),
      );
      expect(
        verdict.decision,
        `Token-2022 AuthorityType ${authorityType}`,
      ).toBe("REJECT");
    }
  });

  it("rejects SetAuthority when the writable target is ALT-resolved", () => {
    const out: number[] = [];
    out.push(0x80);
    out.push(1, 0, 1);
    out.push(2);
    out.push(...key(1));
    out.push(...base58DecodeFixed(SPL_TOKEN, 32));
    out.push(...key(250));
    out.push(1);
    out.push(1);
    out.push(2, 2, 0);
    out.push(35, 6, 2, 1, ...key(9));
    out.push(1);
    out.push(...key(0xbb));
    out.push(1, 0);
    out.push(0);
    const b64 = toB64(Uint8Array.from(out));
    const tableAddress =
      decodeInput(b64).message.addressTableLookups[0]!.accountKey;
    const verdict = reviewBase64(b64, {
      ...DEFAULT_CONTEXT,
      resolvedAltTables: new Map([
        [tableAddress, [base58Encode(Uint8Array.from(key(4)))]],
      ]),
    });
    expect(verdict.decision).toBe("REJECT");
  });

  it("rejects BPF loader authority changes and Stake Withdrawer authorization", () => {
    for (const tag of [4, 7]) {
      expect(
        reviewBase64(buildProgramMessage(BPF_LOADER, [tag, 0, 0, 0])).decision,
      ).toBe("REJECT");
    }
    const stakeAuthorize = reviewBase64(
      buildProgramMessage(STAKE, [1, 0, 0, 0, ...key(7), 1, 0, 0, 0]),
    );
    expect(stakeAuthorize.decision).toBe("REJECT");
    expect(
      stakeAuthorize.findings.some(
        (finding) => finding.id === "stake-authorize",
      ),
    ).toBe(true);
  });

  it("does not SIGN Marginfi authority transfer or lending withdrawal", () => {
    const transfer = reviewBase64(
      buildProgramMessage(
        MARGINFI,
        [0x1c, 0x4f, 0x81, 0xe7, 0xa9, 0x45, 0x45, 0x41],
      ),
    );
    const withdraw = reviewBase64(
      buildProgramMessage(
        MARGINFI,
        [0x24, 0x48, 0x4a, 0x13, 0xd2, 0xd2, 0xc0, 0xc0],
      ),
    );
    expect(transfer.decision).toBe("REJECT");
    expect(withdraw.decision).toBe("HOLD");
  });

  it("does not SIGN Stake Withdraw, large SOL, Approve, CloseAccount, or Batch", () => {
    const cases = [
      buildProgramMessage(STAKE, [4, 0, 0, 0, ...u64le(2_000_000_000n)]),
      buildProgramMessage("11111111111111111111111111111111", [
        2,
        0,
        0,
        0,
        ...u64le(2_000_000_000n),
      ]),
      buildProgramMessage(SPL_TOKEN, [4, ...u64le(1_000_000n)]),
      buildProgramMessage(SPL_TOKEN, [9]),
      buildProgramMessage(SPL_TOKEN, [255]),
    ];
    for (const b64 of cases)
      expect(reviewBase64(b64).decision).not.toBe("SIGN");
  });

  it("does not SIGN unknown writable, unresolved ALT, durable-nonce multi-signer, or malformed input", () => {
    const unknownWritable = toB64(
      legacyBytes([1, 0, 0], [1, 0xff], [{ prog: 1, accts: [0], data: [1] }]),
    );
    const durableNonce = toB64(
      legacyBytes(
        [2, 1, 1],
        [1, 2, 3, 0],
        [{ prog: 3, accts: [2, 1], data: [4, 0, 0, 0] }],
      ),
    );
    expect(reviewBase64(unknownWritable).decision).not.toBe("SIGN");
    expect(reviewBase64(buildTransferCheckedWithAltMint()).decision).toBe(
      "HOLD",
    );
    expect(reviewBase64(durableNonce).decision).not.toBe("SIGN");
    expect(reviewBase64("%%%not-base64%%%").decision).toBe("REJECT");
  });

  it("empty blocklist and benign simulation cannot soften a static REJECT", () => {
    const b64 = buildProgramMessage(SPL_TOKEN, [6, 2, 1, ...key(9)]);
    const verdict = reviewBase64(b64, {
      ...DEFAULT_CONTEXT,
      recipientBlocklist: new Set(),
      simulation: {
        ok: true,
        signerSolDelta: 0n,
        tokenDeltas: [],
        outflowsToNonSigner: [],
      },
    });
    expect(verdict.decision).toBe("REJECT");
  });

  it("benign online simulation cannot overwrite an existing simulation HOLD", async () => {
    const b64 = buildProgramMessage("11111111111111111111111111111111", [
      2,
      0,
      0,
      0,
      ...u64le(1n),
    ]);
    const verdict = await reviewWithEnrichment(
      b64,
      {
        ...DEFAULT_CONTEXT,
        simulation: {
          ok: false,
          err: "previous simulation could not verify the economic outcome",
          signerSolDelta: 0n,
          tokenDeltas: [],
          outflowsToNonSigner: [],
        },
      },
      async () => null,
      {
        simulate: true,
        simulateFn: async () => ({
          err: null,
          logs: [],
          accounts: [
            {
              lamports: 1n,
              data: Buffer.alloc(0),
              owner: "11111111111111111111111111111111",
            },
          ],
          preBalances: [1n],
          postBalances: [1n],
        }),
      },
    );
    expect(verdict.decision).toBe("HOLD");
    expect(
      verdict.findings.some((finding) => finding.id === "simulation-failed"),
    ).toBe(true);
  });

  it("does not SIGN a large unattributed signer SOL loss from simulation", () => {
    const b64 = buildProgramMessage("11111111111111111111111111111111", [
      2,
      0,
      0,
      0,
      ...u64le(1n),
    ]);
    const verdict = reviewBase64(b64, {
      ...DEFAULT_CONTEXT,
      simulation: {
        ok: true,
        signerSolDelta: -2_000_000_000n,
        tokenDeltas: [],
        outflowsToNonSigner: [],
      },
    });
    expect(verdict.decision).toBe("HOLD");
    expect(
      verdict.findings.some((finding) => finding.id === "simulation-outflow"),
    ).toBe(true);
  });

  it("SIGNs only the genuinely benign below-threshold control", () => {
    const verdict = reviewBase64(
      buildProgramMessage("11111111111111111111111111111111", [
        2,
        0,
        0,
        0,
        ...u64le(1n),
      ]),
    );
    expect(verdict.decision).toBe("SIGN");
  });
});
