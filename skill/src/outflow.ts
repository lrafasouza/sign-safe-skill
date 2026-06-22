/**
 * outflow.ts -- PURE: statically-declared, signer-perspective outflow.
 *
 * "Statically-declared" means we read amounts straight out of instruction data
 * without simulation. We deliberately do NOT estimate dynamic effects (CPI,
 * delegate spends, balance deltas) -- only what the bytes literally declare.
 *
 * Sources counted:
 *   - System Transfer ([u32 tag=2][u64 lamports]) whose funding account
 *     (instruction account index 0) is a signer of this message.
 *   - SPL Token Transfer (disc 3) and TransferChecked (disc 12) raw amounts,
 *     for SPL Token and Token-2022. We report the raw base-unit amount; we
 *     cannot know decimals statically for plain Transfer.
 *
 * The lamport total is what the verdict's threshold rule consults. SPL amounts
 * are surfaced for human review but do not by themselves drive the verdict
 * (they are reported as context; the delegate/approve primitives are what
 * carry SPL severity).
 */

import type {
  AccountRole,
  DecodedMessage,
  SplTransferOutflow,
  StaticOutflow,
  VerdictContext,
} from "./types.ts";
import { readU64LE, readU32LE } from "./classify.ts";

const SYSTEM_PROGRAM = "11111111111111111111111111111111";
const SPL_TOKEN = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const TOKEN_2022 = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";

const SPL_TRANSFER_DISC = 3;
const SPL_TRANSFER_CHECKED_DISC = 12;

export function computeOutflow(
  msg: DecodedMessage,
  roles: AccountRole[],
  ctx: VerdictContext,
): StaticOutflow {
  let lamports = 0n;
  const splTransfers: SplTransferOutflow[] = [];

  const signerIndexes = new Set(
    roles
      .filter((r) => r.role === "signer-writable" || r.role === "signer-readonly")
      .map((r) => r.index),
  );

  msg.instructions.forEach((ix, instructionIndex) => {
    if (ix.programId === SYSTEM_PROGRAM) {
      // Count SOL funded FROM the signer (account[0]) toward outflow so a large
      // amount trips the threshold:
      //   Transfer (2) / CreateAccount (0): lamports is a u64-LE at fixed offset 4.
      //   CreateAccountWithSeed (3): lamports is at a VARIABLE offset after the
      //     base pubkey + the seed string -> [tag(4)][base(32)][seedLen u64(8)]
      //     [seed bytes(seedLen)][lamports u64(8)]... so offset = 44 + seedLen.
      // WithdrawNonceAccount / TransferWithSeed also move SOL but from a
      // non-signer / seed-derived source, so they are flagged by the catalog
      // rather than counted here (to avoid mis-attributing them to the signer).
      if (ix.data.length >= 4) {
        const tag = readU32LE(ix.data, 0);
        const fundingIndex = ix.accountIndexes[0];
        const fromSigner =
          fundingIndex !== undefined && signerIndexes.has(fundingIndex);
        if (fromSigner) {
          if ((tag === 2 || tag === 0) && ix.data.length >= 12) {
            lamports += readU64LE(ix.data, 4);
          } else if (tag === 3 && ix.data.length >= 44) {
            const seedLen = Number(readU64LE(ix.data, 36));
            const lamportsOffset = 44 + seedLen;
            if (
              Number.isSafeInteger(seedLen) &&
              seedLen >= 0 &&
              ix.data.length >= lamportsOffset + 8
            ) {
              lamports += readU64LE(ix.data, lamportsOffset);
            }
          }
        }
      }
      return;
    }

    if (ix.programId === SPL_TOKEN || ix.programId === TOKEN_2022) {
      const disc = ix.data.length > 0 ? (ix.data[0] as number) : -1;
      // Transfer (C3):        [u8 3][u64 amount]            -> total 9 bytes
      // TransferChecked (C3): [u8 12][u64 amount][u8 dec]   -> total 10 bytes
      // The amount is u64-LE at offset 1 for BOTH, but the lengths and account
      // lists differ (TransferChecked adds the mint), so we validate the length
      // per discriminator and never conflate the two (C3, common bug #8).
      const isTransfer = disc === SPL_TRANSFER_DISC && ix.data.length >= 9;
      const isTransferChecked =
        disc === SPL_TRANSFER_CHECKED_DISC && ix.data.length >= 10;
      if (isTransfer || isTransferChecked) {
        const amount = readU64LE(ix.data, 1);
        splTransfers.push({
          instructionIndex,
          programId: ix.programId,
          amount: amount.toString(),
          ...(isTransferChecked ? { decimals: ix.data[9] as number } : {}),
        });
      }
    }
  });

  return {
    // Report lamports as a base-10 decimal STRING so the full u64+ range is
    // preserved exactly (a JS number would lose precision above 2^53). The
    // threshold comparison stays in BigInt for the same reason.
    lamports: lamports.toString(),
    splTransfers,
    exceedsLamportThreshold: lamports > BigInt(ctx.lamportThreshold),
  };
}
