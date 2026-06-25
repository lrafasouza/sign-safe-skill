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
  LamportTransfer,
  RecipientRef,
  SplTransferOutflow,
  StaticOutflow,
  VerdictContext,
} from "./types.ts";
import { readU64LE, readU32LE } from "./classify.ts";

const SYSTEM_PROGRAM = "11111111111111111111111111111111";
const STAKE_PROGRAM = "Stake11111111111111111111111111111111111111";
const SPL_TOKEN = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const TOKEN_2022 = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";

const SPL_TRANSFER_DISC = 3;
const SPL_TRANSFER_CHECKED_DISC = 12;

function safeThreshold(ctx: VerdictContext): bigint {
  if (!Number.isSafeInteger(ctx.lamportThreshold)) {
    throw new Error("lamportThreshold must be an exact integer");
  }
  return BigInt(ctx.lamportThreshold);
}

/**
 * Resolve an account index to a RecipientRef. Static-key indices are resolved
 * to their base58 address directly. ALT-loaded indices (accountIndex >=
 * staticAccountKeys.length) are resolved via the `roles` array when
 * `roles[accountIndex].addressVerified` is true — meaning the caller supplied
 * `resolvedAltTables` and the slot is in range. If the ALT slot is NOT
 * resolved (addressVerified=false), we stay fail-closed: address=null,
 * addressUnresolved=true.
 *
 * INVARIANT: an address may be treated as `addressVerified` for the SIGN gate
 * ONLY IF it is simultaneously visible to outflow recipient resolution AND
 * blocklist screening. The `roles` array is the single source of truth for
 * both paths, ensuring they can never diverge.
 */
function resolveRecipient(
  accountIndex: number,
  msg: DecodedMessage,
  signerIndexes: Set<number>,
  roles: AccountRole[],
): RecipientRef {
  const isStatic = accountIndex < msg.staticAccountKeys.length;
  if (isStatic) {
    const address = msg.staticAccountKeys[accountIndex] ?? null;
    const outboundToNonSigner = !signerIndexes.has(accountIndex);
    return {
      index: accountIndex,
      address,
      addressUnresolved: false,
      outboundToNonSigner,
    };
  }

  // ALT-sourced account: consult the roles array (single source of truth).
  // roles[accountIndex] exists when deriveRoles was called and includes the
  // combined-list index covering ALT slots. When addressVerified=true, the
  // real resolved base58 address is in roles[accountIndex].address.
  const role = roles[accountIndex];
  if (role !== undefined && role.addressVerified) {
    // Real address known via resolvedAltTables — resolve it just like a
    // static key. It is NOT a signer (ALT slots are never signers).
    return {
      index: accountIndex,
      address: role.address,
      addressUnresolved: false,
      outboundToNonSigner: true, // ALT-sourced recipients are never signers
    };
  }

  // ALT-sourced account with no resolved address: fail-closed (outbound)
  return {
    index: accountIndex,
    address: null,
    addressUnresolved: true,
    outboundToNonSigner: true,
  };
}

export function computeOutflow(
  msg: DecodedMessage,
  roles: AccountRole[],
  ctx: VerdictContext,
): StaticOutflow {
  let lamports = 0n;
  const splTransfers: SplTransferOutflow[] = [];
  const lamportTransfers: LamportTransfer[] = [];

  const signerIndexes = new Set(
    roles
      .filter(
        (r) => r.role === "signer-writable" || r.role === "signer-readonly",
      )
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
          // System Transfer (tag=2): accounts are [from, to] → recipient = [1]
          // CreateAccount (tag=0): accounts are [from, new account] → recipient = [1]
          if ((tag === 2 || tag === 0) && ix.data.length >= 12) {
            const amount = readU64LE(ix.data, 4);
            lamports += amount;
            // Capture recipient for Transfer (tag=2); CreateAccount (tag=0) is
            // an account creation so we track it too for completeness.
            const recipientAccountIndex = ix.accountIndexes[1];
            if (recipientAccountIndex !== undefined) {
              const recipient = resolveRecipient(
                recipientAccountIndex,
                msg,
                signerIndexes,
                roles,
              );
              lamportTransfers.push({
                instructionIndex,
                to: recipient.address,
                toUnresolved: recipient.addressUnresolved,
                amount: amount.toString(),
                outboundToNonSigner: recipient.outboundToNonSigner,
              });
            }
          } else if (tag === 3 && ix.data.length >= 44) {
            const seedLen = Number(readU64LE(ix.data, 36));
            const lamportsOffset = 44 + seedLen;
            if (
              Number.isSafeInteger(seedLen) &&
              seedLen >= 0 &&
              ix.data.length >= lamportsOffset + 8
            ) {
              const amount = readU64LE(ix.data, lamportsOffset);
              lamports += amount;
              // CreateAccountWithSeed recipient = accounts[1]
              const recipientAccountIndex = ix.accountIndexes[1];
              if (recipientAccountIndex !== undefined) {
                const recipient = resolveRecipient(
                  recipientAccountIndex,
                  msg,
                  signerIndexes,
                  roles,
                );
                lamportTransfers.push({
                  instructionIndex,
                  to: recipient.address,
                  toUnresolved: recipient.addressUnresolved,
                  amount: amount.toString(),
                  outboundToNonSigner: recipient.outboundToNonSigner,
                });
              }
            }
          }
        }
      }
      return;
    }

    if (ix.programId === STAKE_PROGRAM) {
      if (ix.data.length >= 12 && readU32LE(ix.data, 0) === 4) {
        const amount = readU64LE(ix.data, 4);
        const recipientAccountIndex = ix.accountIndexes[1];
        if (recipientAccountIndex !== undefined) {
          const recipient = resolveRecipient(
            recipientAccountIndex,
            msg,
            signerIndexes,
            roles,
          );
          lamports += amount;
          lamportTransfers.push({
            instructionIndex,
            to: recipient.address,
            toUnresolved: recipient.addressUnresolved,
            amount: amount.toString(),
            outboundToNonSigner: recipient.outboundToNonSigner,
          });
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
      //
      // Account orderings (verified against solana-program/token interface):
      //   Transfer:        [source, destination, authority, ...]  → dst = [1]
      //   TransferChecked: [source, mint, destination, authority, ...] → dst = [2]
      const isTransfer = disc === SPL_TRANSFER_DISC && ix.data.length >= 9;
      const isTransferChecked =
        disc === SPL_TRANSFER_CHECKED_DISC && ix.data.length >= 10;
      if (isTransfer || isTransferChecked) {
        const amount = readU64LE(ix.data, 1);
        // Destination index: Transfer → accounts[1]; TransferChecked → accounts[2]
        const destAccountIndex = isTransferChecked
          ? ix.accountIndexes[2]
          : ix.accountIndexes[1];
        const destination =
          destAccountIndex !== undefined
            ? resolveRecipient(destAccountIndex, msg, signerIndexes, roles)
            : {
                index: -1,
                address: null,
                addressUnresolved: true,
                outboundToNonSigner: true,
              };
        splTransfers.push({
          instructionIndex,
          programId: ix.programId,
          amount: amount.toString(),
          ...(isTransferChecked ? { decimals: ix.data[9] as number } : {}),
          destination,
        });
      }
    }
  });

  const outboundToNonSigner =
    lamportTransfers.some((t) => t.outboundToNonSigner) ||
    splTransfers.some((t) => t.destination.outboundToNonSigner);

  return {
    // Report lamports as a base-10 decimal STRING so the full u64+ range is
    // preserved exactly (a JS number would lose precision above 2^53). The
    // threshold comparison stays in BigInt for the same reason.
    lamports: lamports.toString(),
    splTransfers,
    exceedsLamportThreshold: lamports > safeThreshold(ctx),
    lamportTransfers,
    outboundToNonSigner,
  };
}
