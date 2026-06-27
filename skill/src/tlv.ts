/**
 * tlv.ts -- PURE Token-2022 mint/account TLV extension walker (C8/C9/C10/V5) plus
 * a danger-tier decoder for mint account extensions (A4).
 *
 * `decodeMintDangerExtensions` extracts the subset of Token-2022 TLV extensions
 * that materially change transfer risk for the token holder:
 *
 *   PermanentDelegate (type 12): delegate can move/burn from any holder
 *   TransferHook      (type 14): arbitrary program runs on every transfer
 *   NonTransferable   (type  9): marker only; token cannot be transferred
 *
 * Reuses walkTlv() so the TLV parse is single-implementation. PURE: no network,
 * no RPC. Must be called with already-fetched account data (fetching is in enrich.ts).
 *
 * Token-2022 extensions live in the mint/account TLV, NOT the instruction
 * stream: a transfer of a permanent-delegate / transfer-hook / fee token is
 * byte-identical to a vanilla transfer at the instruction level (C9). To know
 * the danger you MUST inspect the on-chain account data. Fetching that data is
 * an online operation (enrich.ts); THIS module is the pure decoder that runs on
 * already-fetched bytes, so it stays offline and deterministic and is fully
 * testable with synthetic fixtures.
 *
 * Layout (C10):
 *   base Mint    = 82 bytes (BASE_MINT_LENGTH)
 *   base Account = 165 bytes (BASE_ACCOUNT_LENGTH)
 *   account_type byte at offset 165: Uninitialized=0x00, Mint=0x01, Account=0x02
 *   TLV entries start at offset 166; each entry =
 *     type: u16-LE (2 bytes) + length: u16-LE (2 bytes) + value (length bytes)
 *   A plain 82-byte mint or 165-byte account has NO account_type byte and NO
 *   extensions -- do NOT read offset 165 on those. Walk ALL TLV entries.
 */

import { base58Encode } from "./decode.ts";

const BASE_ACCOUNT_LENGTH = 165;
const ACCOUNT_TYPE_OFFSET = 165;
const TLV_START = 166;

/** ExtensionType u16 values (C8). Subset that the verdict cares about (V5). */
export const EXTENSION_TYPE_NAMES: Record<number, string> = {
  0: "Uninitialized",
  1: "TransferFeeConfig",
  2: "TransferFeeAmount",
  3: "MintCloseAuthority",
  4: "ConfidentialTransferMint",
  5: "ConfidentialTransferAccount",
  6: "DefaultAccountState",
  7: "ImmutableOwner",
  8: "MemoTransfer",
  9: "NonTransferable",
  10: "InterestBearingConfig",
  11: "CpiGuard",
  12: "PermanentDelegate",
  13: "NonTransferableAccount",
  14: "TransferHook",
  15: "TransferHookAccount",
  16: "ConfidentialTransferFeeConfig",
  17: "ConfidentialTransferFeeAmount",
  18: "MetadataPointer",
  19: "TokenMetadata",
  20: "GroupPointer",
  21: "TokenGroup",
  22: "GroupMemberPointer",
  23: "TokenGroupMember",
  24: "ConfidentialMintBurn",
  25: "ScaledUiAmount",
  26: "Pausable",
  27: "PausableAccount",
  28: "PermissionedBurn",
};

/**
 * Extensions whose presence makes a byte-identical "plain Transfer" dangerous or
 * misleading (V5). Maps ExtensionType u16 -> a factual danger note.
 */
export const DANGEROUS_EXTENSIONS: Record<number, string> = {
  1: "TransferFeeConfig: a fee is skimmed on transfer, so the recipient receives LESS than the displayed amount.",
  6: "DefaultAccountState: new token accounts may be frozen by default, blocking transfers.",
  9: "NonTransferable: the token cannot be transferred by ordinary holders.",
  10: "InterestBearingConfig: the displayed UI amount differs from the raw on-chain balance.",
  12: "PermanentDelegate: a permanent delegate can move or burn tokens from ANY holder irrevocably -- a seizure vector even on a plain transfer.",
  14: "TransferHook: an arbitrary program runs on every transfer and can block or alter it.",
  16: "ConfidentialTransferFeeConfig: confidential-transfer fees apply.",
  25: "ScaledUiAmount: the displayed UI amount is scaled and differs from the raw u64.",
  26: "Pausable: transfers can be globally paused by an authority.",
};

export interface TlvEntry {
  extensionType: number;
  name: string;
  length: number;
  valueOffset: number;
}

export type AccountTypeByte = "uninitialized" | "mint" | "account" | "none";

export interface TlvWalkResult {
  /** The account_type byte interpretation (or "none" for a base-length account). */
  accountType: AccountTypeByte;
  entries: TlvEntry[];
  /** Subset of entries that are in DANGEROUS_EXTENSIONS, with notes. */
  dangerous: Array<{ extensionType: number; name: string; note: string }>;
}

/**
 * Walk the TLV of a fetched Token-2022 mint/account data buffer. PURE. Returns
 * { accountType: "none", entries: [] } for base-length (82 mint / 165 account)
 * accounts which carry no extensions. Throws on a malformed TLV (a length that
 * runs past the buffer) -- fail-closed: a truncated TLV is not "no extensions".
 */
export function walkTlv(data: Uint8Array): TlvWalkResult {
  // A classic SPL-Token mint (82) or a base account (165) has no account_type
  // byte and no extensions. Anything at/above 166 carries the account_type byte
  // + TLV region. Between 83..165 is a non-extension account; treat as none.
  if (data.length <= ACCOUNT_TYPE_OFFSET) {
    return { accountType: "none", entries: [], dangerous: [] };
  }
  if (data.length < TLV_START) {
    // Exactly at the account_type byte but no room for TLV entries.
    return {
      accountType: readAccountType(data[ACCOUNT_TYPE_OFFSET]!),
      entries: [],
      dangerous: [],
    };
  }

  const accountType = readAccountType(data[ACCOUNT_TYPE_OFFSET]!);
  const entries: TlvEntry[] = [];
  let offset = TLV_START;
  while (offset + 4 <= data.length) {
    const extensionType = data[offset]! | (data[offset + 1]! << 8);
    const length = data[offset + 2]! | (data[offset + 3]! << 8);
    // ExtensionType 0 (Uninitialized) as the FIRST 2 bytes marks end-of-TLV
    // padding in practice; stop walking on a zero type with zero length.
    if (extensionType === 0 && length === 0) break;
    const valueOffset = offset + 4;
    if (valueOffset + length > data.length) {
      throw new Error(
        `TLV entry type ${extensionType} length ${length} runs past buffer (offset ${valueOffset}, len ${data.length})`,
      );
    }
    entries.push({
      extensionType,
      name: EXTENSION_TYPE_NAMES[extensionType] ?? `unknown(${extensionType})`,
      length,
      valueOffset,
    });
    offset = valueOffset + length;
  }

  const dangerous = entries
    .filter((e) => e.extensionType in DANGEROUS_EXTENSIONS)
    .map((e) => ({
      extensionType: e.extensionType,
      name: e.name,
      note: DANGEROUS_EXTENSIONS[e.extensionType]!,
    }));

  return { accountType, entries, dangerous };
}

function readAccountType(byte: number): AccountTypeByte {
  if (byte === 0x00) return "uninitialized";
  if (byte === 0x01) return "mint";
  if (byte === 0x02) return "account";
  return "none";
}

// ---------------------------------------------------------------------------
// A4: Danger-tier mint extension decoder
// ---------------------------------------------------------------------------

/** ExtensionType constants for the danger-tier decoder. */
const EXT_NON_TRANSFERABLE = 9; // NonTransferable: marker extension (zero-length value)
const EXT_PERMANENT_DELEGATE = 12; // PermanentDelegate: 32-byte delegate pubkey
const EXT_TRANSFER_HOOK = 14; // TransferHook: authority(32) + programId(32) = 64 bytes

/**
 * Returns true if every byte in the slice is 0x00.
 * Used to interpret OptionalNonZeroPubkey: an all-zero 32-byte pubkey means
 * None (no delegate / no hook program) in SPL Token-2022.
 */
function isAllZero(bytes: Uint8Array): boolean {
  for (const b of bytes) {
    if (b !== 0) return false;
  }
  return true;
}

/**
 * Decoded danger-tier extensions from a Token-2022 mint account.
 *
 * Only the three extension types that materially affect transfer risk for the
 * token holder are surfaced here; all others are silently ignored.
 */
export interface MintDangerExtensions {
  /**
   * Base58 permanent delegate pubkey (ExtensionType 12). When present, the
   * delegate can move or burn tokens from ANY holder without their signature --
   * the defining Token-2022 seizure vector.
   */
  permanentDelegate?: string;
  /**
   * Base58 transfer-hook programId (ExtensionType 14). When present, an
   * arbitrary program runs on every transfer and can block, alter, or add fees.
   */
  transferHook?: string;
  /**
   * True when the NonTransferable marker (ExtensionType 9) is present. The
   * token cannot be transferred by ordinary holders.
   */
  nonTransferable?: boolean;
}

/**
 * Extract danger-tier Token-2022 extension metadata from a mint account's raw
 * data buffer. PURE and OFFLINE: operates on already-fetched bytes.
 *
 * Reuses walkTlv() for the TLV walk. Only PermanentDelegate (type 12),
 * TransferHook (type 14), and NonTransferable (type 9) are decoded; all other
 * extension types are ignored. Returns an empty object for a plain 82-byte SPL
 * mint (no extensions). FAIL-CLOSED: walkTlv throws on malformed TLV.
 *
 * Extension value layouts (per solana-program/token-2022 source):
 *   PermanentDelegate (type 12): value = Pubkey(32)
 *   TransferHook      (type 14): value = [authority Pubkey(32)][programId Pubkey(32)]
 *   NonTransferable   (type  9): value = [] (zero-length marker)
 */
export function decodeMintDangerExtensions(
  mintAccountData: Uint8Array,
): MintDangerExtensions {
  // walkTlv handles the base-length (no TLV) and malformed cases for us.
  const { entries } = walkTlv(mintAccountData);
  const result: MintDangerExtensions = {};

  for (const entry of entries) {
    switch (entry.extensionType) {
      case EXT_PERMANENT_DELEGATE:
        // Value is a 32-byte OptionalNonZeroPubkey.
        // An all-zero pubkey means None (no delegate) -- do NOT surface it.
        if (entry.length >= 32) {
          const pubkeyBytes = mintAccountData.subarray(
            entry.valueOffset,
            entry.valueOffset + 32,
          );
          if (!isAllZero(pubkeyBytes)) {
            result.permanentDelegate = base58Encode(pubkeyBytes);
          }
        }
        break;

      case EXT_TRANSFER_HOOK:
        // Value is [authority OptionalNonZeroPubkey(32)][programId OptionalNonZeroPubkey(32)].
        // If the programId (bytes [32..64)) is all-zero, the hook is not active -- do NOT surface.
        if (entry.length >= 64) {
          const programIdBytes = mintAccountData.subarray(
            entry.valueOffset + 32,
            entry.valueOffset + 64,
          );
          if (!isAllZero(programIdBytes)) {
            result.transferHook = base58Encode(programIdBytes);
          }
        }
        break;

      case EXT_NON_TRANSFERABLE:
        // Zero-length marker: presence alone is enough.
        result.nonTransferable = true;
        break;

      default:
        // All other extension types are ignored here.
        break;
    }
  }

  return result;
}
