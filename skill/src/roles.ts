/**
 * roles.ts -- PURE header math: derive each account's role, with a TWO-LAYER
 * writability model that matches the runtime exactly.
 *
 * The Solana runtime decides writability in two stages:
 *
 *   1. PARTITION layer (`is_writable_index`, == `is_maybe_writable(i, None)`):
 *      pure positional math over the header counts and the combined-list
 *      ordering. For STATIC keys the layout is, in order:
 *
 *        [ 0 .. S-Rs )      signer + writable
 *        [ S-Rs .. S )      signer + readonly
 *        [ S .. K-Ru )      writable non-signer
 *        [ K-Ru .. K )      readonly non-signer
 *
 *      where S=numRequiredSignatures, Rs=numReadonlySignedAccounts,
 *      Ru=numReadonlyUnsignedAccounts, K=staticAccountKeys.length. For LOADED
 *      (ALT) accounts at combined index i >= K: writable iff (i - K) < W, where
 *      W = total writable_indexes flattened across all tables. (R3/R4.)
 *
 *   2. DEMOTION layer (`is_writable_internal` / `demote_program_id`): even when
 *      the partition layer says writable, the account is READONLY at runtime if
 *      EITHER (a) its key is in the reserved-account-keys set (SIMD-0105), OR
 *      (b) it is used as a `programIdIndex` by ANY instruction AND the
 *      upgradeable BPF loader is NOT present in the combined list. (R5.)
 *
 * BOTH modes are exposed on every AccountRole (`writablePartition` and
 * `writableRuntime`) so output is reproducible regardless of which mode a
 * verdict consumed (R6). With no reserved set supplied, `writableRuntime`
 * equals `writablePartition` (the runtime's `None` behaviour).
 *
 * ALT-loaded accounts: their concrete ADDRESS is unknown offline (it needs an
 * on-chain table fetch), so `addressVerified=false` and the address is a
 * synthetic `alt:<table>#wN/#rN` id. But their WRITABILITY is fully known from
 * ordering, so they get a real `writable`/`readonly` role -- NOT a collapsed
 * "unverified" bucket. The SIGN bar keys on `addressVerified` (R10/V7).
 */

import type { AccountRole, DecodedMessage, RoleKind, VerdictContext } from "./types.ts";

/**
 * BPF Loader Upgradeable program id. When it is present in the combined account
 * list, program-id demotion (R5b) does NOT apply (the loader CAN write to a
 * program account being upgraded). The "1" in "Upgradeab1e" is the digit one;
 * base58 has no letter "l"/"O"/"I"/"0".
 */
const BPF_LOADER_UPGRADEABLE = "BPFLoaderUpgradeab1e11111111111111111111111";

/**
 * The Incinerator is explicitly NOT reserved (SIMD-0105 / reserved-account-keys)
 * and MUST stay writable. It is excluded from the reserved set below precisely
 * so a naive "all 1...1 native-looking accounts are reserved" rule cannot wrongly
 * demote it. (R7.)
 */
export const INCINERATOR = "1nc1nerator11111111111111111111111111111111";

/**
 * The active reserved-account-keys set (SIMD-0105). These keys are READONLY at
 * runtime even when the partition math says writable. Native programs + the
 * standard sysvars. The Incinerator is deliberately ABSENT (R7). This set is
 * epoch/feature-gated on-chain; we pin the SIMD-0105 active set documented in
 * the spec (section R7 / docs.rs/solana-reserved-account-keys).
 */
export const RESERVED_ACCOUNT_KEYS: ReadonlySet<string> = new Set<string>([
  // Native programs
  "11111111111111111111111111111111", // System
  "Vote111111111111111111111111111111111111111", // Vote
  "Stake11111111111111111111111111111111111111", // Stake
  "StakeConfig11111111111111111111111111111111", // Stake config
  "Config1111111111111111111111111111111111111", // Config
  "Feature111111111111111111111111111111111111", // Feature
  "BPFLoader1111111111111111111111111111111111", // BPF loader (deprecated)
  "BPFLoader2111111111111111111111111111111111", // BPF loader 2 (standard)
  BPF_LOADER_UPGRADEABLE, // BPF loader upgradeable
  "NativeLoader1111111111111111111111111111111", // Native loader
  // Sysvars
  "SysvarC1ock11111111111111111111111111111111", // clock
  "SysvarEpochSchedu1e111111111111111111111111", // epoch_schedule
  "SysvarFees111111111111111111111111111111111", // fees
  "Sysvar1nstructions1111111111111111111111111", // instructions
  "SysvarRecentB1ockHashes11111111111111111111", // recent_blockhashes
  "SysvarRent111111111111111111111111111111111", // rent
  "SysvarRewards111111111111111111111111111111", // rewards
  "SysvarS1otHashes111111111111111111111111111", // slot_hashes
  "SysvarS1otHistory11111111111111111111111111", // slot_history
  "SysvarStakeHistory1111111111111111111111111", // stake_history
]);

export interface DeriveRolesOptions {
  /**
   * The reserved-account-keys set to apply for demotion (R5a). Supply
   * RESERVED_ACCOUNT_KEYS for runtime-accurate writability; omit (or pass
   * undefined) for the raw partition mode (`is_maybe_writable(i, None)`), in
   * which `writableRuntime === writablePartition`. (R6.)
   */
  reservedAccountKeys?: ReadonlySet<string>;
  /**
   * Pre-resolved ALT contents (table base58 -> ordered address list). When
   * provided and the table + index are in range, the synthetic
   * `alt:<table>#wN/#rN` address is replaced with the real resolved base58
   * address and `addressVerified` is set to true, allowing the SIGN gate to
   * pass when ALL ALT roles are verified. Absent or partial -> unverified
   * (fail-closed: HOLD preserved for anything we cannot verify). (A2.)
   */
  resolvedAltTables?: ReadonlyMap<string, readonly string[]>;
}

/**
 * is_writable_index (R4): the pure partition layer. `combinedIndex` is the index
 * into the combined list (static keys ++ ALT-writable ++ ALT-readonly).
 */
export function isWritableIndex(
  combinedIndex: number,
  args: {
    numRequiredSignatures: number;
    numReadonlySignedAccounts: number;
    numReadonlyUnsignedAccounts: number;
    numStaticKeys: number;
    numLoadedWritable: number;
  },
): boolean {
  const {
    numRequiredSignatures: S,
    numReadonlySignedAccounts: Rs,
    numReadonlyUnsignedAccounts: Ru,
    numStaticKeys: K,
    numLoadedWritable: W,
  } = args;

  if (combinedIndex >= K) {
    // Loaded (ALT) account: writable iff it falls in the flattened writable run.
    return combinedIndex - K < W;
  }
  if (combinedIndex >= S) {
    // Unsigned static: writable iff before the readonly-unsigned tail.
    return combinedIndex - S < K - S - Ru;
  }
  // Signed static: writable iff before the readonly-signers tail.
  return combinedIndex < S - Rs;
}

export function deriveRoles(
  msg: DecodedMessage,
  opts: DeriveRolesOptions = {},
): AccountRole[] {
  const {
    numRequiredSignatures: S,
    numReadonlySignedAccounts: Rs,
    numReadonlyUnsignedAccounts: Ru,
  } = msg.header;
  const K = msg.staticAccountKeys.length;
  const reserved = opts.reservedAccountKeys;
  const resolvedAltTables = opts.resolvedAltTables;

  // W = total writable ALT indexes flattened across all tables (R1).
  let W = 0;
  for (const lut of msg.addressTableLookups) W += lut.writableIndexes.length;

  // Programs called by any instruction, by combined index (R5b). An index used
  // as a programIdIndex is "called as a program"; in practice these are always
  // static (programs are not ALT-sourced in our decoder), but we key on the
  // combined index to stay faithful to the rule.
  const calledAsProgram = new Set<number>();
  for (const ix of msg.instructions) calledAsProgram.add(ix.programIdIndex);

  // Upgradeable loader present anywhere in the combined list? If so, program-id
  // demotion does NOT apply (R5b). Static keys are the only thing we can name;
  // an ALT account COULD be the loader, but offline we cannot know, so we only
  // consider static keys here (fail toward demotion = readonly, the safe side).
  const upgradeableLoaderPresent =
    msg.staticAccountKeys.includes(BPF_LOADER_UPGRADEABLE);

  const idxArgs = {
    numRequiredSignatures: S,
    numReadonlySignedAccounts: Rs,
    numReadonlyUnsignedAccounts: Ru,
    numStaticKeys: K,
    numLoadedWritable: W,
  };

  function buildRole(
    address: string,
    combinedIndex: number,
    isSigner: boolean,
    addressVerified: boolean,
    keyForReservedCheck: string | null,
  ): AccountRole {
    const writablePartition = isWritableIndex(combinedIndex, idxArgs);

    // Demotion (R5). Only evaluable when a reserved set is supplied (R6).
    let writableRuntime = writablePartition;
    if (writablePartition && reserved) {
      const reservedHit =
        keyForReservedCheck !== null && reserved.has(keyForReservedCheck);
      const programDemote =
        calledAsProgram.has(combinedIndex) && !upgradeableLoaderPresent;
      if (reservedHit || programDemote) writableRuntime = false;
    }

    let role: RoleKind;
    if (isSigner) {
      role = writableRuntime ? "signer-writable" : "signer-readonly";
    } else {
      role = writableRuntime ? "writable" : "readonly";
    }

    return {
      address,
      index: combinedIndex,
      role,
      writablePartition,
      writableRuntime,
      demotedToReadonly: writablePartition && !writableRuntime,
      verified: addressVerified,
      addressVerified,
    };
  }

  const roles: AccountRole[] = msg.staticAccountKeys.map((address, index) =>
    buildRole(address, index, index < S, true, address),
  );

  // Append loaded (ALT) accounts in Solana's CANONICAL resolved order: ALL
  // writable across tables (in lookup order), THEN all readonly across tables
  // (R1/R11). A two-pass layout -- never per-table interleaving -- so a
  // synthetic role's combined index equals the runtime account index an
  // instruction would use.
  //
  // When resolvedAltTables is provided and the table+index are in range, use
  // the real resolved address with addressVerified=true and apply the reserved-
  // key demotion path (same as static keys). When absent or out-of-range, fall
  // back to the synthetic `alt:<table>#wN/#rN` address with
  // addressVerified=false (fail-closed: HOLD gate preserved). (A2.)
  let altCursor = K;
  for (const lut of msg.addressTableLookups) {
    const resolvedTable = resolvedAltTables?.get(lut.accountKey);
    for (const w of lut.writableIndexes) {
      const resolvedAddr =
        resolvedTable !== undefined && w < resolvedTable.length
          ? (resolvedTable[w] ?? null)
          : null;
      if (resolvedAddr !== null) {
        // Real address known: apply reserved-key demotion.
        roles.push(buildRole(resolvedAddr, altCursor++, false, true, resolvedAddr));
      } else {
        // Address unknown offline: synthetic id, no demotion.
        roles.push(
          buildRole(`alt:${lut.accountKey}#w${w}`, altCursor++, false, false, null),
        );
      }
    }
  }
  for (const lut of msg.addressTableLookups) {
    const resolvedTable = resolvedAltTables?.get(lut.accountKey);
    for (const r of lut.readonlyIndexes) {
      const resolvedAddr =
        resolvedTable !== undefined && r < resolvedTable.length
          ? (resolvedTable[r] ?? null)
          : null;
      if (resolvedAddr !== null) {
        // Real address known: apply reserved-key demotion.
        roles.push(buildRole(resolvedAddr, altCursor++, false, true, resolvedAddr));
      } else {
        // Address unknown offline: synthetic id, no demotion.
        roles.push(
          buildRole(`alt:${lut.accountKey}#r${r}`, altCursor++, false, false, null),
        );
      }
    }
  }

  return roles;
}

/**
 * True if any role has an unverified concrete ADDRESS (i.e. ALT-sourced). This
 * is the SIGN bar (R10/V7): we never know an ALT account's identity offline.
 * Renamed concept: it is the ADDRESS that is unverified, not the role.
 */
export function hasUnverifiedRoles(roles: AccountRole[]): boolean {
  return roles.some((r) => !r.addressVerified);
}

/** Convenience: the signer accounts (writable or readonly) in header order. */
export function signerRoles(roles: AccountRole[]): AccountRole[] {
  return roles.filter(
    (r) => r.role === "signer-writable" || r.role === "signer-readonly",
  );
}

/**
 * Convenience: is a given combined index writable at RUNTIME (after demotion)?
 * Returns true for ALT-loaded writable-region indices too (their writability is
 * known from ordering even though their address is not) -- so an ALT-loaded
 * writable account is correctly surfaced as writable.
 */
export function isWritable(roles: AccountRole[], index: number): boolean {
  const r = roles[index];
  return r?.writableRuntime ?? false;
}
