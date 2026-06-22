/**
 * roles.ts -- PURE header math: derive each account's role.
 *
 * Solana's message header packs the privilege layout into three counts plus a
 * canonical key ordering. For the STATIC keys the layout is, in order:
 *
 *   [ 0 .. numRequiredSignatures - numReadonlySignedAccounts )      signer + writable
 *   [ .. numRequiredSignatures )                                    signer + readonly
 *   [ numRequiredSignatures .. N - numReadonlyUnsignedAccounts )    writable
 *   [ .. N )                                                        readonly
 *
 * where N = staticAccountKeys.length.
 *
 * For v0 ALT lookups we DO NOT trust the writable/readonly hint in the message:
 * resolving which concrete address sits at a table index requires fetching the
 * on-chain Address Lookup Table, which is a network operation we deliberately
 * never perform in the core. Every ALT-referenced account is therefore emitted
 * with role "unverified" and verified=false. The verdict layer treats the
 * presence of any unverified role as a hard bar against SIGN.
 */

import type { AccountRole, DecodedMessage, RoleKind } from "./types.ts";

export function deriveRoles(msg: DecodedMessage): AccountRole[] {
  const { numRequiredSignatures, numReadonlySignedAccounts, numReadonlyUnsignedAccounts } =
    msg.header;
  const n = msg.staticAccountKeys.length;

  const numWritableSigners = numRequiredSignatures - numReadonlySignedAccounts;
  const firstUnsignedReadonly = n - numReadonlyUnsignedAccounts;

  const roles: AccountRole[] = msg.staticAccountKeys.map((address, index) => {
    let role: RoleKind;
    if (index < numWritableSigners) {
      role = "signer-writable";
    } else if (index < numRequiredSignatures) {
      role = "signer-readonly";
    } else if (index < firstUnsignedReadonly) {
      role = "writable";
    } else {
      role = "readonly";
    }
    return { address, index, role, verified: true };
  });

  // Append synthetic, unverified entries for every ALT-referenced index, in
  // Solana's CANONICAL resolved order so that a synthetic role's index equals
  // the real runtime account index an instruction would use.
  //
  // Solana resolves the dynamic account list as:
  //   [ static keys ]
  //   [ ALL writable indexes, table-by-table in lookup order ]
  //   [ ALL readonly indexes, table-by-table in lookup order ]
  // i.e. a TWO-PASS layout: every table's writable entries come before ANY
  // table's readonly entries. The previous per-table interleaving
  // (writable+readonly of table 0, then table 1, ...) produced WRONG indexes
  // for multi-table v0 messages, so an instruction account index could not be
  // mapped back to the right synthetic role. We now match the canonical order.
  let altCursor = n;
  for (const lut of msg.addressTableLookups) {
    for (const w of lut.writableIndexes) {
      roles.push({
        address: `alt:${lut.accountKey}#w${w}`,
        index: altCursor++,
        role: "unverified",
        verified: false,
      });
    }
  }
  for (const lut of msg.addressTableLookups) {
    for (const r of lut.readonlyIndexes) {
      roles.push({
        address: `alt:${lut.accountKey}#r${r}`,
        index: altCursor++,
        role: "unverified",
        verified: false,
      });
    }
  }

  return roles;
}

/** True if any role in the message is "unverified" (i.e. ALT-sourced). */
export function hasUnverifiedRoles(roles: AccountRole[]): boolean {
  return roles.some((r) => r.role === "unverified");
}

/** Convenience: the signer accounts (writable or readonly) in header order. */
export function signerRoles(roles: AccountRole[]): AccountRole[] {
  return roles.filter(
    (r) => r.role === "signer-writable" || r.role === "signer-readonly",
  );
}

/** Convenience: is a given static index writable (signer or not)? */
export function isWritable(roles: AccountRole[], index: number): boolean {
  const r = roles[index];
  return r?.role === "signer-writable" || r?.role === "writable";
}
