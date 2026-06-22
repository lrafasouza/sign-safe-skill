/**
 * Shared contract types for the sign-safe deterministic core.
 *
 * Every module in src/ (except enrich.ts, which is impure and never imported
 * by the core or tests) speaks in terms of these interfaces. The data flow is:
 *
 *   bytes -> decode.ts   -> DecodedMessage
 *   DecodedMessage -> roles.ts -> AccountRole[]
 *   DecodedMessage + roles -> classify.ts -> Finding[]
 *   DecodedMessage + roles -> outflow.ts -> StaticOutflow
 *   Finding[] + context -> verdict.ts -> Verdict (+ verdict.json)
 *
 * All of the above are PURE: no network, no RPC, no simulation, no clock,
 * no randomness. Same bytes in => same JSON out, forever.
 */

/** The three terminal decisions the gate can emit. Ordered by severity. */
export type Decision = "SIGN" | "HOLD" | "REJECT";

/** Finding severity. INFO never escalates a verdict on its own. */
export type Severity = "INFO" | "HOLD" | "REJECT";

/** How an account participates in the transaction, from the message header. */
export type RoleKind =
  | "signer-writable"
  | "signer-readonly"
  | "writable"
  | "readonly"
  /**
   * The account is only referenced through an Address Lookup Table. Its
   * writable/signer status cannot be determined from the message bytes alone
   * (it requires resolving the on-chain ALT), so we conservatively mark it
   * "unverified". The presence of any unverified role forbids a SIGN verdict.
   */
  | "unverified";

/** A single account in the message, with its statically-derived role. */
export interface AccountRole {
  /** Base58 program/account address, or a synthetic "alt:<table>#<index>" id. */
  address: string;
  index: number;
  role: RoleKind;
  /** True only for static header keys; ALT-sourced keys are never trusted. */
  verified: boolean;
}

/** One compiled instruction, with indices resolved to base58 addresses. */
export interface DecodedInstruction {
  /** Index into the account-keys array identifying the program. */
  programIdIndex: number;
  /** Base58 program id. */
  programId: string;
  /** Indices into the account-keys array for this instruction's accounts. */
  accountIndexes: number[];
  /** Raw instruction data bytes. */
  data: Uint8Array;
}

/** A v0 address-table-lookup entry (legacy messages have none). */
export interface AddressTableLookup {
  /** Base58 address of the lookup table account. */
  accountKey: string;
  writableIndexes: number[];
  readonlyIndexes: number[];
}

/** Fully parsed message (legacy or v0), independent of @solana/web3.js. */
export interface DecodedMessage {
  version: "legacy" | 0;
  header: {
    numRequiredSignatures: number;
    numReadonlySignedAccounts: number;
    numReadonlyUnsignedAccounts: number;
  };
  /** Static account keys, in canonical order (signers first). */
  staticAccountKeys: string[];
  recentBlockhash: string;
  instructions: DecodedInstruction[];
  /** v0 only; empty for legacy. */
  addressTableLookups: AddressTableLookup[];
  /** True if any addressTableLookups are present (v0 with ALTs). */
  altLookupsPresent: boolean;
}

/** A matched danger primitive (or an INFO note) against one instruction. */
export interface Finding {
  /** Catalog id, or a synthetic id for unknown-program / threshold findings. */
  id: string;
  label: string;
  severity: Severity;
  /** Index of the instruction that produced this finding. */
  instructionIndex: number;
  programId: string;
  /** Short, factual explanation. Never reassuring language. */
  detail: string;
  /** Real-loss mapping copied from the catalog (or a built-in note). */
  mapsToLoss: string;
}

/** Statically-declared, signer-perspective SOL/SPL outflow. */
export interface StaticOutflow {
  /**
   * Sum of System Transfer lamports where the signer is the funding source,
   * as a base-10 DECIMAL STRING. A string (not a JS number) because lamport
   * sums can exceed 2^53 (~9,007,199 SOL) and silently lose precision as a
   * double; the verdict and threshold math must stay exact at full u64+ range.
   */
  lamports: string;
  /**
   * SPL token transfer amounts (transfer / transferChecked) in base units,
   * keyed by nothing more than order of appearance. We cannot know decimals
   * or mint statically for plain `transfer`, so these are raw amounts.
   */
  splTransfers: SplTransferOutflow[];
  /** True if lamports exceeded the configured large-transfer threshold. */
  exceedsLamportThreshold: boolean;
}

export interface SplTransferOutflow {
  instructionIndex: number;
  programId: string;
  /** Raw base-unit amount from the instruction data. */
  amount: string;
}

/** The machine-readable verdict. This is the verdict.json contract. */
export interface Verdict {
  /** Schema version for the verdict.json contract. */
  schema: "sign-safe/verdict@1";
  decision: Decision;
  /** Qualified, non-reassuring reason string. */
  reason: string;
  messageVersion: "legacy" | 0;
  /** Worst severity observed across all findings. */
  worstSeverity: Severity;
  findings: Finding[];
  outflow: StaticOutflow;
  flags: {
    unknownProgramPresent: boolean;
    altLookupsPresent: boolean;
    rolesUnverified: boolean;
    /** True when input could not be parsed; forces REJECT. */
    decodeFailed: boolean;
  };
  /** Programs seen that are not in the recognized set. */
  unknownPrograms: string[];
}

/** Tunable context for the verdict (kept explicit so tests are deterministic). */
export interface VerdictContext {
  /** Lamport threshold above which a System Transfer is a HOLD finding. */
  lamportThreshold: number;
}

export const DEFAULT_CONTEXT: VerdictContext = {
  // 1 SOL, per the danger catalog's system-large-transfer default.
  lamportThreshold: 1_000_000_000,
};

/** Catalog entry shape, mirrored from catalog/danger-primitives.json. */
export interface CatalogEntry {
  id: string;
  label: string;
  program: string;
  programId: string;
  detection: {
    instructionType: string;
    /** Accepted leading discriminator byte(s). Omitted => program-id match. */
    discriminator?: number[];
  };
  severity: Severity;
  mapsToLoss: string;
}
