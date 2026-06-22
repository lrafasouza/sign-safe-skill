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

/**
 * How an account participates in the transaction.
 *
 * IMPORTANT: this is the *writability* axis, and for ALT-loaded accounts it IS
 * determinable offline from message ordering (R1/R4/R11 in the spec): the v0
 * writable_indexes-vs-readonly_indexes placement decides it with no per-account
 * flag and no network. Only the concrete ADDRESS of an ALT account is unknown
 * offline -- that is tracked separately by `addressVerified`, NOT by collapsing
 * the role to a single "unverified" bucket. Conflating "address unknown" with
 * "role unknown" loses information the runtime determines purely from ordering.
 */
export type RoleKind =
  | "signer-writable"
  | "signer-readonly"
  | "writable"
  | "readonly";

/** A single account in the message, with its statically-derived role. */
export interface AccountRole {
  /** Base58 program/account address, or a synthetic "alt:<table>#<index>" id. */
  address: string;
  index: number;
  /**
   * The runtime writability class. For ALT-loaded accounts this reflects the
   * writable/readonly region the index falls in (writable region => "writable",
   * readonly region => "readonly"), which IS known offline.
   */
  role: RoleKind;
  /**
   * Raw partition writability: `is_writable_index(i)` == `is_maybe_writable(i,
   * None)`. The header/ordering math BEFORE demotion (R4/R6). Always known
   * offline (even for ALT accounts).
   */
  writablePartition: boolean;
  /**
   * Runtime writability AFTER demotion (R5/R6): partition writability AND NOT a
   * reserved key AND NOT (called-as-program with the upgradeable loader absent).
   * Equal to `writablePartition` when no reserved set is supplied. For ALT
   * accounts we cannot know the concrete key, so program-id demotion never
   * applies to them and reserved-key demotion cannot be evaluated; their
   * runtime writability equals their partition writability.
   */
  writableRuntime: boolean;
  /** True iff `writablePartition && !writableRuntime` (R5 demoted this index). */
  demotedToReadonly: boolean;
  /** True only for static header keys; ALT-sourced keys are never trusted. */
  verified: boolean;
  /**
   * Whether the CONCRETE on-chain address at this index is known offline. True
   * for static keys; false for ALT-loaded accounts (their address requires
   * fetching the on-chain table). The SIGN bar keys on this (R10/V7), not on
   * writability being unknown -- because writability is NOT unknown.
   */
  addressVerified: boolean;
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
  /**
   * Decimals u8 from a TransferChecked (disc 12) instruction. Present only for
   * TransferChecked (a plain Transfer carries no decimals in its data). (C3.)
   */
  decimals?: number;
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
  /**
   * Present ONLY when the caller passed a FULL signed transaction
   * (`signatures || message`) instead of a bare message: the signature slots
   * were stripped (never verified) and the inner message analyzed. Omitted for
   * the common bare-message case so that verdict shape is unchanged.
   */
  inputWasFullTransaction?: boolean;
  /** Number of stripped signature slots (only set with inputWasFullTransaction). */
  signatureCount?: number;
}

/** Tunable context for the verdict (kept explicit so tests are deterministic). */
export interface VerdictContext {
  /** Lamport threshold above which a System Transfer is a HOLD finding. */
  lamportThreshold: number;
  /**
   * When true, a bare durable-nonce transaction (even with no other finding)
   * is escalated to REJECT. This models a strict privileged-signing policy
   * where non-expiring transactions are never acceptable, regardless of
   * payload. Default false: a truly bare durable nonce (no other finding, no
   * unknown program) remains HOLD (a durable nonce can be legitimate for
   * offline cold-storage signing).
   */
  governanceContext?: boolean;
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
    /**
     * For Token-2022 extension instructions, the OUTER tag (byte 0) selects an
     * extension and a SECOND byte selects the sub-instruction. When present, the
     * byte at index 1 must also be in this list for the entry to match -- so a
     * config sub-instruction under the same extension tag is not mis-flagged.
     */
    subDiscriminator?: number[];
  };
  severity: Severity;
  mapsToLoss: string;
}
