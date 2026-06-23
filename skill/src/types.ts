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

/**
 * A resolved or ALT-unresolved recipient reference.
 *
 * When the destination account index falls within the static key range,
 * `address` is the base58 public key and `addressUnresolved` is false.
 * When the account is sourced from an address-lookup-table (ALT), the
 * concrete address is unknown offline; `address` is null and
 * `addressUnresolved` is true (fail-closed: treat as external).
 */
export interface RecipientRef {
  /** Index into the message's full account-keys array. */
  index: number;
  /**
   * Base58 address when statically known; null for ALT-loaded accounts whose
   * address cannot be resolved offline.
   */
  address: string | null;
  /** True when the concrete address cannot be determined offline (ALT account). */
  addressUnresolved: boolean;
  /**
   * True when the recipient is NOT a signer of this message (i.e., funds are
   * being sent to an external party). False for self-transfers (signer pays
   * signer). Fail-closed: when addressUnresolved is true this is always true.
   */
  outboundToNonSigner: boolean;
}

/** A resolved lamport transfer with source and destination. */
export interface LamportTransfer {
  /** Index of the instruction that produced this transfer. */
  instructionIndex: number;
  /** Base58 address of the recipient, or null if ALT-unresolved. */
  to: string | null;
  /** True when the recipient address is ALT-sourced and cannot be resolved. */
  toUnresolved: boolean;
  /** Lamport amount as a base-10 decimal string. */
  amount: string;
  /** True when the recipient is NOT a signer of this message. */
  outboundToNonSigner: boolean;
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
  /**
   * Per-instruction lamport transfers, each with a resolved recipient address.
   * Populated only for System Transfer instructions whose funding account is
   * a signer. Additive — existing lamports/exceedsLamportThreshold math is
   * byte-identical.
   */
  lamportTransfers: LamportTransfer[];
  /**
   * True if ANY transfer (SOL or SPL) has a recipient that is NOT a signer of
   * this message (i.e., value is leaving to an external address). This flags
   * potential outbound value movement for policy enforcement.
   */
  outboundToNonSigner: boolean;
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
  /**
   * Resolved destination recipient for this SPL transfer.
   * Transfer (disc 3):        destination = accountIndexes[1]
   * TransferChecked (disc 12): destination = accountIndexes[2]  (mint is [1])
   */
  destination: RecipientRef;
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
   * Pre-resolved Address Lookup Table contents, keyed by the table account's
   * base58 address. Each value is the ordered list of base58 addresses stored
   * in that table (index 0 = first slot, matching the on-chain layout).
   *
   * When provided, `deriveRoles` can substitute real resolved addresses for
   * ALT-sourced accounts (setting `addressVerified=true`) instead of using the
   * synthetic `alt:<table>#wN/#rN` placeholders. Any table missing from the map,
   * or any index out of range, falls back to the unverified synthetic address
   * (fail-closed: the HOLD gate is preserved for anything we cannot verify).
   *
   * ESCALATE-ONLY invariant: supplying a MORE complete map can only raise the
   * information level (fewer unverified roles). An absent or partial map keeps
   * the prior conservative behavior (unverified => HOLD).
   *
   * Default: undefined (no resolution; behavior is byte-identical to pre-A2).
   *
   * Populated by the caller (e.g. enrich.ts) after on-chain table fetches.
   * The core never fetches tables itself (offline invariant).
   */
  resolvedAltTables?: ReadonlyMap<string, readonly string[]>;
  /**
   * When true, a bare durable-nonce transaction (even with no other finding)
   * is escalated to REJECT. This models a strict privileged-signing policy
   * where non-expiring transactions are never acceptable, regardless of
   * payload. Default false: a truly bare durable nonce (no other finding, no
   * unknown program) remains HOLD (a durable nonce can be legitimate for
   * offline cold-storage signing).
   */
  governanceContext?: boolean;
  /**
   * Optional set (or array) of known-bad base58 addresses (e.g. from Scam
   * Sniffer or a community drainer blocklist). When provided, any transfer
   * recipient, SPL Approve delegate, or SetAuthority new-authority that appears
   * in this list causes a REJECT finding "blocklisted-recipient".
   *
   * Default: undefined (no screening — verdict behavior is byte-identical).
   *
   * The blocklist is injected by the host or test; the core never fetches it.
   * To populate this at runtime, use enrich.ts reconRecipients().
   */
  recipientBlocklist?: ReadonlySet<string> | readonly string[];
  /**
   * When true, any outbound transfer (SOL or SPL) to a non-signer recipient
   * is escalated to at least HOLD. Self-transfers (signer pays signer) are
   * unaffected.
   *
   * Default: false — transfers stay at SIGN when no other finding escalates
   * them (existing behavior is unchanged).
   *
   * This models a strict "human-review-required for all external payments"
   * policy. Escalate-only: it never downgrades a REJECT or another HOLD.
   */
  holdOutboundTransfers?: boolean;
  /**
   * Pre-decoded Token-2022 mint extension danger metadata, keyed by the mint
   * account's base58 address. The value is the output of
   * `decodeMintDangerExtensions(mintAccountData)`.
   *
   * When provided, `reviewBase64` checks whether any mint that appears in the
   * transaction's touched mints/recipients has a `permanentDelegate` or
   * `transferHook` extension, and if so, pushes a HOLD finding explaining
   * that the holder's tokens can be moved or burned without their signature.
   *
   * ESCALATE-ONLY: absence of this map (or an absent entry for a mint) leaves
   * the verdict byte-identical to pre-A4. Providing the map can only ADD
   * findings, never remove or downgrade them.
   *
   * Populated by the caller (e.g. enrich.ts) after on-chain mint account
   * fetches. The core never fetches accounts itself (offline invariant).
   */
  mintExtensions?: ReadonlyMap<
    string,
    { permanentDelegate?: string; transferHook?: string; nonTransferable?: boolean }
  >;
  /**
   * When true, enables the maximal fail-closed posture for institutional or
   * high-value signers. Default false (standard two-tier default mode).
   *
   * DEFAULT mode (strict !== true):
   *   - Unknown program writing to a value-bearing account → HOLD (not REJECT).
   *     Unknown ≠ proven-malicious; HOLD still never SIGNs.
   *   - Drift composite: durable-nonce + (authority/ownership change OR a
   *     REJECT-class catalog finding) → REJECT. Durable-nonce combined with
   *     only a HOLD-class finding (unknown program, unknown instruction, etc.)
   *     → HOLD, not REJECT.
   *
   * STRICT mode (strict === true):
   *   - Unknown program writing to a value-bearing account → REJECT.
   *   - Drift composite uses the broad formula: durable-nonce + any non-INFO
   *     finding OR unknown program present → REJECT (today's aggressive posture).
   *
   * `strict` and `governanceContext` are independent flags; both can be set.
   * HOLD is always the minimum for any potential danger (never SIGN on risk).
   */
  strict?: boolean;
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
