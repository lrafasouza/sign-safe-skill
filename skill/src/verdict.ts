/**
 * verdict.ts -- PURE: Finding[] + context -> Verdict (the verdict.json).
 *
 * Decision rules (deterministic; see ../references/verdict-contract.md):
 *
 *   REJECT if:
 *     - any Finding.severity === "REJECT", OR
 *     - decode failed (malformed/truncated input), OR
 *     - an unknown program is writable on a value-bearing account.
 *
 *   else HOLD if:
 *     - any Finding.severity === "HOLD", OR
 *     - any unknown program is present, OR
 *     - (altLookupsPresent && rolesUnverified), OR
 *     - staticOutflow.lamports > threshold.
 *
 *   else SIGN -- only when there are zero non-INFO findings, zero unknown
 *   programs, and no unverified ALT roles. The SIGN reason is ALWAYS qualified:
 *   it asserts recognized-instructions-within-thresholds, never intent safety.
 *
 * Worst-severity wins. This module never emits a reassuring phrase (see the
 * banned-phrase list in ../../rules/signing-output.md); reasons are factual.
 *
 * `reviewMessage` is the single offline entry point that chains
 * decode -> roles -> classify -> outflow -> verdict. It catches DecodeError
 * and returns a fail-closed REJECT verdict rather than throwing.
 */

import { DecodeError, decodeInput, base58Encode } from "./decode.ts";
import {
  deriveRoles,
  hasUnverifiedRoles,
  RESERVED_ACCOUNT_KEYS,
} from "./roles.ts";
import { classify } from "./classify.ts";
import { computeOutflow } from "./outflow.ts";
import { assertNoBannedPhrase, findBannedPhrase } from "./banned.ts";
import { isSquadsVaultExecute, decodeVaultTransaction } from "./squads.ts";
import { classifyInnerInstructions } from "./classify-inner.ts";
import { screenAddresses, type ScreenHit } from "./reputation.ts";
import {
  DEFAULT_CONTEXT,
  type AccountRole,
  type Decision,
  type DecodedMessage,
  type Finding,
  type Severity,
  type StaticOutflow,
  type Verdict,
  type VerdictContext,
} from "./types.ts";

/**
 * Format a lamport amount as a human-readable SOL string.
 * Keeps exact integer representation; shows SOL only when >= 1 SOL.
 */
function lamportsToDisplay(lamports: string): string {
  const n = BigInt(lamports);
  const sol = n / 1_000_000_000n;
  const rem = n % 1_000_000_000n;
  if (sol > 0n && rem === 0n) return `${sol} SOL`;
  if (sol > 0n) return `${lamports} lamports (~${sol} SOL)`;
  return `${lamports} lamports`;
}

/**
 * Build a short recipient summary string for SOL outflows in the SIGN reason.
 * Returns null if there is nothing to surface (no lamport transfers).
 */
function buildSignRecipientNote(outflow: StaticOutflow): string | null {
  const transfers = outflow.lamportTransfers;
  const splTransfers = outflow.splTransfers;
  const parts: string[] = [];

  for (const t of transfers) {
    const to = t.toUnresolved ? "unresolved ALT address" : (t.to ?? "unknown");
    parts.push(`sends ${lamportsToDisplay(t.amount)} to ${to}`);
  }

  for (const s of splTransfers) {
    const dst = s.destination;
    const to = dst.addressUnresolved
      ? "unresolved ALT address"
      : (dst.address ?? "unknown");
    parts.push(`sends ${s.amount} token units to ${to}`);
  }

  if (parts.length === 0) return null;
  return parts.join("; ") + ".";
}

/**
 * Build a short recipient summary for SOL outflow threshold HOLD reasons.
 * Returns null if there are no lamport transfers to surface.
 */
function buildLamportRecipientSummary(outflow: StaticOutflow): string | null {
  const transfers = outflow.lamportTransfers;
  if (transfers.length === 0) return null;
  const parts = transfers.map((t) => {
    const to = t.toUnresolved ? "unresolved ALT address" : (t.to ?? "unknown");
    return `to ${to}`;
  });
  return parts.join(", ");
}

// ─────────────────────────────────────────────────────────────────────────────
// Reputation screening helpers (PURE, offline)
// ─────────────────────────────────────────────────────────────────────────────

const SPL_TOKEN_PID = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const TOKEN_2022_PID = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";
const SYSTEM_PID = "11111111111111111111111111111111";

/**
 * Extract all addresses that should be screened against a blocklist from the
 * decoded message + computed outflow. Returns candidate objects for
 * screenAddresses(). PURE.
 *
 * Addresses collected:
 *   - Transfer recipients (SOL lamport transfers) → category "recipient"
 *   - SPL transfer destinations → category "recipient"
 *   - SPL Approve/ApproveChecked delegate (accounts[1] / accounts[2]) → "delegate"
 *   - SetAuthority new_authority from data (data[3..35]) → "new-authority"
 *   - System Assign new owner from data (data[4..36]) → "new-authority"
 *
 * The `roles` array (from deriveRoles) is used as the single source of truth
 * for resolving ALT-sourced account indices to real addresses. When an account
 * index falls in the ALT region AND roles[index].addressVerified is true, the
 * real resolved address is used instead of null — ensuring blocklist screening
 * covers all addresses that the SIGN gate considers verified.
 */
function collectScreenCandidates(
  msg: DecodedMessage,
  outflow: StaticOutflow,
  roles: AccountRole[],
): Array<{
  address: string | null;
  category: ScreenHit["category"];
  instructionIndex: number;
}> {
  const candidates: Array<{
    address: string | null;
    category: ScreenHit["category"];
    instructionIndex: number;
  }> = [];

  /**
   * Resolve an account index to a base58 address for screening purposes.
   * Uses roles as the single source of truth (same as outflow.ts) to ensure
   * blocklist screening and SIGN-gate address verification are always in sync.
   */
  function resolveForScreen(accountIndex: number): string | null {
    if (accountIndex < msg.staticAccountKeys.length) {
      return msg.staticAccountKeys[accountIndex] ?? null;
    }
    // ALT-sourced index: use resolved address from roles when verified.
    const role = roles[accountIndex];
    if (role !== undefined && role.addressVerified) {
      return role.address;
    }
    return null; // unresolved → skip (cannot screen offline)
  }

  // 1. SOL transfer recipients
  for (const t of outflow.lamportTransfers) {
    candidates.push({
      address: t.to,
      category: "recipient",
      instructionIndex: t.instructionIndex,
    });
  }

  // 2. SPL transfer destinations
  for (const s of outflow.splTransfers) {
    candidates.push({
      address: s.destination.address,
      category: "recipient",
      instructionIndex: s.instructionIndex,
    });
  }

  // 3. Scan instructions for Approve (disc 4) / ApproveChecked (disc 13)
  //    and SetAuthority (disc 6) on SPL Token / Token-2022, plus System Assign.
  msg.instructions.forEach((ix, instructionIndex) => {
    const pid = ix.programId;
    const data = ix.data;
    if (data.length === 0) return;

    const disc = data[0] as number;

    if (pid === SPL_TOKEN_PID || pid === TOKEN_2022_PID) {
      // Approve (disc=4): accounts[0]=source, accounts[1]=delegate, accounts[2]=owner
      // ApproveChecked (disc=13): accounts[0]=source, accounts[1]=mint, accounts[2]=delegate, accounts[3]=owner
      if (disc === 4 && data.length >= 9) {
        // Approve: delegate is accounts[1]
        const delegateIdx = ix.accountIndexes[1];
        const addr =
          delegateIdx !== undefined ? resolveForScreen(delegateIdx) : null;
        candidates.push({
          address: addr,
          category: "delegate",
          instructionIndex,
        });
      } else if (disc === 13 && data.length >= 10) {
        // ApproveChecked: delegate is accounts[2]
        const delegateIdx = ix.accountIndexes[2];
        const addr =
          delegateIdx !== undefined ? resolveForScreen(delegateIdx) : null;
        candidates.push({
          address: addr,
          category: "delegate",
          instructionIndex,
        });
      } else if (disc === 6 && data.length >= 3) {
        // SetAuthority (disc=6): new_authority in data bytes [3..35] when COption=Some (flag=1 at data[2])
        const optionFlag = data[2] as number;
        if (optionFlag === 1 && data.length >= 35) {
          const newAuthority = base58Encode(data.subarray(3, 35));
          candidates.push({
            address: newAuthority,
            category: "new-authority",
            instructionIndex,
          });
        }
      }
    } else if (pid === SYSTEM_PID && data.length >= 4) {
      // System Assign (u32 LE tag=1): new owner pubkey at data[4..36]
      const tag =
        ((data[0] as number) |
          ((data[1] as number) << 8) |
          ((data[2] as number) << 16) |
          ((data[3] as number) << 24)) >>>
        0;
      if (tag === 1 && data.length >= 36) {
        const newOwner = base58Encode(data.subarray(4, 36));
        candidates.push({
          address: newOwner,
          category: "new-authority",
          instructionIndex,
        });
      }
    }
  });

  return candidates;
}

/**
 * Convert ScreenHit[] produced by screenAddresses() into Finding[] entries
 * with severity REJECT. One finding per hit. PURE.
 */
function screenHitsToFindings(hits: ScreenHit[]): Finding[] {
  return hits.map((hit) => ({
    id: "blocklisted-recipient",
    label: `${hit.category === "delegate" ? "Delegate" : hit.category === "new-authority" ? "New authority" : "Recipient"} on the provided drainer blocklist: ${hit.address}`,
    severity: "REJECT" as const,
    category: "screening" as const,
    instructionIndex: hit.instructionIndex,
    programId: "",
    detail: `Address ${hit.address} (role: ${hit.category}) appears in the provided drainer blocklist. This is a known malicious address. Do not sign.`,
    mapsToLoss:
      "Sending value or authority to a known drainer/scammer address results in immediate, irreversible loss.",
  }));
}

const SEVERITY_RANK: Record<Severity, number> = { INFO: 0, HOLD: 1, REJECT: 2 };

function worstSeverity(findings: Finding[]): Severity {
  let worst: Severity = "INFO";
  for (const f of findings) {
    if (SEVERITY_RANK[f.severity] > SEVERITY_RANK[worst]) worst = f.severity;
  }
  return worst;
}

/**
 * Scan every human-facing narrative string in a verdict for banned
 * reassurance phrases and throw if any is present. We deliberately do NOT scan
 * machine identifiers (schema id, decision enum, programId base58, flag names)
 * or the SKILL's own hyphenated name -- only the prose fields a human or agent
 * would read as a judgement: reason, and each finding's label/detail/mapsToLoss.
 * PURE. Called as the last step before any Verdict is returned, so the gate can
 * never emit reassuring language; a violation fails loud (caller converts to a
 * fail-closed REJECT).
 */
function enforceBannedPhrases(v: Verdict): Verdict {
  assertNoBannedPhrase(v.reason, "verdict.reason");
  v.findings.forEach((f, i) => {
    assertNoBannedPhrase(f.label, `findings[${i}].label`);
    assertNoBannedPhrase(f.detail, `findings[${i}].detail`);
    assertNoBannedPhrase(f.mapsToLoss, `findings[${i}].mapsToLoss`);
  });
  return v;
}

/** Build a Verdict from already-computed components. PURE. */
export function buildVerdict(args: {
  messageVersion: "legacy" | 0;
  findings: Finding[];
  outflow: StaticOutflow;
  unknownPrograms: string[];
  unknownProgramWritable: boolean;
  altLookupsPresent: boolean;
  rolesUnverified: boolean;
  /** ix index 0 is System AdvanceNonceAccount (C17 durable-nonce marker). */
  durableNonceMarker?: boolean;
  /** Any authority/ownership-changing finding is present (V4). */
  authorityOrOwnershipChange?: boolean;
  /** Caller passed a full signed transaction; signatures were stripped. */
  inputWasFullTransaction?: boolean;
  /** Number of stripped signature slots (with inputWasFullTransaction). */
  signatureCount?: number;
  /**
   * True when any top-level instruction is a Squads vaultTransactionExecute
   * AND the inner VaultTransaction content was NOT provided. Forces HOLD/REJECT
   * (fail-closed: an unverified Squads proposal can hide any inner instruction).
   */
  squadsExecuteWithoutInner?: boolean;
  /**
   * Findings produced by classifying the inner instructions of a decoded
   * Squads VaultTransaction PDA. When present, these are folded into the
   * verdict (escalating severity). Only set when the VaultTransaction bytes
   * were provided offline (e.g. pre-fetched and supplied to the call).
   */
  squadsInnerFindings?: Finding[];
  /**
   * When true, even a truly bare durable-nonce transaction (no other finding,
   * no unknown program) is REJECT. Models a strict governance policy where
   * non-expiring transactions are never acceptable. Default false.
   */
  governanceContext?: boolean;
  /**
   * When true, enables the maximal fail-closed posture (strict mode).
   * See VerdictContext.strict for full documentation. Default false.
   */
  strict?: boolean;
}): Verdict {
  const {
    messageVersion,
    findings: topLevelFindings,
    outflow,
    unknownPrograms,
    unknownProgramWritable,
    altLookupsPresent,
    rolesUnverified,
    durableNonceMarker = false,
    authorityOrOwnershipChange = false,
    inputWasFullTransaction = false,
    signatureCount = 0,
    squadsExecuteWithoutInner = false,
    squadsInnerFindings = [],
    governanceContext = false,
    strict = false,
  } = args;

  // Merge top-level findings with any decoded Squads inner findings.
  // Inner findings carry instructionIndex relative to the VaultTransaction; that
  // is preserved as-is so operators can map them back.
  const findings: Finding[] = [...topLevelFindings, ...squadsInnerFindings];

  // When a vaultTransactionExecute is present but no inner bytes were provided,
  // inject a mandatory HOLD finding. This ensures we never silently SIGN a
  // Squads execute whose content we have not seen.
  if (squadsExecuteWithoutInner) {
    findings.push({
      id: "squads-execute-unverified",
      label: "Squads vaultTransactionExecute: inner content not provided",
      severity: "HOLD",
      category: "squads",
      instructionIndex: -1,
      programId: "SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf",
      detail:
        "A top-level Squads vaultTransactionExecute instruction is present but the VaultTransaction PDA bytes were not supplied. The inner instruction(s) executed via CPI are unknown. Fetch the VaultTransaction PDA to see what this proposal will execute before signing.",
      mapsToLoss:
        "Hidden inner instructions executed via Squads CPI can transfer admin authority, upgrade programs, or drain funds -- exactly the Drift blind-signing attack class.",
    });
  }

  const worst = worstSeverity(findings);
  const unknownProgramPresent = unknownPrograms.length > 0;

  // Does any finding (top-level OR inner) represent an authority/ownership change?
  const INNER_AUTHORITY_FINDING_IDS = new Set([
    "anchor-inner-update_admin",
    "anchor-inner-set_admin",
    "anchor-inner-transfer_admin",
    "anchor-inner-set_owner",
    "anchor-inner-transfer_ownership",
    "anchor-inner-set_authority",
    "anchor-inner-update_authority",
    "anchor-inner-set_upgrade_authority",
  ]);
  const innerAuthorityChange = findings.some((f) =>
    INNER_AUTHORITY_FINDING_IDS.has(f.id),
  );
  const anyAuthorityChange = authorityOrOwnershipChange || innerAuthorityChange;

  // V3 (the Drift signature): a durable-nonce carrier (marker at ix0) PLUS a
  // genuine danger triggers REJECT. Two modes differ in what "genuine danger" means:
  //
  // STRICT mode (strict === true) — current broad formula:
  //   durable-nonce + any non-INFO finding OR unknown program present => REJECT.
  //   This is the maximal fail-closed posture for institutional/high-value signers.
  //
  // DEFAULT mode (strict !== true) — narrowed formula:
  //   durable-nonce + (authority/ownership change OR a catalog REJECT-class finding
  //   whose id is not "durable-nonce-advance") => REJECT (genuine Drift class).
  //   durable-nonce + only HOLD-class findings (unknown program, unknown instruction,
  //   registered-program-unknown-instruction, etc.) => HOLD, not REJECT.
  //   This reduces the 4 Jupiter+nonce false-REJECTs to HOLD without sacrificing recall
  //   on real authority-change attacks.
  //
  // A TRULY BARE durable nonce (no other finding, no unknown program) stays HOLD
  // unless governanceContext is set (which escalates it to REJECT regardless of mode).

  const hasNonInfoFindingBeyondNonce = findings.some(
    (f) =>
      f.id !== "durable-nonce-advance" &&
      (f.severity === "HOLD" || f.severity === "REJECT"),
  );

  // "REJECT-class finding beyond nonce" used in DEFAULT mode: only findings whose
  // severity is REJECT AND that are not the durable-nonce marker itself.
  const hasRejectClassFindingBeyondNonce = findings.some(
    (f) => f.id !== "durable-nonce-advance" && f.severity === "REJECT",
  );

  // STRICT drift composite: broad formula (current / today's behavior).
  const driftCompositeStrict =
    durableNonceMarker &&
    (anyAuthorityChange ||
      hasNonInfoFindingBeyondNonce ||
      unknownProgramPresent);

  // DEFAULT drift composite: narrowed formula (only genuine Drift dangers).
  const driftCompositeDefault =
    durableNonceMarker &&
    (anyAuthorityChange || hasRejectClassFindingBeyondNonce);

  // Select the active drift composite based on mode.
  const driftComposite = strict ? driftCompositeStrict : driftCompositeDefault;

  // Governance policy: bare durable nonce is also REJECT under governanceContext.
  const governanceNonceReject = durableNonceMarker && governanceContext;

  // In DEFAULT mode, unknownProgramWritable → HOLD (not REJECT).
  // In STRICT mode, unknownProgramWritable → REJECT (legacy behavior).
  const unknownWritableReject = strict && unknownProgramWritable;
  const unknownWritableHold = !strict && unknownProgramWritable;

  let decision: Decision;
  let reason: string;

  if (
    worst === "REJECT" ||
    unknownWritableReject ||
    driftComposite ||
    governanceNonceReject
  ) {
    decision = "REJECT";
    if (
      governanceNonceReject &&
      !driftComposite &&
      worst !== "REJECT" &&
      !unknownWritableReject
    ) {
      reason =
        "Durable-nonce carrier (non-expiring transaction) rejected by governance policy: this signing context prohibits non-expiring transactions regardless of payload.";
    } else if (driftComposite) {
      // Build a detail string that names the inner-instruction danger when present.
      const innerAdminFinding = squadsInnerFindings.find((f) =>
        INNER_AUTHORITY_FINDING_IDS.has(f.id),
      );
      if (innerAdminFinding) {
        reason = `Durable-nonce carrier (non-expiring transaction) combined with an authority/ownership change via a Squads vault inner instruction (${innerAdminFinding.label}) -- the Drift blind-signing attack class. The dangerous instruction was hidden inside a Squads VaultTransaction PDA and executed via CPI, not visible in the signed top-level message. A signed message like this can be held and replayed to seize control later.`;
      } else if (anyAuthorityChange) {
        reason =
          "Durable-nonce carrier (non-expiring transaction) combined with an authority/ownership change -- the Drift blind-signing attack class. A signed message like this can be held and replayed to seize control later.";
      } else if (unknownProgramPresent) {
        reason =
          "Durable-nonce carrier (non-expiring transaction) combined with an unknown program -- inner effects cannot be bounded offline. A held, non-expiring transaction with an unverified program can be replayed at any time.";
      } else {
        reason =
          "Durable-nonce carrier (non-expiring transaction) combined with an unverified or dangerous instruction -- the Drift blind-signing attack class. A held, non-expiring transaction can be replayed at any time.";
      }
    } else if (worst === "REJECT" && unknownWritableReject) {
      reason =
        "Contains a REJECT-class danger primitive and an unknown program writing to a value-bearing account.";
    } else if (worst === "REJECT") {
      const rej = findings.find((f) => f.severity === "REJECT");
      reason = `Contains a REJECT-class danger primitive: ${rej?.label ?? "unknown"}.`;
    } else {
      // strict && unknownProgramWritable, no other REJECT finding
      reason =
        "An unknown (uncatalogued) program writes to a value-bearing account; effect cannot be bounded.";
    }
  } else if (
    worst === "HOLD" ||
    unknownWritableHold ||
    unknownProgramPresent ||
    (altLookupsPresent && rolesUnverified) ||
    outflow.exceedsLamportThreshold
  ) {
    decision = "HOLD";
    const reasons: string[] = [];
    if (worst === "HOLD") {
      const holds = findings
        .filter((f) => f.severity === "HOLD")
        .map((f) => f.label);
      reasons.push(`HOLD-class primitive(s): ${holds.join(", ")}`);
    }
    if (unknownWritableHold) {
      reasons.push(
        `unknown program writing to a value-bearing account: ${unknownPrograms.join(", ")} (use --strict to reject)`,
      );
    } else if (unknownProgramPresent) {
      reasons.push(`unknown program(s) present: ${unknownPrograms.join(", ")}`);
    }
    if (altLookupsPresent && rolesUnverified) {
      reasons.push(
        "address-lookup-table references are unresolved, so some account roles are unverified",
      );
    }
    if (outflow.exceedsLamportThreshold) {
      const recipientSummary = buildLamportRecipientSummary(outflow);
      if (recipientSummary) {
        reasons.push(
          `declared SOL outflow ${outflow.lamports} lamports exceeds threshold (${recipientSummary})`,
        );
      } else {
        reasons.push(
          `declared SOL outflow ${outflow.lamports} lamports exceeds threshold`,
        );
      }
    }
    reason = `Manual review required: ${reasons.join("; ")}.`;
  } else {
    decision = "SIGN";
    const signRecipientNote = buildSignRecipientNote(outflow);
    if (signRecipientNote) {
      reason = `Recognized instructions within thresholds; no danger primitives, unknown programs, or unverified ALT references. ${signRecipientNote} Not a guarantee of intent -- verify the recipients and amounts yourself.`;
    } else {
      reason =
        "Recognized instructions within thresholds; no danger primitives, unknown programs, or unverified ALT references. Not a guarantee of intent -- verify the recipients and amounts yourself.";
    }
  }

  // If the caller handed us a full signed transaction, say so plainly. The
  // signatures were never verified or reused -- only stripped so the inner
  // message could be analyzed. This note is factual, never reassuring.
  if (inputWasFullTransaction) {
    reason =
      `Input was a full signed transaction; analyzed the inner message ` +
      `(${signatureCount} signature slot(s) stripped, not verified). ` +
      reason;
  }

  const verdict: Verdict = {
    schema: "sign-safe/verdict@1",
    decision,
    requiresHumanReview: decision !== "SIGN",
    reason,
    messageVersion,
    worstSeverity: worst,
    findings,
    outflow,
    flags: {
      unknownProgramPresent,
      altLookupsPresent,
      rolesUnverified,
      decodeFailed: false,
    },
    unknownPrograms,
  };
  // Only attach these fields for a full-transaction input, so the common
  // bare-message verdict shape (and its golden fixtures) stays unchanged.
  if (inputWasFullTransaction) {
    verdict.inputWasFullTransaction = true;
    verdict.signatureCount = signatureCount;
  }
  return enforceBannedPhrases(verdict);
}

/**
 * The fail-closed verdict for input we could not parse (or any usage/IO error).
 * The decode-error message is sanitized so an adversarial input string cannot
 * smuggle a banned reassurance phrase into our narration: if the underlying
 * reason text itself contains a banned phrase, we drop it and emit a generic
 * fail-closed reason rather than echoing attacker-controlled prose.
 */
export function rejectVerdict(reason: string): Verdict {
  let safeReason = `Decode failed (fail-closed): ${reason}`;
  if (findBannedPhrase(safeReason) !== null) {
    safeReason =
      "Decode failed (fail-closed): input could not be parsed into a recognized message.";
  }
  return enforceBannedPhrases({
    schema: "sign-safe/verdict@1",
    decision: "REJECT",
    requiresHumanReview: true,
    reason: safeReason,
    messageVersion: "legacy",
    worstSeverity: "REJECT",
    findings: [],
    outflow: {
      lamports: "0",
      splTransfers: [],
      exceedsLamportThreshold: false,
      lamportTransfers: [],
      outboundToNonSigner: false,
    },
    flags: {
      unknownProgramPresent: false,
      altLookupsPresent: false,
      rolesUnverified: false,
      decodeFailed: true,
    },
    unknownPrograms: [],
  });
}

/**
 * Offline end-to-end review of a base64 message. NEVER throws on bad input:
 * a DecodeError becomes a REJECT verdict. The only path that could throw is a
 * genuine programming bug, which we also catch and convert to REJECT so the
 * gate is fail-closed by construction.
 *
 * Optional `vaultTransactionBytes`: when a top-level vaultTransactionExecute is
 * detected AND these bytes are provided, the VaultTransaction PDA is decoded
 * OFFLINE and its inner instructions classified, folding the findings into the
 * verdict. When a vaultTransactionExecute is present but these bytes are NOT
 * supplied, a mandatory HOLD finding is injected (fail-closed: never SIGN a
 * Squads execute whose inner content is unknown).
 */
export function reviewBase64(
  b64: string,
  ctx: VerdictContext = DEFAULT_CONTEXT,
  vaultTransactionBytes?: Uint8Array,
): Verdict {
  try {
    // Accept a bare base64 message OR a full signed transaction (signatures are
    // stripped, never verified). decodeInput is fail-closed: unparseable input
    // throws a DecodeError, which the catch below turns into a REJECT.
    const {
      message: msg,
      inputWasFullTransaction,
      signatureCount,
    } = decodeInput(b64);
    // Runtime-accurate writability: apply the SIMD-0105 reserved-account-keys
    // demotion (R5/R6). Both partition and runtime writability are exposed on
    // each role; the verdict consumes the runtime (demoted) mode.
    // When ctx.resolvedAltTables is provided, thread it through so ALT-sourced
    // accounts can be verified offline when the caller has pre-fetched tables.
    const roles = deriveRoles(msg, {
      reservedAccountKeys: RESERVED_ACCOUNT_KEYS,
      resolvedAltTables: ctx.resolvedAltTables,
    });
    const cls = classify(msg, roles, ctx);
    const outflow = computeOutflow(msg, roles, ctx);

    // Detect whether any top-level instruction is a Squads vaultTransactionExecute.
    const hasSquadsExecute = msg.instructions.some((ix) =>
      isSquadsVaultExecute(ix.programId, ix.data),
    );

    // Classify inner instructions from a provided VaultTransaction PDA (offline).
    let squadsInnerFindings: Finding[] | undefined;
    let squadsDecodeFailed = false;
    if (hasSquadsExecute && vaultTransactionBytes !== undefined) {
      try {
        const decoded = decodeVaultTransaction(vaultTransactionBytes);
        squadsInnerFindings = classifyInnerInstructions(
          decoded.instructions,
          ctx,
        );
      } catch (e) {
        // Decode failure of the vault transaction is fail-closed: treat as
        // unverified. We record the failure so operators can distinguish
        // "bytes supplied but malformed/tampered" from "no bytes provided".
        squadsInnerFindings = undefined;
        squadsDecodeFailed = true;
      }
    }

    // Build the top-level findings list, injecting a distinct diagnostic when
    // VaultTransaction bytes were supplied but could not be decoded -- so
    // operators can tell "bytes provided but malformed/tampered" from "no bytes
    // provided" (both are fail-closed HOLD, but the cause is now visible).
    const topLevelFindings: Finding[] = [...cls.findings];
    if (squadsDecodeFailed) {
      topLevelFindings.push({
        id: "squads-inner-decode-failed",
        label:
          "Squads VaultTransaction PDA: supplied bytes could not be decoded",
        severity: "HOLD",
        category: "squads",
        instructionIndex: -1,
        programId: "SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf",
        detail:
          "VaultTransaction PDA bytes were provided but failed to parse (malformed, truncated, or tampered). The inner instruction(s) executed via CPI are unknown. Do not sign until the PDA can be fetched and verified.",
        mapsToLoss:
          "A tampered or unreadable VaultTransaction PDA is indistinguishable from a hidden authority transfer or fund drain. Treat it as unverified.",
      });
    }

    // ── FEATURE 3a: Address-reputation screening (blocklist, PURE, offline) ──
    // When ctx.recipientBlocklist is provided, screen all transfer recipients,
    // Approve delegates, and SetAuthority new-authorities against it. Any hit
    // becomes a REJECT finding "blocklisted-recipient". No-op when no blocklist.
    if (ctx.recipientBlocklist !== undefined) {
      const blocklistSet: ReadonlySet<string> =
        ctx.recipientBlocklist instanceof Set
          ? ctx.recipientBlocklist
          : new Set(ctx.recipientBlocklist);

      const candidates = collectScreenCandidates(msg, outflow, roles);
      const hits = screenAddresses(candidates, blocklistSet);
      const reputationFindings = screenHitsToFindings(hits);
      topLevelFindings.push(...reputationFindings);
    }

    // ── FEATURE 3b: holdOutboundTransfers policy flag ──
    // When ctx.holdOutboundTransfers is true AND any transfer goes to a
    // non-signer recipient, inject a HOLD finding. Escalate-only: this finding
    // is a HOLD; it cannot downgrade a REJECT or override a higher-severity
    // finding already in place. Self-transfers (outboundToNonSigner=false) are
    // unaffected. Default (false) leaves transfer verdicts unchanged.
    if (ctx.holdOutboundTransfers && outflow.outboundToNonSigner) {
      topLevelFindings.push({
        id: "policy-outbound-transfer",
        label:
          "Outbound transfer to non-signer: manual review required by policy",
        severity: "HOLD",
        category: "policy",
        instructionIndex: -1,
        programId: "",
        detail:
          "This transaction sends value to at least one recipient that is not a signer of the message (an external address). The holdOutboundTransfers policy is enabled: all outbound transfers require manual review before signing.",
        mapsToLoss:
          "Outbound transfers to external addresses can move funds to an attacker if the recipient address is attacker-controlled.",
      });
    }

    const oversizedTokenTransfers = outflow.splTransfers.filter(
      (transfer) =>
        transfer.destination.outboundToNonSigner &&
        BigInt(transfer.amount) > BigInt(Number.MAX_SAFE_INTEGER),
    );
    for (const transfer of oversizedTokenTransfers) {
      topLevelFindings.push({
        id: "oversized-token-transfer",
        label:
          "Outbound token transfer exceeds the context-free safe integer range",
        severity: "HOLD",
        category: "value-outflow",
        instructionIndex: transfer.instructionIndex,
        programId: transfer.programId,
        detail:
          `This transaction sends ${transfer.amount} raw token units to a non-signer account. ` +
          `The amount exceeds JavaScript's exact safe-integer range and cannot be treated as a routine transfer without mint decimals and value context.`,
        mapsToLoss:
          "An extremely large raw token amount can represent a full-balance drain or an amount that downstream displays round incorrectly.",
      });
    }

    // ── FEATURE A4: Token-2022 mint extension danger screening ──
    // When ctx.mintExtensions is provided, check each mint address that is a KEY
    // in the map against the transaction's verified account roles. Because
    // permanent-delegate and transfer-hook danger is an INHERENT property of the
    // token mint (not specific to any one instruction), the screening fires
    // whenever the dangerous mint appears anywhere in the transaction's account
    // address set. Each (mint, extensionType) pair yields at most ONE finding
    // (de-duplicated). instructionIndex = -1 (tx-level / inherent property).
    // ESCALATE-ONLY: absence of the map leaves verdict byte-identical.
    if (ctx.mintExtensions !== undefined) {
      const mintExtMap = ctx.mintExtensions;
      const verifiedAccountSet = new Set(
        roles
          .filter((role) => role.addressVerified)
          .map((role) => role.address),
      );

      // Iterate in deterministic (sorted) order so findings are insertion-order
      // independent. Without sorting, Map iteration order (insertion order) can
      // produce different findings arrays for maps with the same entries.
      const sortedMintEntries = [...mintExtMap.entries()].sort(([a], [b]) =>
        a < b ? -1 : a > b ? 1 : 0,
      );

      for (const [mintAddr, exts] of sortedMintEntries) {
        if (!verifiedAccountSet.has(mintAddr)) continue; // mint not referenced in this tx

        if (exts.permanentDelegate !== undefined) {
          topLevelFindings.push({
            id: "token2022-permanent-delegate",
            label: `Token-2022 mint has a permanent delegate: ${mintAddr}`,
            severity: "HOLD",
            category: "token-2022-extension",
            instructionIndex: -1,
            programId: "",
            detail:
              `The mint ${mintAddr} has a PermanentDelegate extension ` +
              `(delegate: ${exts.permanentDelegate}). A permanent delegate can move or burn ` +
              `tokens from any holder's account irrevocably, without requiring the holder's signature. ` +
              `This is an inherent property of the token design, not this transaction specifically -- ` +
              `but it means your tokens are not exclusively under your control.`,
            mapsToLoss:
              "A permanent delegate can drain or burn your tokens at any time without your approval, " +
              "regardless of what this specific transaction does.",
          });
        }

        if (exts.transferHook !== undefined) {
          topLevelFindings.push({
            id: "token2022-transfer-hook",
            label: `Token-2022 mint has a transfer hook program: ${mintAddr}`,
            severity: "HOLD",
            category: "token-2022-extension",
            instructionIndex: -1,
            programId: "",
            detail:
              `The mint ${mintAddr} has a transfer hook extension (TransferHook) ` +
              `(hook program: ${exts.transferHook}). An arbitrary program runs on every transfer ` +
              `and can block, reject, or add fees to this transaction at runtime. ` +
              `The hook program is invoked as a CPI on every token transfer involving this mint.`,
            mapsToLoss:
              "A transfer hook program can block or alter token transfers, freeze accounts, or levy hidden fees.",
          });
        }
      }
    }

    // ── FEATURE P2: Simulation-based economic outflow findings ──
    // When ctx.simulation is provided (set by the host after simulateAssetDiff),
    // fold it into findings. ESCALATE-ONLY: simulation can only ADD findings.
    //
    // Cases:
    //   1. simulation.ok === false AND simulation was requested → HOLD
    //      "simulation-failed": economic outcome unverified.
    //   2. simulation.ok === true AND signer loses SOL/tokens to non-signers
    //      beyond what static analysis already flagged → HOLD "simulation-outflow"
    //      (REJECT if a blocklisted recipient is among sim outflows).
    if (ctx.simulation !== undefined) {
      const sim = ctx.simulation;
      if (!sim.ok) {
        // Simulation was requested but could not complete → fail-closed HOLD.
        topLevelFindings.push({
          id: "simulation-failed",
          label:
            "Transaction simulation requested but could not complete — economic outcome unverified",
          severity: "HOLD",
          category: "simulation",
          instructionIndex: -1,
          programId: "",
          detail:
            `A simulateTransaction call was requested to verify economic outcomes, but it failed: ` +
            (sim.err ?? "unknown error") +
            `. The actual token/SOL balances after signing cannot be verified. ` +
            `Do not sign when the economic outcome is unknown.`,
          mapsToLoss:
            "Unverified economic outcomes may hide swap-output manipulation, CPI-driven fund drains, " +
            "or other side effects not visible in the static instruction analysis.",
        });
      } else {
        // Simulation succeeded: check for SOL outflows to non-signers.
        const simHasOutflow =
          sim.outflowsToNonSigner.length > 0 ||
          sim.signerSolDelta < -BigInt(ctx.lamportThreshold);

        if (simHasOutflow) {
          // Determine severity: REJECT if any outflow recipient appears in the blocklist.
          let severity: Severity = "HOLD";
          if (ctx.recipientBlocklist !== undefined) {
            const blocklistSet: ReadonlySet<string> =
              ctx.recipientBlocklist instanceof Set
                ? ctx.recipientBlocklist
                : new Set(ctx.recipientBlocklist);
            const anyBlocklisted = sim.outflowsToNonSigner.some(
              (o) => o.to !== "_non-signer_" && blocklistSet.has(o.to),
            );
            if (anyBlocklisted) severity = "REJECT";
          }

          const solLoss =
            sim.signerSolDelta < 0n
              ? ` Net signer SOL delta: ${sim.signerSolDelta.toString()} lamports.`
              : "";
          const outflowCount = sim.outflowsToNonSigner.length;

          topLevelFindings.push({
            id: "simulation-outflow",
            label: `Simulation detected ${outflowCount} outflow(s) from signer to non-signer account(s)`,
            severity,
            category: "simulation",
            instructionIndex: -1,
            programId: "",
            detail:
              `Transaction simulation shows the signer's assets being transferred to ` +
              `non-signer account(s): ${outflowCount} outflow event(s) detected.` +
              solLoss +
              ` This may represent swap outputs, CPI-driven transfers, or other ` +
              `dynamic effects not fully visible in the static instruction analysis. ` +
              `Verify the recipients and amounts against your intent before signing.`,
            mapsToLoss:
              "Simulation-detected outflows to non-signers may represent fund drains, " +
              "manipulated swap outputs, or CPI transfers to attacker-controlled addresses.",
          });
        }
      }
    }

    return buildVerdict({
      messageVersion: msg.version,
      findings: topLevelFindings,
      outflow,
      unknownPrograms: cls.unknownPrograms,
      unknownProgramWritable: cls.unknownProgramWritable,
      altLookupsPresent: msg.altLookupsPresent,
      rolesUnverified: hasUnverifiedRoles(roles),
      durableNonceMarker: cls.durableNonceMarker,
      authorityOrOwnershipChange: cls.authorityOrOwnershipChange,
      inputWasFullTransaction,
      signatureCount,
      // Fail-closed: a Squads execute is "verified" only when the decoded vault
      // produced at least one inner finding to show the signer. A vault that
      // decodes to ZERO inner instructions (or that failed to decode, leaving
      // squadsInnerFindings === undefined) gives us nothing affirmative to
      // present, so it is treated exactly like a missing inner: the mandatory
      // HOLD is injected. Otherwise an empty-instruction VaultTransaction would
      // coast a Squads execute through to SIGN -- a fail-open.
      squadsExecuteWithoutInner:
        hasSquadsExecute &&
        (squadsInnerFindings === undefined || squadsInnerFindings.length === 0),
      squadsInnerFindings: squadsInnerFindings ?? [],
      governanceContext: ctx.governanceContext ?? false,
      strict: ctx.strict ?? false,
    });
  } catch (err) {
    const msg = err instanceof DecodeError ? err.message : String(err);
    return rejectVerdict(msg);
  }
}

/** Stable JSON serialization of a verdict (sorted-ish, deterministic). */
export function verdictToJson(v: Verdict): string {
  return JSON.stringify(v, jsonReplacer, 2);
}

/** Replacer that renders Uint8Array (in Finding-less paths) safely; reserved. */
function jsonReplacer(_key: string, value: unknown): unknown {
  if (value instanceof Uint8Array) {
    return Buffer.from(value).toString("hex");
  }
  return value;
}
