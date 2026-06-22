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

import { DecodeError, decodeInput } from "./decode.ts";
import { deriveRoles, hasUnverifiedRoles, RESERVED_ACCOUNT_KEYS } from "./roles.ts";
import { classify } from "./classify.ts";
import { computeOutflow } from "./outflow.ts";
import { assertNoBannedPhrase, findBannedPhrase } from "./banned.ts";
import { isSquadsVaultExecute, decodeVaultTransaction } from "./squads.ts";
import { classifyInnerInstructions } from "./classify-inner.ts";
import {
  DEFAULT_CONTEXT,
  type Decision,
  type Finding,
  type Severity,
  type StaticOutflow,
  type Verdict,
  type VerdictContext,
} from "./types.ts";

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
  const innerAuthorityChange = findings.some((f) => INNER_AUTHORITY_FINDING_IDS.has(f.id));
  const anyAuthorityChange = authorityOrOwnershipChange || innerAuthorityChange;

  // V3 (the Drift signature): a durable-nonce carrier (marker at ix0) PLUS an
  // authority/ownership change is BLOCK/CRITICAL, independent of the individual
  // findings' severities. A held, non-expiring transaction that also hands over
  // authority is the exact ~$285M Drift blind-signing class -- it must REJECT
  // even when each piece in isolation would only be a HOLD.
  //
  // BROADENED: durable-nonce marker AND any of:
  //   - an authority/ownership change (top-level or inner), OR
  //   - worst severity >= HOLD (any non-INFO finding alongside a durable nonce), OR
  //   - an unknown program present (could hide any action)
  // ...also yields REJECT (Drift-class). A TRULY BARE durable nonce (no other
  // finding, no unknown program, no inner authority) stays HOLD unless
  // governanceContext is set.
  const hasNonInfoFindingBeyondNonce = findings.some(
    (f) => f.id !== "durable-nonce-advance" && (f.severity === "HOLD" || f.severity === "REJECT"),
  );
  const driftComposite =
    durableNonceMarker &&
    (anyAuthorityChange || hasNonInfoFindingBeyondNonce || unknownProgramPresent);

  // Governance policy: bare durable nonce is also REJECT under governanceContext.
  const governanceNonceReject = durableNonceMarker && governanceContext;

  let decision: Decision;
  let reason: string;

  if (worst === "REJECT" || unknownProgramWritable || driftComposite || governanceNonceReject) {
    decision = "REJECT";
    if (governanceNonceReject && !driftComposite && worst !== "REJECT" && !unknownProgramWritable) {
      reason =
        "Durable-nonce carrier (non-expiring transaction) rejected by governance policy: this signing context prohibits non-expiring transactions regardless of payload.";
    } else if (driftComposite) {
      // Build a detail string that names the inner-instruction danger when present.
      const innerAdminFinding = squadsInnerFindings.find((f) =>
        INNER_AUTHORITY_FINDING_IDS.has(f.id),
      );
      if (innerAdminFinding) {
        reason =
          `Durable-nonce carrier (non-expiring transaction) combined with an authority/ownership change via a Squads vault inner instruction (${innerAdminFinding.label}) -- the Drift blind-signing attack class. The dangerous instruction was hidden inside a Squads VaultTransaction PDA and executed via CPI, not visible in the signed top-level message. A signed message like this can be held and replayed to seize control later.`;
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
    } else if (worst === "REJECT" && unknownProgramWritable) {
      reason =
        "Contains a REJECT-class danger primitive and an unknown program writing to a value-bearing account.";
    } else if (worst === "REJECT") {
      const rej = findings.find((f) => f.severity === "REJECT");
      reason = `Contains a REJECT-class danger primitive: ${rej?.label ?? "unknown"}.`;
    } else {
      reason =
        "An unknown (uncatalogued) program writes to a value-bearing account; effect cannot be bounded.";
    }
  } else if (
    worst === "HOLD" ||
    unknownProgramPresent ||
    (altLookupsPresent && rolesUnverified) ||
    outflow.exceedsLamportThreshold
  ) {
    decision = "HOLD";
    const reasons: string[] = [];
    if (worst === "HOLD") {
      const holds = findings.filter((f) => f.severity === "HOLD").map((f) => f.label);
      reasons.push(`HOLD-class primitive(s): ${holds.join(", ")}`);
    }
    if (unknownProgramPresent) {
      reasons.push(`unknown program(s) present: ${unknownPrograms.join(", ")}`);
    }
    if (altLookupsPresent && rolesUnverified) {
      reasons.push(
        "address-lookup-table references are unresolved, so some account roles are unverified",
      );
    }
    if (outflow.exceedsLamportThreshold) {
      reasons.push(`declared SOL outflow ${outflow.lamports} lamports exceeds threshold`);
    }
    reason = `Manual review required: ${reasons.join("; ")}.`;
  } else {
    decision = "SIGN";
    reason =
      "Recognized instructions within thresholds; no danger primitives, unknown programs, or unverified ALT references. Not a guarantee of intent -- verify the recipients and amounts yourself.";
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
    reason: safeReason,
    messageVersion: "legacy",
    worstSeverity: "REJECT",
    findings: [],
    outflow: { lamports: "0", splTransfers: [], exceedsLamportThreshold: false },
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
    const { message: msg, inputWasFullTransaction, signatureCount } =
      decodeInput(b64);
    // Runtime-accurate writability: apply the SIMD-0105 reserved-account-keys
    // demotion (R5/R6). Both partition and runtime writability are exposed on
    // each role; the verdict consumes the runtime (demoted) mode.
    const roles = deriveRoles(msg, { reservedAccountKeys: RESERVED_ACCOUNT_KEYS });
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
        squadsInnerFindings = classifyInnerInstructions(decoded.instructions, ctx);
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
        label: "Squads VaultTransaction PDA: supplied bytes could not be decoded",
        severity: "HOLD",
        instructionIndex: -1,
        programId: "SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf",
        detail:
          "VaultTransaction PDA bytes were provided but failed to parse (malformed, truncated, or tampered). The inner instruction(s) executed via CPI are unknown. Do not sign until the PDA can be fetched and verified.",
        mapsToLoss:
          "A tampered or unreadable VaultTransaction PDA is indistinguishable from a hidden authority transfer or fund drain. Treat it as unverified.",
      });
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
