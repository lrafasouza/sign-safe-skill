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

import { DecodeError, decodeBase64Message } from "./decode.ts";
import { deriveRoles, hasUnverifiedRoles, RESERVED_ACCOUNT_KEYS } from "./roles.ts";
import { classify } from "./classify.ts";
import { computeOutflow } from "./outflow.ts";
import { assertNoBannedPhrase, findBannedPhrase } from "./banned.ts";
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
}): Verdict {
  const {
    messageVersion,
    findings,
    outflow,
    unknownPrograms,
    unknownProgramWritable,
    altLookupsPresent,
    rolesUnverified,
    durableNonceMarker = false,
    authorityOrOwnershipChange = false,
  } = args;

  const worst = worstSeverity(findings);
  const unknownProgramPresent = unknownPrograms.length > 0;

  // V3 (the Drift signature): a durable-nonce carrier (marker at ix0) PLUS an
  // authority/ownership change is BLOCK/CRITICAL, independent of the individual
  // findings' severities. A held, non-expiring transaction that also hands over
  // authority is the exact ~$285M Drift blind-signing class -- it must REJECT
  // even when each piece in isolation would only be a HOLD.
  const driftComposite = durableNonceMarker && authorityOrOwnershipChange;

  let decision: Decision;
  let reason: string;

  if (worst === "REJECT" || unknownProgramWritable || driftComposite) {
    decision = "REJECT";
    if (driftComposite) {
      reason =
        "Durable-nonce carrier (non-expiring transaction) combined with an authority/ownership change -- the Drift blind-signing attack class. A signed message like this can be held and replayed to seize control later.";
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

  return enforceBannedPhrases({
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
  });
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
 */
export function reviewBase64(
  b64: string,
  ctx: VerdictContext = DEFAULT_CONTEXT,
): Verdict {
  try {
    const msg = decodeBase64Message(b64);
    // Runtime-accurate writability: apply the SIMD-0105 reserved-account-keys
    // demotion (R5/R6). Both partition and runtime writability are exposed on
    // each role; the verdict consumes the runtime (demoted) mode.
    const roles = deriveRoles(msg, { reservedAccountKeys: RESERVED_ACCOUNT_KEYS });
    const cls = classify(msg, roles, ctx);
    const outflow = computeOutflow(msg, roles, ctx);
    return buildVerdict({
      messageVersion: msg.version,
      findings: cls.findings,
      outflow,
      unknownPrograms: cls.unknownPrograms,
      unknownProgramWritable: cls.unknownProgramWritable,
      altLookupsPresent: msg.altLookupsPresent,
      rolesUnverified: hasUnverifiedRoles(roles),
      durableNonceMarker: cls.durableNonceMarker,
      authorityOrOwnershipChange: cls.authorityOrOwnershipChange,
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
