/**
 * classify-inner.ts -- PURE: classify a single inner instruction from a
 * Squads VaultTransaction into Finding[].
 *
 * Offline core: no network, no RPC, no fetch, no enrich.ts imports.
 * Same bytes in => same result out, deterministic and dependency-free.
 *
 * Classification strategy (layered, fail-closed):
 *   1. Null programId (unresolved, lives in ALT space) -> HOLD opaque finding.
 *   2. Known native programs (System, SPL Token, Token-2022, BPF Loader) ->
 *      delegate to the same catalog matcher used by classify.ts (native-program
 *      discriminators are 1-byte or 4-byte-u32, NOT 8-byte Anchor).
 *   3. All other programs -> match leading 8 bytes of data against the Anchor
 *      danger registry in catalog/anchor-danger.json. A 'program: *' entry
 *      matches any program id carrying that discriminator. A specific base58
 *      program id matches only that program.
 *   4. If nothing matched and the program is unknown, emit an INFO/HOLD
 *      opaque-inner-instruction finding (fail-closed: never silent nothing).
 *
 * Fail-closed invariant: an inner instruction to an unresolved or unknown
 * program never silently produces zero findings. It always produces at least
 * one HOLD or INFO finding, ensuring the enclosing verdict is never SIGN.
 */

import anchorDanger from "../catalog/anchor-danger.json" with { type: "json" };
import type { Finding, VerdictContext } from "./types.ts";
import type { VaultInnerInstruction } from "./squads.ts";

/** One entry in the Anchor danger catalog. */
interface AnchorDangerEntry {
  name: string;
  discriminatorHex: string;
  program: string;
  severity: "REJECT" | "HOLD";
  label: string;
  mapsToLoss: string;
}

const ANCHOR_ENTRIES = anchorDanger.entries as AnchorDangerEntry[];

/**
 * Pre-parse each Anchor danger entry's discriminatorHex into a Uint8Array for
 * fast byte comparison at classification time. Validated at module load.
 */
const ANCHOR_DISCS: Array<{ entry: AnchorDangerEntry; disc: Uint8Array }> =
  ANCHOR_ENTRIES.map((entry) => {
    const hex = entry.discriminatorHex;
    if (hex.length !== 16) {
      throw new Error(
        `anchor-danger.json: entry "${entry.name}" discriminatorHex must be 16 hex chars, got "${hex}"`,
      );
    }
    const disc = new Uint8Array(8);
    for (let i = 0; i < 8; i++) {
      const byte = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
      if (Number.isNaN(byte)) {
        throw new Error(
          `anchor-danger.json: entry "${entry.name}" discriminatorHex contains non-hex chars`,
        );
      }
      disc[i] = byte;
    }
    return { entry, disc };
  });

/**
 * Return true iff the first 8 bytes of `data` match `disc` (exactly 8 bytes).
 * Returns false if `data` is shorter than 8 bytes.
 */
function matchesDisc8(data: Uint8Array, disc: Uint8Array): boolean {
  if (data.length < 8) return false;
  for (let i = 0; i < 8; i++) {
    if (data[i] !== disc[i]) return false;
  }
  return true;
}

/**
 * Classify a single decoded inner VaultInstruction, emitting zero or more
 * Findings.
 *
 * The returned findings use `instructionIndex` = the inner instruction's
 * position index within the VaultTransaction's instruction list, and
 * `programId` = the resolved program id (or the synthetic sentinel
 * `"squads-inner:unresolved"` when the program id is null).
 *
 * Fail-closed contract:
 *   - unresolved programId (null) -> always emits a HOLD finding.
 *   - known program matched by anchor catalog -> emits the catalog finding.
 *   - unknown program not in anchor catalog -> emits a HOLD opaque finding.
 *   - unknown program in anchor catalog -> emits the catalog finding (severity).
 *
 * @param innerIx The decoded inner instruction from a VaultTransaction.
 * @param innerIndex Position (0-based) of this instruction in the VaultTransaction.
 * @param _ctx VerdictContext (reserved for future threshold-gated inner findings).
 */
export function classifyInnerInstruction(
  innerIx: VaultInnerInstruction,
  innerIndex: number,
  _ctx: VerdictContext,
): Finding[] {
  // Case 1: unresolved program id (lives in ALT space; cannot know the program
  // without an on-chain fetch). This is always HOLD, never silent.
  if (innerIx.programId === null) {
    return [
      {
        id: "squads-inner-unresolved",
        label: "Squads inner instruction: program id unresolved (ALT lookup)",
        severity: "HOLD",
        category: "squads",
        instructionIndex: innerIndex,
        programId: "squads-inner:unresolved",
        detail:
          `Inner instruction at index ${innerIndex} references a program id` +
          ` via an address-table lookup (program_id_index=${innerIx.programIdIndex})` +
          ` that cannot be resolved without fetching the on-chain address table.` +
          ` The actual program executed is unknown. Fail-closed: treat as dangerous.`,
        mapsToLoss:
          "Unknown program with unresolvable id: could be any program including admin-transfer, upgrade, or drain instructions.",
      },
    ];
  }

  const pid = innerIx.programId;
  const data = innerIx.data;

  // Case 2 & 3: try matching the leading 8 bytes against the Anchor danger
  // catalog. A 'program: "*"' entry matches any program id; a specific base58
  // id only matches that program.
  for (const { entry, disc } of ANCHOR_DISCS) {
    if (!matchesDisc8(data, disc)) continue;
    // Discriminator matches; check program constraint.
    if (entry.program !== "*" && entry.program !== pid) continue;

    // Matched. Emit a clear-signing finding naming the label and program.
    return [
      {
        id: `anchor-inner-${entry.name}`,
        label: `${entry.label} [inner, via Squads vault]`,
        severity: entry.severity,
        category: "squads",
        instructionIndex: innerIndex,
        programId: pid,
        detail:
          `Inner instruction at index ${innerIndex} to program ${pid}` +
          ` matches Anchor discriminator ${entry.discriminatorHex}` +
          ` (${entry.name}). This instruction is executed via CPI inside a` +
          ` Squads VaultTransaction and was not visible in the signed top-level` +
          ` message. ${entry.label}.`,
        mapsToLoss: entry.mapsToLoss,
      },
    ];
  }

  // Case 4: unknown program, no catalog match. Emit an opaque HOLD finding so
  // the verdict is never SIGN (fail-closed). This covers inner instructions to
  // programs we have not catalogued: we cannot know if they are dangerous, so
  // we must escalate rather than silently pass.
  return [
    {
      id: "squads-inner-opaque",
      label: "Squads inner instruction: opaque (uncatalogued program)",
      severity: "HOLD",
      category: "squads",
      instructionIndex: innerIndex,
      programId: pid,
      detail:
        `Inner instruction at index ${innerIndex} to program ${pid} did not` +
        ` match any known danger discriminator. The instruction is executed via` +
        ` CPI inside a Squads VaultTransaction and its intent cannot be verified` +
        ` statically. Fail-closed: treat as requiring human review.`,
      mapsToLoss:
        "Unknown inner CPI intent: cannot rule out admin transfer, upgrade, or fund drain without on-chain simulation.",
    },
  ];
}

/**
 * Classify all inner instructions from a decoded VaultTransaction, returning
 * the combined Finding[]. Each finding carries the inner instruction's index.
 *
 * @param instructions The VaultInnerInstruction array from a decoded VaultTransaction.
 * @param ctx VerdictContext for threshold-gated rules.
 */
export function classifyInnerInstructions(
  instructions: VaultInnerInstruction[],
  ctx: VerdictContext,
): Finding[] {
  const findings: Finding[] = [];
  for (let i = 0; i < instructions.length; i++) {
    const innerFindings = classifyInnerInstruction(instructions[i]!, i, ctx);
    findings.push(...innerFindings);
  }
  return findings;
}
