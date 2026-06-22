/**
 * classify.ts -- PURE: each instruction x catalog -> Finding[].
 *
 * Matching is intentionally conservative and explicit:
 *   1. programId must match a catalog entry's programId exactly.
 *   2. the instruction's leading discriminator byte(s) must match.
 *
 * Discriminator note (see ../references/decode-notes.md): the native programs
 * in this catalog (System, SPL Token, Token-2022, BPF Loader Upgradeable) all
 * use a SINGLE leading byte (u8 for SPL/Token-2022, u32-le whose first byte is
 * the tag for System/BPF where the value is small enough that the first byte
 * is the discriminator). We match on the first byte. Anchor's 8-byte and
 * Pinocchio's 1-byte discriminators are discussed in decode-notes.md; none of
 * the catalogued primitives are Anchor instructions.
 *
 * The system-large-transfer entry is threshold-gated: a System Transfer only
 * becomes a HOLD finding when its lamport amount exceeds the context
 * threshold. That amount is parsed here from the instruction data so classify
 * and outflow agree on the same number.
 *
 * Any instruction whose programId is NOT in the known-program set produces an
 * "unknown-program" INFO/HOLD signal surfaced via collectUnknownPrograms (the
 * verdict layer escalates it); classify itself only emits catalog findings.
 */

import catalog from "../catalog/danger-primitives.json" with { type: "json" };
import type {
  AccountRole,
  CatalogEntry,
  DecodedMessage,
  Finding,
  VerdictContext,
} from "./types.ts";
import { isWritable } from "./roles.ts";

const ENTRIES = catalog.entries as CatalogEntry[];
const KNOWN_PROGRAMS = catalog.knownPrograms as Record<string, string>;

const SYSTEM_PROGRAM = "11111111111111111111111111111111";
const COMPUTE_BUDGET = "ComputeBudget111111111111111111111111111111";
const BPF_LOADER_UPGRADEABLE = "BPFLoaderUpgradeab1e11111111111111111111111";

/**
 * Programs whose instruction discriminator is a 4-byte little-endian u32 enum
 * index (Borsh-serialized Rust enum tag), NOT a single leading byte. Both the
 * System program and the BPF Loader Upgradeable program use this encoding, so
 * we must read the FULL u32 and validate the trailing 3 bytes are zero. Reading
 * only byte[0] would let a crafted payload (e.g. tag bytes [3, 1, 0, 0]) match
 * "Upgrade" (3) when it is actually a different/invalid instruction.
 */
const U32_TAG_PROGRAMS = new Set<string>([SYSTEM_PROGRAM, BPF_LOADER_UPGRADEABLE]);

/** Read a little-endian u64 from data at offset; returns a bigint. */
function readU64LE(data: Uint8Array, offset: number): bigint {
  if (offset + 8 > data.length) {
    throw new RangeError("instruction data too short for u64");
  }
  let v = 0n;
  for (let i = 0; i < 8; i++) {
    v |= BigInt(data[offset + i] as number) << BigInt(8 * i);
  }
  return v;
}

/** Read a little-endian u32 from data at offset; returns a number. */
function readU32LE(data: Uint8Array, offset: number): number {
  if (offset + 4 > data.length) {
    throw new RangeError("instruction data too short for u32");
  }
  return (
    (data[offset] as number) |
    ((data[offset + 1] as number) << 8) |
    ((data[offset + 2] as number) << 16) |
    ((data[offset + 3] as number) << 24)
  ) >>> 0;
}

/**
 * Read a 4-byte little-endian u32 enum-index discriminator (used by the System
 * program and the BPF Loader Upgradeable program). For Transfer that index is
 * 2, AdvanceNonceAccount is 4, BPF Upgrade is 3, BPF SetAuthority is 4, etc.
 * We read the full u32 so a small tag is never confused with a stray high byte.
 * Returns null if there are fewer than 4 bytes of data.
 */
function u32TagDiscriminator(data: Uint8Array): number | null {
  if (data.length < 4) return null;
  return readU32LE(data, 0);
}

/**
 * Human names for the specific discriminator tags inside multi-variant catalog
 * entries, so the finding detail distinguishes (e.g.) System InitializeNonce
 * (tag 6) from AuthorizeNonce (tag 7) rather than emitting one generic label.
 * Keyed by "<catalogId>:<tag>".
 */
const DISCRIMINATOR_NAMES: Record<string, string> = {
  "durable-nonce-initialize:6": "InitializeNonceAccount",
  "durable-nonce-initialize:7": "AuthorizeNonceAccount",
  "spl-approve-delegate:4": "Approve",
  "spl-approve-delegate:13": "ApproveChecked",
  "bpf-set-upgrade-authority:4": "SetAuthority",
};

/**
 * Build the factual `detail` string for a catalog finding. For multi-variant
 * entries (more than one accepted discriminator) we surface the exact decoded
 * tag and its variant name so the operator sees which sub-instruction matched
 * (e.g. nonce Initialize=6 vs Authorize=7). PURE.
 */
function buildDetail(
  entry: CatalogEntry,
  programLabel: string,
  u32Disc: number | null,
  byteDisc: number | null,
): string {
  const discs = entry.detection.discriminator ?? [];
  const tag = U32_TAG_PROGRAMS.has(entry.programId) ? u32Disc : byteDisc;
  if (discs.length > 1 && tag !== null) {
    const variant = DISCRIMINATOR_NAMES[`${entry.id}:${tag}`];
    const variantStr = variant ? ` (${variant})` : "";
    return `Matched ${entry.detection.instructionType} on ${programLabel}; instruction discriminator ${tag}${variantStr}.`;
  }
  return `Matched ${entry.detection.instructionType} on ${programLabel}.`;
}

export interface ClassifyResult {
  findings: Finding[];
  /** Programs encountered that are not in the known-program set. */
  unknownPrograms: string[];
  /** True if an unknown program touches a writable account (value-bearing). */
  unknownProgramWritable: boolean;
}

export function classify(
  msg: DecodedMessage,
  roles: AccountRole[],
  ctx: VerdictContext,
): ClassifyResult {
  const findings: Finding[] = [];
  const unknownPrograms = new Set<string>();
  let unknownProgramWritable = false;

  msg.instructions.forEach((ix, instructionIndex) => {
    const pid = ix.programId;

    // ComputeBudget is always benign metadata; never a danger, never unknown.
    if (pid === COMPUTE_BUDGET) return;

    if (!(pid in KNOWN_PROGRAMS)) {
      unknownPrograms.add(pid);
      // Does this unknown program touch any writable (value-bearing) account?
      //
      // Two cases both count as value-bearing, and BOTH must escalate to
      // REJECT:
      //   1. a static index that header math resolved to a writable role, OR
      //   2. an ALT-sourced index (>= number of static keys). Its concrete
      //      writability cannot be known without resolving the on-chain table,
      //      so we MUST treat it as potentially-writable. Treating an
      //      unresolved ALT account as readonly would let an attacker hide a
      //      writable target behind an ALT and downgrade an unknown-program
      //      REJECT into a mere HOLD -- the exact ALT-hiding attack this gate
      //      exists to stop. Fail-closed: unknown program + any ALT-sourced
      //      account => writable.
      const numStaticKeys = msg.staticAccountKeys.length;
      for (const accIdx of ix.accountIndexes) {
        if (accIdx >= numStaticKeys || isWritable(roles, accIdx)) {
          unknownProgramWritable = true;
          break;
        }
      }
      return; // unknown programs cannot match catalog entries
    }

    // Programs that use a 4-byte LE u32 enum tag (System, BPF Loader
    // Upgradeable) are matched on the FULL u32 -- never on byte[0] alone --
    // so a crafted payload like [3,1,0,0] cannot masquerade as tag 3.
    // Single-byte-discriminator programs (SPL Token, Token-2022) match byte[0].
    const usesU32Tag = U32_TAG_PROGRAMS.has(pid);
    const u32Disc = usesU32Tag ? u32TagDiscriminator(ix.data) : null;
    const byteDisc = ix.data.length > 0 ? (ix.data[0] as number) : null;

    for (const entry of ENTRIES) {
      if (entry.programId !== pid) continue;

      const matched = usesU32Tag
        ? u32Disc !== null &&
          (entry.detection.discriminator?.includes(u32Disc) ?? false)
        : byteDisc !== null &&
          (entry.detection.discriminator?.includes(byteDisc) ?? false);

      if (!matched) continue;

      // Threshold-gated entry: a System Transfer is only a finding when its
      // lamport amount exceeds the configured threshold.
      if (entry.id === "system-large-transfer") {
        const lamports = parseSystemTransferLamports(ix.data);
        if (lamports === null || lamports <= BigInt(ctx.lamportThreshold)) {
          continue; // below threshold -> not a danger finding
        }
        findings.push({
          id: entry.id,
          label: entry.label,
          severity: entry.severity,
          instructionIndex,
          programId: pid,
          detail: `System Transfer of ${lamports.toString()} lamports exceeds threshold ${ctx.lamportThreshold}.`,
          mapsToLoss: entry.mapsToLoss,
        });
        continue;
      }

      findings.push({
        id: entry.id,
        label: entry.label,
        severity: entry.severity,
        instructionIndex,
        programId: pid,
        detail: buildDetail(entry, KNOWN_PROGRAMS[pid] as string, u32Disc, byteDisc),
        mapsToLoss: entry.mapsToLoss,
      });
    }
  });

  return {
    findings,
    unknownPrograms: [...unknownPrograms],
    unknownProgramWritable,
  };
}

/**
 * Parse the lamport amount from a System Transfer instruction.
 * Layout: [u32 tag = 2][u64 lamports]. Returns null if not a Transfer.
 */
export function parseSystemTransferLamports(data: Uint8Array): bigint | null {
  if (data.length < 12) return null;
  if (readU32LE(data, 0) !== 2) return null;
  return readU64LE(data, 4);
}

/** Exposed for tests / outflow reuse. */
export { readU64LE, readU32LE };
