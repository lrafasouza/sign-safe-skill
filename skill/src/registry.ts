/**
 * registry.ts -- PURE: recognized non-native DeFi/NFT program registry.
 *
 * Loads program-registry.json and provides fast lookups for:
 *   - isRegisteredProgram(pid): is this program in the registry?
 *   - matchInstruction(pid, data): returns kind "dangerous"|"safe"|"unknown" + entry.
 *   - matchDangerousInstruction(pid, data): legacy compat wrapper.
 *
 * DISCRIMINATOR SCHEME INVARIANTS (verified against canonical sources):
 *
 *   beet-u8   — Metaplex Token Metadata: single leading u8 (beet serialization).
 *               Discriminators verified per-instruction in the generated JS client.
 *   anchor-8  — Bubblegum, Jupiter v6, Orca, Pump.fun, Pump AMM, Raydium CLMM/CPMM,
 *               Drift, Kamino klend, Meteora DLMM: 8-byte Anchor discriminator
 *               (sha256("global:<snake_case_instruction_name>")[0..8]).
 *               All anchor-8 discriminators are verified by the self-checking test
 *               registry-discriminators.test.ts which computes sha256 at test time.
 *   raydium-u8 — Raydium AMM v4: single leading u8.
 *
 * FAIL-CLOSED CONTRACT:
 *   - A recognized program with a SAFE instruction -> INFO (no escalation).
 *     A tx of only safe + benign system/token/compute ix within thresholds -> SIGN.
 *   - A recognized program with a DANGEROUS instruction -> its severity (HOLD/REJECT).
 *   - A recognized program with an UNRECOGNIZED instruction -> HOLD
 *     ("recognized-unknown-instruction"), NEVER SIGN.
 *   - Safe classification can NEVER override a danger finding elsewhere, an unknown
 *     program, an unresolved ALT, or a threshold breach.
 *   - An unregistered program is NOT touched here; the caller falls through
 *     to the existing unknown-program path (REJECT when writable).
 *   - Recognition ONLY ADDS / ESCALATES severity. It can never turn a
 *     value-moving or dangerous instruction into SIGN.
 *
 * No network. No imports from enrich.ts. Same bytes in => same JSON out.
 */

import registryData from "../catalog/program-registry.json" with { type: "json" };

export interface RegistryDangerEntry {
  /** Discriminator hex string (2 chars for beet-u8, 16 chars for anchor-8). */
  discHex: string;
  /** Canonical snake_case instruction name (anchor-8 only; used in self-verifying test). */
  ixName?: string;
  /** Human-readable label for the finding. */
  label: string;
  /** Severity: HOLD or REJECT. */
  severity: "HOLD" | "REJECT";
  /** Concrete real-loss mapping. */
  mapsToLoss: string;
}

export interface RegistrySafeEntry {
  /** Discriminator hex string (2 chars for beet-u8, 16 chars for anchor-8). */
  discHex: string;
  /** Canonical snake_case instruction name (anchor-8 only; used in self-verifying test). */
  ixName?: string;
  /** Human-readable label for this safe instruction (shown as INFO to the signer). */
  label: string;
}

export interface RegistryProgram {
  id: string;
  name: string;
  programId: string;
  discriminatorScheme: "beet-u8" | "anchor-8" | "raydium-u8";
  safeInstructions: RegistrySafeEntry[];
  dangerousInstructions: RegistryDangerEntry[];
}

/**
 * Result of matchInstruction(): what kind of instruction is this?
 *   - "dangerous": found in dangerousInstructions; `dangerEntry` is set.
 *   - "safe": found in safeInstructions; `safeEntry` is set.
 *   - "unknown": recognized program but instruction not listed in either list.
 *               Must HOLD (fail-closed).
 * Returns undefined when programId is not in the registry.
 */
export type MatchResult =
  | { kind: "dangerous"; dangerEntry: RegistryDangerEntry; safeEntry?: undefined }
  | { kind: "safe"; safeEntry: RegistrySafeEntry; dangerEntry?: undefined }
  | { kind: "unknown"; dangerEntry?: undefined; safeEntry?: undefined };

// Build lookup maps once at module load.
const programById = new Map<string, RegistryProgram>();
for (const p of (registryData as { programs: RegistryProgram[] }).programs) {
  programById.set(p.programId, p);
}

/** Returns true if the program id is in the DeFi/NFT registry. */
export function isRegisteredProgram(programId: string): boolean {
  return programById.has(programId);
}

/** Returns the registry entry for the program id, or undefined. */
export function getRegistryProgram(programId: string): RegistryProgram | undefined {
  return programById.get(programId);
}

/**
 * Extract the discriminator hex string from instruction data for the given program's scheme.
 * Returns null if data is too short.
 */
function extractDiscHex(
  scheme: "beet-u8" | "anchor-8" | "raydium-u8",
  data: Uint8Array,
): string | null {
  switch (scheme) {
    case "beet-u8":
    case "raydium-u8": {
      if (data.length === 0) return null;
      return (data[0] as number).toString(16).padStart(2, "0");
    }
    case "anchor-8": {
      if (data.length < 8) return null;
      return Array.from(data.subarray(0, 8))
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");
    }
    default: {
      return null;
    }
  }
}

/**
 * Match instruction data against a registered program's safe and dangerous instruction lists.
 *
 * Returns:
 *   - MatchResult with kind="dangerous" when a dangerous instruction matches.
 *   - MatchResult with kind="safe" when a safe instruction matches.
 *   - MatchResult with kind="unknown" when program is registered but instruction is not listed.
 *   - undefined when programId is not in the registry.
 *
 * PRIORITY: dangerous > safe. An instruction cannot be both, but if it were, dangerous wins.
 */
export function matchInstruction(
  programId: string,
  data: Uint8Array,
): MatchResult | undefined {
  const prog = programById.get(programId);
  if (prog === undefined) return undefined; // not in registry

  const discHex = extractDiscHex(prog.discriminatorScheme, data);
  if (discHex === null) {
    // Too short to read a discriminator — fail-closed: treat as unknown instruction.
    return { kind: "unknown" };
  }

  // Check dangerous first (higher priority).
  for (const entry of prog.dangerousInstructions) {
    if (entry.discHex === discHex) return { kind: "dangerous", dangerEntry: entry };
  }

  // Check safe.
  for (const entry of prog.safeInstructions) {
    if (entry.discHex === discHex) return { kind: "safe", safeEntry: entry };
  }

  // Recognized program, but instruction not listed in either list.
  return { kind: "unknown" };
}

/**
 * Match the instruction data against a registered program's dangerous-instruction
 * list using the correct discriminator scheme for that program.
 *
 * Returns the matching danger entry, or null if no dangerous entry matches.
 * Returns null (not undefined) for "recognized but instruction not listed as
 * dangerous" -- the caller must then emit a HOLD "recognized-unknown-instruction".
 *
 * Returns undefined when the programId is not in the registry at all -- the
 * caller should NOT call this function for unregistered programs.
 *
 * @deprecated Use matchInstruction() instead. Kept for backward compatibility.
 */
export function matchDangerousInstruction(
  programId: string,
  data: Uint8Array,
): RegistryDangerEntry | null | undefined {
  const prog = programById.get(programId);
  if (prog === undefined) return undefined; // not in registry

  const discHex = extractDiscHex(prog.discriminatorScheme, data);
  if (discHex === null) return null;

  for (const entry of prog.dangerousInstructions) {
    if (entry.discHex === discHex) return entry;
  }

  // Instruction byte(s) present but not listed as dangerous -> recognized-unknown.
  return null;
}

/** All registered program IDs (for invariant tests). */
export function allRegisteredProgramIds(): string[] {
  return [...programById.keys()];
}

/** All registered programs (for discriminator verification tests). */
export function allRegisteredPrograms(): RegistryProgram[] {
  return [...programById.values()];
}

/** Catalog validation: all discHex values are well-formed (2 or 16 hex chars). */
export function validateRegistry(): string[] {
  const errors: string[] = [];
  for (const prog of (registryData as { programs: RegistryProgram[] }).programs) {
    const expectedLen = (prog.discriminatorScheme === "anchor-8") ? 16 : 2;

    for (const d of prog.dangerousInstructions) {
      if (!/^[0-9a-f]+$/.test(d.discHex) || d.discHex.length !== expectedLen) {
        errors.push(
          `Program ${prog.id}: dangerous discHex "${d.discHex}" must be ${expectedLen} lowercase hex chars (scheme=${prog.discriminatorScheme})`,
        );
      }
      if (d.severity !== "HOLD" && d.severity !== "REJECT") {
        errors.push(`Program ${prog.id}: invalid severity "${d.severity}" on "${d.label}"`);
      }
    }

    for (const s of (prog.safeInstructions ?? [])) {
      if (!/^[0-9a-f]+$/.test(s.discHex) || s.discHex.length !== expectedLen) {
        errors.push(
          `Program ${prog.id}: safe discHex "${s.discHex}" must be ${expectedLen} lowercase hex chars (scheme=${prog.discriminatorScheme})`,
        );
      }
    }
  }
  return errors;
}
