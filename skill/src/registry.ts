/**
 * registry.ts -- PURE: recognized non-native DeFi/NFT program registry.
 *
 * Loads program-registry.json and provides fast lookups for:
 *   - isRegisteredProgram(pid): is this program in the registry?
 *   - matchDangerousInstruction(pid, data): returns a dangerous-instruction
 *     entry if the data discriminator matches, or null for unrecognized.
 *
 * DISCRIMINATOR SCHEME INVARIANTS (verified against canonical sources):
 *
 *   beet-u8   — Metaplex Token Metadata: single leading u8 (beet serialization).
 *               Discriminators verified per-instruction in the generated JS client.
 *   anchor-8  — Bubblegum, Jupiter v6, Orca: 8-byte Anchor discriminator
 *               (sha256("global:<instruction_name>")[0..8]).
 *               Bubblegum discriminators verified: transfer = a334c8e78c0345ba.
 *   raydium-u8 — Raydium AMM v4: single leading u8.
 *
 * FAIL-CLOSED CONTRACT:
 *   - A recognized program with an UNRECOGNIZED instruction -> HOLD
 *     ("recognized-unknown-instruction"), NEVER SIGN.
 *   - A recognized dangerous instruction -> its listed severity, with the
 *     clear-signed label from the registry entry.
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
  /** Human-readable label for the finding. */
  label: string;
  /** Severity: HOLD or REJECT. */
  severity: "HOLD" | "REJECT";
  /** Concrete real-loss mapping. */
  mapsToLoss: string;
}

export interface RegistryProgram {
  id: string;
  name: string;
  programId: string;
  discriminatorScheme: "beet-u8" | "anchor-8" | "raydium-u8";
  dangerousInstructions: RegistryDangerEntry[];
}

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
 * Match the instruction data against a registered program's dangerous-instruction
 * list using the correct discriminator scheme for that program.
 *
 * Returns the matching danger entry, or null if no dangerous entry matches.
 * Returns null (not undefined) for "recognized but instruction not listed as
 * dangerous" -- the caller must then emit a HOLD "recognized-unknown-instruction".
 *
 * Returns undefined when the programId is not in the registry at all -- the
 * caller should NOT call this function for unregistered programs.
 */
export function matchDangerousInstruction(
  programId: string,
  data: Uint8Array,
): RegistryDangerEntry | null | undefined {
  const prog = programById.get(programId);
  if (prog === undefined) return undefined; // not in registry

  // No dangerous instructions listed for this program (e.g. Jupiter, Orca,
  // Raydium in "recognizeOnly" mode) -> always a recognized-unknown-instruction.
  if (prog.dangerousInstructions.length === 0) return null;

  let discHex: string;

  switch (prog.discriminatorScheme) {
    case "beet-u8":
    case "raydium-u8": {
      // Single leading byte discriminator.
      if (data.length === 0) return null;
      discHex = (data[0] as number).toString(16).padStart(2, "0");
      break;
    }
    case "anchor-8": {
      // 8-byte Anchor discriminator.
      if (data.length < 8) return null;
      discHex = Array.from(data.subarray(0, 8))
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");
      break;
    }
    default: {
      // Unknown scheme -> fail-closed, treat as no match (HOLD).
      return null;
    }
  }

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

/** Catalog validation: all discHex values are well-formed (2 or 16 hex chars). */
export function validateRegistry(): string[] {
  const errors: string[] = [];
  for (const prog of (registryData as { programs: RegistryProgram[] }).programs) {
    const expectedLen = (prog.discriminatorScheme === "anchor-8") ? 16 : 2;
    for (const d of prog.dangerousInstructions) {
      if (!/^[0-9a-f]+$/.test(d.discHex) || d.discHex.length !== expectedLen) {
        errors.push(
          `Program ${prog.id}: discHex "${d.discHex}" must be ${expectedLen} lowercase hex chars (scheme=${prog.discriminatorScheme})`,
        );
      }
      if (d.severity !== "HOLD" && d.severity !== "REJECT") {
        errors.push(`Program ${prog.id}: invalid severity "${d.severity}" on "${d.label}"`);
      }
    }
  }
  return errors;
}
