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
import {
  isRegisteredProgram,
  getRegistryProgram,
  matchInstruction,
} from "./registry.ts";
import type {
  AccountRole,
  CatalogFindingId,
  CatalogEntry,
  DecodedMessage,
  Finding,
  FindingCategory,
  VerdictContext,
} from "./types.ts";
import { isWritable } from "./roles.ts";
import { base58Encode } from "./decode.ts";

const ENTRIES = catalog.entries as CatalogEntry[];
const KNOWN_PROGRAMS = catalog.knownPrograms as Record<string, string>;

const SYSTEM_PROGRAM = "11111111111111111111111111111111";
const STAKE_PROGRAM = "Stake11111111111111111111111111111111111111";
const COMPUTE_BUDGET = "ComputeBudget111111111111111111111111111111";
const BPF_LOADER_UPGRADEABLE = "BPFLoaderUpgradeab1e11111111111111111111111";
const LIGHTHOUSE_PROGRAM = "L2TExMFKdjpN9kozasaurPirfHy9P8sbXoAN1qA3S95";

const LIGHTHOUSE_ASSERT_INSTRUCTIONS: Readonly<
  Record<number, { name: string; targetCount: number }>
> = {
  2: { name: "AssertAccountData", targetCount: 1 },
  3: { name: "AssertAccountDataMulti", targetCount: 1 },
  4: { name: "AssertAccountDelta", targetCount: 2 },
  5: { name: "AssertAccountInfo", targetCount: 1 },
  6: { name: "AssertAccountInfoMulti", targetCount: 1 },
  7: { name: "AssertMintAccount", targetCount: 1 },
  8: { name: "AssertMintAccountMulti", targetCount: 1 },
  9: { name: "AssertTokenAccount", targetCount: 1 },
  10: { name: "AssertTokenAccountMulti", targetCount: 1 },
  11: { name: "AssertStakeAccount", targetCount: 1 },
  12: { name: "AssertStakeAccountMulti", targetCount: 1 },
  13: { name: "AssertUpgradeableLoaderAccount", targetCount: 1 },
  14: { name: "AssertUpgradeableLoaderAccountMulti", targetCount: 1 },
  15: { name: "AssertSysvarClock", targetCount: 0 },
  16: { name: "AssertMerkleTreeAccount", targetCount: 1 },
  17: { name: "AssertBubblegumTreeConfigAccount", targetCount: 1 },
};

/**
 * Programs whose instruction discriminator is a 4-byte little-endian u32 enum
 * discriminant, NOT a single leading byte. The System program and the BPF
 * Loader Upgradeable program serialize with BINCODE: bincode writes a Rust enum
 * discriminant as a 4-byte u32 LITTLE-ENDIAN value (the `#[repr(u8)]` on the
 * loader enum is a red herring -- bincode ignores it). So we read the FULL u32
 * and match on it; reading only byte[0] would let a crafted payload (e.g. tag
 * bytes [3, 1, 0, 0] = 259) masquerade as "Upgrade" (3).
 *
 * Compute Budget is the ODD ONE OUT: it is borsh with a single u8 tag at byte 0
 * (handled separately and treated as benign), so the u32-LE rule must NEVER be
 * applied to it.
 */
const U32_TAG_PROGRAMS = new Set<string>([
  SYSTEM_PROGRAM,
  STAKE_PROGRAM,
  BPF_LOADER_UPGRADEABLE,
]);

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
    ((data[offset] as number) |
      ((data[offset + 1] as number) << 8) |
      ((data[offset + 2] as number) << 16) |
      ((data[offset + 3] as number) << 24)) >>>
    0
  );
}

/**
 * Read a 4-byte little-endian u32 bincode enum discriminant (used by the System
 * program and the BPF Loader Upgradeable program). For Transfer that index is
 * 2, AdvanceNonceAccount is 4, BPF Upgrade is 3, BPF SetAuthority is 4, Close is
 * 5, SetAuthorityChecked is 7, System Assign is 1, etc. We read the full u32 so
 * a small tag is never confused with a stray high byte. Returns null if there
 * are fewer than 4 bytes of data.
 */
function u32TagDiscriminator(data: Uint8Array): number | null {
  if (data.length < 4) return null;
  return readU32LE(data, 0);
}

/**
 * SPL Token / Token-2022 AuthorityType names by u8 value (C5). Values 0-3 are
 * valid on classic SPL Token (Tokenkeg); 4-17 are Token-2022 additions and are
 * INVALID on a Tokenkeg-owned account. Values > 17 are "unknown".
 */
const AUTHORITY_TYPE_NAMES: Record<number, string> = {
  0: "MintTokens",
  1: "FreezeAccount",
  2: "AccountOwner",
  3: "CloseAccount",
  4: "TransferFeeConfig",
  5: "WithheldWithdraw",
  6: "CloseMint",
  7: "InterestRate",
  8: "PermanentDelegate",
  9: "ConfidentialTransferMint",
  10: "TransferHookProgramId",
  11: "ConfidentialTransferFeeConfig",
  12: "MetadataPointer",
  13: "GroupPointer",
  14: "GroupMemberPointer",
  15: "ScaledUiAmount",
  16: "Pause",
  17: "PermissionedBurn",
};

const SPL_TOKEN = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";

/**
 * Decode a SPL/Token-2022 SetAuthority (tag 6) detail (C4/C5/V1): byte1 =
 * authority_type, byte2 = COption presence flag (0=None, 1=Some), bytes 3..35 =
 * new_authority pubkey iff flag==1. Valid lengths are 3 (None) or 35 (Some).
 * Surfaces the AuthorityType name and the new authority (or "cleared"), and
 * flags an AuthorityType 4-17 seen on a Tokenkeg-owned program as invalid.
 */
function buildSetAuthorityDetail(
  programLabel: string,
  programId: string,
  data: Uint8Array,
): string {
  if (data.length < 3) {
    return `SetAuthority on ${programLabel}; truncated instruction data (cannot read authority type).`;
  }
  const authType = data[1] as number;
  const optionFlag = data[2] as number;
  const typeName = AUTHORITY_TYPE_NAMES[authType] ?? "unknown authority type";

  let newAuthority: string;
  if (optionFlag === 0) {
    newAuthority = "cleared (None)";
  } else if (optionFlag === 1 && data.length >= 35) {
    newAuthority = base58Encode(data.subarray(3, 35));
  } else {
    newAuthority = "malformed new_authority option";
  }

  const isClassicSplToken = programId === SPL_TOKEN;
  const invalidOnClassic = isClassicSplToken && authType >= 4 && authType <= 17;
  const invalidNote = invalidOnClassic
    ? ` -- AuthorityType ${authType} (${typeName}) is INVALID on classic SPL Token (only 0-3 valid)`
    : "";

  return `SetAuthority on ${programLabel}: authority_type=${authType} (${typeName}), new_authority=${newAuthority}${invalidNote}.`;
}

const STAKE_AUTHORIZE_NAMES: Record<number, string> = {
  0: "Staker",
  1: "Withdrawer",
};

function buildStakeAuthorizeDetail(
  data: Uint8Array,
  accountIndexes: number[],
  staticAccountKeys: string[],
): string | null {
  const tag = u32TagDiscriminator(data);
  if (tag === 1) {
    if (data.length < 40) return null;
    const role = readU32LE(data, 36);
    const roleName = STAKE_AUTHORIZE_NAMES[role];
    if (roleName === undefined) return null;
    const newAuthority = base58Encode(data.subarray(4, 36));
    return `Stake Authorize: role=${role} (${roleName}), new_authority=${newAuthority}.`;
  }
  if (tag === 8) {
    if (data.length < 48) return null;
    const role = readU32LE(data, 36);
    const roleName = STAKE_AUTHORIZE_NAMES[role];
    const seedLength = readU64LE(data, 40);
    if (roleName === undefined || seedLength > BigInt(Number.MAX_SAFE_INTEGER))
      return null;
    const requiredLength = 48 + Number(seedLength) + 32;
    if (data.length < requiredLength) return null;
    const newAuthority = base58Encode(data.subarray(4, 36));
    return `Stake AuthorizeWithSeed: role=${role} (${roleName}), new_authority=${newAuthority}.`;
  }
  if (tag === 10) {
    if (data.length < 8) return null;
    const role = readU32LE(data, 4);
    const roleName = STAKE_AUTHORIZE_NAMES[role];
    const newAuthorityIndex = accountIndexes[3];
    if (roleName === undefined || newAuthorityIndex === undefined) return null;
    const newAuthority = staticAccountKeys[newAuthorityIndex];
    if (newAuthority === undefined) return null;
    return `Stake AuthorizeChecked: role=${role} (${roleName}), new_authority=${newAuthority}.`;
  }
  if (tag === 11) {
    if (data.length < 48) return null;
    const role = readU32LE(data, 4);
    const roleName = STAKE_AUTHORIZE_NAMES[role];
    const seedLength = readU64LE(data, 8);
    const newAuthorityIndex = accountIndexes[3];
    if (
      roleName === undefined ||
      seedLength > BigInt(Number.MAX_SAFE_INTEGER) ||
      newAuthorityIndex === undefined
    )
      return null;
    const requiredLength = 48 + Number(seedLength);
    if (data.length < requiredLength) return null;
    const newAuthority = staticAccountKeys[newAuthorityIndex];
    if (newAuthority === undefined) return null;
    return `Stake AuthorizeCheckedWithSeed: role=${role} (${roleName}), new_authority=${newAuthority}.`;
  }
  return null;
}

function buildStakeWithdrawDetail(
  data: Uint8Array,
  accountIndexes: number[],
  staticAccountKeys: string[],
): string | null {
  if (data.length < 12 || readU32LE(data, 0) !== 4) return null;
  const destinationIndex = accountIndexes[1];
  if (destinationIndex === undefined) return null;
  const destination =
    staticAccountKeys[destinationIndex] ?? "unresolved ALT account";
  const lamports = readU64LE(data, 4);
  return `Stake Withdraw: amount=${lamports.toString()} lamports, destination=${destination}.`;
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
  "token2022-approve-delegate:4": "Approve",
  "token2022-approve-delegate:13": "ApproveChecked",
  "spl-mint-to:7": "MintTo",
  "spl-mint-to:14": "MintToChecked",
  "token2022-mint-to:7": "MintTo",
  "token2022-mint-to:14": "MintToChecked",
  "spl-burn:8": "Burn",
  "spl-burn:15": "BurnChecked",
  "token2022-burn:8": "Burn",
  "token2022-burn:15": "BurnChecked",
  "bpf-set-upgrade-authority:4": "SetAuthority",
};

/** System Program program id; the durable-nonce marker only counts under it. */
const NONCED_TX_MARKER_IX_INDEX = 0;
const SYSTEM_ADVANCE_NONCE_TAG = 4;

const CATALOG_FINDING_CATEGORIES = {
  "spl-set-authority": "authority-change",
  "token2022-set-authority": "authority-change",
  "token2022-permanent-delegate": "token-2022-extension",
  "bpf-upgrade": "program-upgrade",
  "bpf-set-upgrade-authority": "authority-change",
  "bpf-set-upgrade-authority-checked": "authority-change",
  "bpf-close": "program-upgrade",
  "system-assign": "ownership-transfer",
  "system-assign-with-seed": "ownership-transfer",
  "system-transfer-with-seed": "value-outflow",
  "durable-nonce-advance": "durable-nonce",
  "durable-nonce-initialize": "durable-nonce",
  "stake-authorize": "authority-change",
  "stake-withdraw": "value-outflow",
  "spl-approve-delegate": "delegate-approval",
  "spl-close-account": "value-outflow",
  "token2022-approve-delegate": "delegate-approval",
  "token2022-close-account": "value-outflow",
  "spl-freeze-account": "token-operation",
  "token2022-freeze-account": "token-operation",
  "spl-mint-to": "token-operation",
  "token2022-mint-to": "token-operation",
  "spl-burn": "value-outflow",
  "token2022-burn": "value-outflow",
  "spl-withdraw-excess-lamports": "value-outflow",
  "token2022-withdraw-excess-lamports": "value-outflow",
  "spl-unwrap-lamports": "value-outflow",
  "token2022-unwrap-lamports": "value-outflow",
  "spl-batch": "token-operation",
  "token2022-batch": "token-operation",
  "token2022-confidential-mint": "token-2022-extension",
  "token2022-confidential-burn": "token-2022-extension",
  "token2022-withdraw-withheld-fees": "token-2022-extension",
  "token2022-confidential-withdraw-withheld-fees": "token-2022-extension",
  "token2022-permissioned-burn": "token-2022-extension",
  "system-withdraw-nonce": "value-outflow",
  "system-large-transfer": "value-outflow",
} satisfies Readonly<Record<CatalogFindingId, FindingCategory>>;

function catalogFindingCategory(id: CatalogFindingId): FindingCategory {
  return CATALOG_FINDING_CATEGORIES[id];
}

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
  /**
   * True iff instruction index 0 is a System AdvanceNonceAccount (C17): the
   * durable-nonce marker. Computed independently of catalog matching so the
   * verdict's Drift-composite rule (V3) is robust.
   */
  durableNonceMarker: boolean;
  /**
   * True iff any finding represents an authority/ownership change (V4): SPL/
   * Token-2022 SetAuthority, BPF Loader Upgrade/SetAuthority/SetAuthorityChecked/
   * Close, System Assign/AssignWithSeed. The durable-nonce + authority-change
   * composite is the Drift signature and must escalate to REJECT (V3).
   */
  authorityOrOwnershipChange: boolean;
}

/** Catalog ids that constitute an authority/ownership change (V4). */
const AUTHORITY_CHANGE_FINDING_IDS: ReadonlySet<string> = new Set<string>([
  "spl-set-authority",
  "token2022-set-authority",
  "bpf-upgrade",
  "bpf-set-upgrade-authority",
  "bpf-set-upgrade-authority-checked",
  "bpf-close",
  "system-assign",
  "system-assign-with-seed",
  "stake-authorize",
]);

export function classify(
  msg: DecodedMessage,
  roles: AccountRole[],
  ctx: VerdictContext,
): ClassifyResult {
  const findings: Finding[] = [];
  const unknownPrograms = new Set<string>();
  let unknownProgramWritable = false;

  // C17 durable-nonce marker: ix index 0 is System AdvanceNonceAccount. Computed
  // directly from bytes (System programId + u32-LE tag 4), independent of the
  // catalog, so the Drift-composite escalation (V3) cannot be bypassed.
  const ix0 = msg.instructions[NONCED_TX_MARKER_IX_INDEX];
  const durableNonceMarker =
    ix0 !== undefined &&
    ix0.programId === SYSTEM_PROGRAM &&
    ix0.data.length >= 4 &&
    readU32LE(ix0.data, 0) === SYSTEM_ADVANCE_NONCE_TAG;

  msg.instructions.forEach((ix, instructionIndex) => {
    const pid = ix.programId;

    // ComputeBudget is always benign metadata; never a danger, never unknown.
    if (pid === COMPUTE_BUDGET) return;

    if (pid === LIGHTHOUSE_PROGRAM && ix.data.length > 0) {
      const assertion = LIGHTHOUSE_ASSERT_INSTRUCTIONS[ix.data[0] as number];
      if (
        assertion !== undefined &&
        ix.accountIndexes.length >= assertion.targetCount
      ) {
        const targetIndexes = ix.accountIndexes.slice(0, assertion.targetCount);
        const targetsSigner =
          targetIndexes.length > 0 &&
          targetIndexes.every(
            (index) => index < msg.header.numRequiredSignatures,
          );
        findings.push({
          id: "lighthouse-assertion",
          label: `Lighthouse: ${assertion.name}`,
          severity: "INFO",
          category: "program-interaction",
          instructionIndex,
          programId: pid,
          detail: targetsSigner
            ? `${assertion.name} uses the canonical Lighthouse u8 discriminator and targets analyzed signer account index(es) ${targetIndexes.join(", ")}. This is positive anti-spoof guard context only and does not alter other findings.`
            : `${assertion.name} uses the canonical Lighthouse u8 discriminator${targetIndexes.length === 0 ? " and has no account target" : ` but target account index(es) ${targetIndexes.join(", ")} are not all analyzed signer accounts`}. This INFO note does not alter other findings.`,
          mapsToLoss: "",
        });
        return;
      }
    }

    if (isRegisteredProgram(pid) || !(pid in KNOWN_PROGRAMS)) {
      // --- RECOGNIZED DeFi/NFT program tier (GAP 3 fix) ---
      // Programs in the registry are known but not native. They must NEVER
      // produce a SIGN outcome. Recognition only adds/escalates:
      //   - A listed dangerous instruction -> its severity with a clear label.
      //   - ANY other instruction on a recognized program -> HOLD
      //     "recognized-unknown-instruction" (never SIGN).
      //   - A truly unregistered program -> fall through to the unknown path.
      if (isRegisteredProgram(pid)) {
        const prog = getRegistryProgram(pid)!;
        const match = matchInstruction(pid, ix.data);

        if (match === undefined) {
          // Should not happen (isRegisteredProgram already confirmed it's in registry),
          // but fail-closed if it does: treat as unknown instruction.
          findings.push({
            id: `registry-${prog.id}-unknown-instruction`,
            label: `${prog.name}: unrecognized instruction (not individually decoded)`,
            severity: "HOLD",
            category: "unknown-program",
            instructionIndex,
            programId: pid,
            detail: `Instruction sent to recognized program ${prog.name} (${pid}) but the specific instruction was not decoded. Verify recipients and amounts before signing.`,
            mapsToLoss:
              "Unverified instruction on a DeFi/NFT program; inner effects cannot be fully bounded without per-instruction decoding.",
          });
        } else if (match.kind === "dangerous") {
          // Listed dangerous instruction: emit finding with the registry label.
          const dangerEntry = match.dangerEntry;
          findings.push({
            id: `registry-${prog.id}-danger`,
            label: dangerEntry.label,
            severity: dangerEntry.severity,
            category: "program-interaction",
            instructionIndex,
            programId: pid,
            detail: `${dangerEntry.label} on ${prog.name} (${pid}). Discriminator matched.`,
            mapsToLoss: dangerEntry.mapsToLoss,
          });
        } else if (match.kind === "safe") {
          // Recognized benign user instruction: emit INFO finding (no escalation).
          // The signer sees a human-readable label (e.g. "Jupiter v6: route (swap)").
          // INFO findings do NOT escalate a verdict — a tx of only registry-benign
          // instructions within thresholds and with no unknown programs will SIGN.
          const safeEntry = match.safeEntry;
          findings.push({
            id: `registry-${prog.id}-safe`,
            label: safeEntry.label,
            severity: "INFO",
            category: "program-interaction",
            instructionIndex,
            programId: pid,
            detail: `${safeEntry.label} on ${prog.name} (${pid}). Recognized user instruction (clear-signed by registry entry).`,
            mapsToLoss: "",
          });
        } else {
          // kind === "unknown": recognized program, unrecognized instruction: mandatory HOLD.
          // The fail-closed rule: this must NEVER become SIGN.
          findings.push({
            id: `registry-${prog.id}-unknown-instruction`,
            label: `${prog.name}: unrecognized instruction (not individually decoded)`,
            severity: "HOLD",
            category: "unknown-program",
            instructionIndex,
            programId: pid,
            detail: `Instruction sent to recognized program ${prog.name} (${pid}) but the specific instruction was not decoded. Verify recipients and amounts before signing.`,
            mapsToLoss:
              "Unverified instruction on a DeFi/NFT program; inner effects cannot be fully bounded without per-instruction decoding.",
          });
        }
        // A recognized program does NOT contribute to unknownPrograms or
        // unknownProgramWritable -- that path is reserved for truly unknown programs.
        return;
      }

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
    const findingsBeforeInstruction = findings.length;

    for (const entry of ENTRIES) {
      if (entry.programId !== pid) continue;

      const matched = usesU32Tag
        ? u32Disc !== null &&
          (entry.detection.discriminator?.includes(u32Disc) ?? false)
        : byteDisc !== null &&
          (entry.detection.discriminator?.includes(byteDisc) ?? false);

      if (!matched) continue;

      // Token-2022 extension sub-discriminator (byte 1): tags like 26/37/42
      // select an extension; the sub-instruction is byte[1]. An entry with a
      // subDiscriminator only matches when byte[1] is in its list, so config
      // sub-instructions under the same extension tag are NOT mis-flagged
      // (e.g. ConfidentialMintBurn::Mint(42,3)/Burn(42,4) are dangers, but
      // InitializeMint(42,0) is config and must stay a SIGN on its merits).
      if (entry.detection.subDiscriminator) {
        const sub = ix.data.length > 1 ? (ix.data[1] as number) : null;
        if (sub === null || !entry.detection.subDiscriminator.includes(sub)) {
          continue;
        }
      }

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
          category: catalogFindingCategory(entry.id),
          instructionIndex,
          programId: pid,
          detail: `System Transfer of ${lamports.toString()} lamports exceeds threshold ${ctx.lamportThreshold}.`,
          mapsToLoss: entry.mapsToLoss,
        });
        continue;
      }

      // Durable-nonce marker (C17): a transaction is durable-nonce-backed IFF
      // instruction index 0 is a System AdvanceNonceAccount. AdvanceNonceAccount
      // at index >= 1 is NOT a durable nonce -- raising the non-expiry HOLD there
      // is a false positive. At index >= 1 we emit only an INFO note (routine
      // nonce advance), so the genuine "does not expire" property stays tied to
      // the index-0 marker.
      if (entry.id === "durable-nonce-advance") {
        if (instructionIndex === NONCED_TX_MARKER_IX_INDEX) {
          findings.push({
            id: entry.id,
            label: entry.label,
            severity: entry.severity, // HOLD
            category: "durable-nonce",
            instructionIndex,
            programId: pid,
            detail:
              "Instruction index 0 is System AdvanceNonceAccount: this transaction is durable-nonce-backed and does not expire (its blockhash is the stored nonce value, not a fresh cluster blockhash), so it can be held and replayed until the nonce is advanced.",
            mapsToLoss: entry.mapsToLoss,
          });
        } else {
          findings.push({
            id: "nonce-advance-noninitial",
            label: "System: AdvanceNonceAccount (not at index 0)",
            severity: "INFO",
            category: "durable-nonce",
            instructionIndex,
            programId: pid,
            detail: `AdvanceNonceAccount at instruction index ${instructionIndex} (not index 0): this is a routine nonce advance, NOT the durable-nonce marker, so it does not by itself make the transaction non-expiring.`,
            mapsToLoss:
              "None on its own; the durable-nonce non-expiry property requires AdvanceNonceAccount at instruction index 0.",
          });
        }
        continue;
      }

      // SetAuthority (C4/C5/V1): decode authority_type + new_authority into the
      // detail so the operator sees WHICH authority is being handed over (and we
      // flag an invalid Token-2022 AuthorityType used on classic SPL Token).
      if (
        entry.id === "spl-set-authority" ||
        entry.id === "token2022-set-authority"
      ) {
        findings.push({
          id: entry.id,
          label: entry.label,
          severity: entry.severity,
          category: catalogFindingCategory(entry.id),
          instructionIndex,
          programId: pid,
          detail: buildSetAuthorityDetail(
            KNOWN_PROGRAMS[pid] as string,
            pid,
            ix.data,
          ),
          mapsToLoss: entry.mapsToLoss,
        });
        continue;
      }

      if (entry.id === "stake-authorize") {
        const detail = buildStakeAuthorizeDetail(
          ix.data,
          ix.accountIndexes,
          msg.staticAccountKeys,
        );
        if (detail === null) continue;
        findings.push({
          id: entry.id,
          label: entry.label,
          severity: entry.severity,
          category: catalogFindingCategory(entry.id),
          instructionIndex,
          programId: pid,
          detail,
          mapsToLoss: entry.mapsToLoss,
        });
        continue;
      }

      if (entry.id === "stake-withdraw") {
        const detail = buildStakeWithdrawDetail(
          ix.data,
          ix.accountIndexes,
          msg.staticAccountKeys,
        );
        if (detail === null) continue;
        findings.push({
          id: entry.id,
          label: entry.label,
          severity: ctx.strict ? "REJECT" : entry.severity,
          category: catalogFindingCategory(entry.id),
          instructionIndex,
          programId: pid,
          detail,
          mapsToLoss: entry.mapsToLoss,
        });
        continue;
      }

      findings.push({
        id: entry.id,
        label: entry.label,
        severity: entry.severity,
        category: catalogFindingCategory(entry.id),
        instructionIndex,
        programId: pid,
        detail: buildDetail(
          entry,
          KNOWN_PROGRAMS[pid] as string,
          u32Disc,
          byteDisc,
        ),
        mapsToLoss: entry.mapsToLoss,
      });
    }

    if (
      pid === STAKE_PROGRAM &&
      findings.length === findingsBeforeInstruction
    ) {
      findings.push({
        id: "stake-unverified-instruction",
        label: "Stake: recognized instruction requiring review",
        severity: "HOLD",
        category: "structural",
        instructionIndex,
        programId: pid,
        detail:
          u32Disc === null
            ? "Instruction sent to the Native Stake program but the u32-LE instruction tag could not be decoded."
            : `Instruction sent to the Native Stake program with u32-LE tag ${u32Disc}; it is recognized but not classified as an authority transfer or withdrawal.`,
        mapsToLoss:
          "Stake-account effects are recognized but not fully decoded; manual review is required before signing.",
      });
    }
  });

  if (durableNonceMarker && msg.header.numRequiredSignatures > 1) {
    const nonFeePayerSigners = msg.staticAccountKeys.slice(
      1,
      msg.header.numRequiredSignatures,
    );
    findings.push({
      id: "durable-nonce-non-fee-payer-signer",
      label: "Durable-nonce transaction includes a non-fee-payer signer",
      severity: "HOLD",
      category: "durable-nonce",
      instructionIndex: NONCED_TX_MARKER_IX_INDEX,
      programId: SYSTEM_PROGRAM,
      detail: `Instruction index 0 is System AdvanceNonceAccount and the transaction requires ${nonFeePayerSigners.length} signer(s) other than fee payer ${msg.staticAccountKeys[0]}. Non-fee-payer signer(s): ${nonFeePayerSigners.join(", ")}. This is a non-expiring transaction in which a separate party can pay fees and retain the signed transaction for later submission.`,
      mapsToLoss:
        "A separate fee payer can hold and later submit a durable-nonce transaction authorized by another signer, preserving a stale authority or value-moving action until conditions favor execution.",
    });
  }

  const authorityOrOwnershipChange = findings.some((f) =>
    AUTHORITY_CHANGE_FINDING_IDS.has(f.id),
  );

  return {
    findings,
    unknownPrograms: [...unknownPrograms],
    unknownProgramWritable,
    durableNonceMarker,
    authorityOrOwnershipChange,
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
