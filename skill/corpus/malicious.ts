/**
 * malicious.ts -- Synthetic malicious transaction corpus (deterministic, no network).
 *
 * Constructs in-code synthetic transaction messages for 7 danger families,
 * each labeled with family + expectedDecision. All offline; no RPC calls.
 *
 * Families:
 *   1. SetAuthority → AccountOwner (SPL Token instr 6, authorityType 2)
 *   2. System Assign / AssignWithSeed (owner change)
 *   3. SPL Approve / ApproveChecked to non-signer delegate
 *   4. Multi-transfer sweep (many transfers draining signer)
 *   5. Durable-nonce-anchored sensitive tx (AdvanceNonceAccount first ix)
 *   6. Token-2022 mint with PermanentDelegate (via mintExtensions frozen)
 *   7. Squads vaultTransactionExecute wrapping hidden authority change
 */

// ---------------------------------------------------------------------------
// Byte helpers (no imports — this module is standalone, read by corpus scripts)
// ---------------------------------------------------------------------------

export function u32le(n: number): number[] {
  return [n & 0xff, (n >>> 8) & 0xff, (n >>> 16) & 0xff, (n >>> 24) & 0xff];
}

export function u64le(n: bigint): number[] {
  const out: number[] = [];
  let v = n;
  for (let i = 0; i < 8; i++) {
    out.push(Number(v & 0xffn));
    v >>= 8n;
  }
  return out;
}

function compactU16(n: number): number[] {
  const out: number[] = [];
  let rem = n;
  for (;;) {
    const byte = rem & 0x7f;
    rem >>= 7;
    if (rem === 0) {
      out.push(byte);
      break;
    }
    out.push(byte | 0x80);
  }
  return out;
}

const B58_ALPHA = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
function b58ToBytes32(b58: string): Uint8Array {
  const m: Record<string, number> = {};
  for (let i = 0; i < B58_ALPHA.length; i++) m[B58_ALPHA[i]!] = i;
  let bytes: number[] = [];
  for (const ch of b58) {
    let c = m[ch]!;
    for (let j = 0; j < bytes.length; j++) {
      c += bytes[j]! * 58;
      bytes[j] = c & 0xff;
      c >>= 8;
    }
    while (c > 0) {
      bytes.push(c & 0xff);
      c >>= 8;
    }
  }
  let lz = 0;
  for (const ch of b58) {
    if (ch === "1") lz++;
    else break;
  }
  const out = new Uint8Array(32);
  const body = bytes.reverse();
  const off = 32 - body.length - lz;
  for (let i = 0; i < body.length; i++) out[off + i] = body[i]!;
  return out;
}

function b58Encode(bytes: Uint8Array): string {
  let n = 0n;
  for (const b of bytes) n = n * 256n + BigInt(b);
  if (n === 0n && bytes.length > 0) return "1".repeat(bytes.length);
  let s = "";
  while (n > 0n) {
    s = B58_ALPHA[Number(n % 58n)]! + s;
    n /= 58n;
  }
  let lz = 0;
  for (const b of bytes) {
    if (b === 0) lz++;
    else break;
  }
  return "1".repeat(lz) + s;
}

function key(byte: number): number[] {
  return new Array(32).fill(byte);
}

function toB64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64");
}

// Program IDs
const SYSTEM = "11111111111111111111111111111111";
const SPL_TOKEN = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const TOKEN_2022 = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";
const SQUADS_V4 = "SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf";

const VAULT_TX_EXECUTE_DISC = [0xc2, 0x08, 0xa1, 0x57, 0x99, 0xa4, 0x19, 0xab];
const VAULT_TX_ACCOUNT_DISC = [0xa8, 0xfa, 0xa2, 0x64, 0x51, 0x0e, 0xa2, 0xcf];
const UPDATE_ADMIN_DISC = [0xa1, 0xb0, 0x28, 0xd5, 0x3c, 0xb8, 0xb3, 0xe4];

/**
 * Build a legacy message with:
 *   header: [numRequired, numReadonlySigned, numReadonlyUnsigned]
 *   keySpecs: number (fill byte) | string (base58)
 *   ixs: array of {prog, accts, data}
 */
function buildLegacyMsg(
  header: [number, number, number],
  keySpecs: Array<number | string>,
  ixs: Array<{ prog: number; accts: number[]; data: number[] }>,
  blockhashByte = 250,
): Uint8Array {
  const out: number[] = [];
  out.push(...header);
  out.push(...compactU16(keySpecs.length));
  for (const k of keySpecs) {
    if (typeof k === "number") out.push(...key(k));
    else out.push(...Array.from(b58ToBytes32(k)));
  }
  out.push(...key(blockhashByte)); // blockhash
  out.push(...compactU16(ixs.length));
  for (const ix of ixs) {
    out.push(ix.prog);
    out.push(...compactU16(ix.accts.length));
    out.push(...ix.accts);
    out.push(...compactU16(ix.data.length));
    out.push(...ix.data);
  }
  return Uint8Array.from(out);
}

/** Build a synthetic VaultTransaction account bytes with one inner instruction. */
function buildVaultTxBytes(
  instrProgramIdIndex: number,
  instrData: number[],
  numKeys = 3,
): Uint8Array {
  const bytes: number[] = [];
  bytes.push(...VAULT_TX_ACCOUNT_DISC);
  bytes.push(...new Array(32).fill(0x01)); // multisig
  bytes.push(...new Array(32).fill(0x02)); // creator
  bytes.push(1, 0, 0, 0, 0, 0, 0, 0); // index u64-LE
  bytes.push(255, 0, 254); // bump, vault_index, vault_bump
  bytes.push(0, 0, 0, 0); // ephemeral_signer_bumps Vec<u8> len=0
  bytes.push(1, 1, 1); // num_signers, num_writable_signers, num_writable_non_signers
  bytes.push(...u32le(numKeys));
  for (let i = 0; i < numKeys; i++) bytes.push(...new Array(32).fill(0x10 + i));
  bytes.push(...u32le(1)); // 1 instruction
  bytes.push(instrProgramIdIndex);
  bytes.push(...u32le(0)); // accountIndexes: empty
  bytes.push(...u32le(instrData.length));
  bytes.push(...instrData);
  bytes.push(...u32le(0)); // address_table_lookups: empty
  return new Uint8Array(bytes);
}

// ---------------------------------------------------------------------------
// Export types
// ---------------------------------------------------------------------------

export interface MaliciousFixture {
  family: string;
  txB64: string;
  accounts?: Record<string, string>;
  /** Bytes for vaultTransactionBytes (Squads family) — NOT base64, just array */
  vaultTxBytes?: number[];
  expectedDecision: "REJECT" | "HOLD";
  note: string;
}

// ---------------------------------------------------------------------------
// Family 1: SetAuthority → AccountOwner (SPL Token disc=6, authorityType=2)
// Expect REJECT
// ---------------------------------------------------------------------------

function setAuthorityMsg(
  newAuthByte: number,
  tokenProg: string = SPL_TOKEN,
): string {
  // SPL Token SetAuthority: disc=6, authorityType=2 (AccountOwner), newAuthority=Some(key)
  const newAuthKey = new Uint8Array(32).fill(newAuthByte);
  const setAuth = [6, 2, 1, ...Array.from(newAuthKey)]; // disc=6, type=2, Some, 32 bytes
  const bytes = buildLegacyMsg(
    [1, 0, 1],
    [1, tokenProg, 3],
    [{ prog: 1, accts: [2, 0], data: setAuth }],
  );
  return toB64(bytes);
}

// ---------------------------------------------------------------------------
// Family 2: System Assign / AssignWithSeed (owner change)
// Expect REJECT
// ---------------------------------------------------------------------------

function systemAssignMsg(variant: "assign" | "assignWithSeed"): string {
  // System Assign: disc=1, then 32-byte programId
  // System AssignWithSeed: disc=10 (0x0a), then base, seed, owner
  if (variant === "assign") {
    const newOwner = new Uint8Array(32).fill(0x77);
    const data = [...u32le(1), ...Array.from(newOwner)];
    const bytes = buildLegacyMsg(
      [1, 0, 1],
      [1, SYSTEM],
      [{ prog: 1, accts: [0], data }],
    );
    return toB64(bytes);
  } else {
    // AssignWithSeed disc=10, base(32), seed_len(u64le), seed(bytes), owner(32)
    const base = new Uint8Array(32).fill(0x01);
    const seed = Buffer.from("evil");
    const owner = new Uint8Array(32).fill(0x88);
    const data = [
      ...u32le(10),
      ...Array.from(base),
      ...u64le(BigInt(seed.length)),
      ...Array.from(seed),
      ...Array.from(owner),
    ];
    const bytes = buildLegacyMsg(
      [1, 0, 1],
      [1, SYSTEM],
      [{ prog: 1, accts: [0], data }],
    );
    return toB64(bytes);
  }
}

// ---------------------------------------------------------------------------
// Family 3: SPL Approve / ApproveChecked to non-signer delegate
// Expect REJECT/HOLD (Approve is HOLD, SetAuthority is REJECT)
// Per catalog: Approve is HOLD (delegate can drain)
// ---------------------------------------------------------------------------

function splApproveMsg(
  variant: "approve" | "approveChecked",
  tokenProg: string = SPL_TOKEN,
): string {
  if (variant === "approve") {
    // SPL Approve disc=4: source(0), delegate(non-signer=2), owner(signer=0), amount u64
    const data = [4, ...u64le(999_000_000_000n)];
    const bytes = buildLegacyMsg(
      [1, 0, 1],
      [1, tokenProg, 3], // idx0=signer, idx1=tokenProg, idx2=nonSignerDelegate
      [{ prog: 1, accts: [0, 2, 0], data }], // source, delegate=idx2, owner
    );
    return toB64(bytes);
  } else {
    // SPL ApproveChecked disc=13: source, mint, delegate, owner, amount u64, decimals u8
    const data = [13, ...u64le(5_000_000_000n), 6]; // 5000 USDC (6 decimals)
    const bytes = buildLegacyMsg(
      [1, 0, 1],
      [1, tokenProg, 3, 4], // idx0=signer, idx1=tokenProg, idx2=mint, idx3=delegate (non-signer)
      [{ prog: 1, accts: [0, 2, 3, 0], data }], // source, mint, delegate, owner
    );
    return toB64(bytes);
  }
}

// ---------------------------------------------------------------------------
// Family 4: Multi-transfer sweep (many transfers draining signer)
// Expect HOLD (large SOL outflow) or REJECT
// ---------------------------------------------------------------------------

function multiTransferMsg(numTransfers: number): string {
  const ixs = [];
  for (let i = 0; i < numTransfers; i++) {
    // Each transfer: 1 SOL = 1_000_000_000 lamports
    const data = [...u32le(2), ...u64le(1_000_000_000n)];
    ixs.push({ prog: 1, accts: [0, 2], data });
  }
  const bytes = buildLegacyMsg([1, 0, 1], [1, SYSTEM, 3], ixs);
  return toB64(bytes);
}

// ---------------------------------------------------------------------------
// Family 5: Durable-nonce-anchored sensitive tx (AdvanceNonceAccount first ix)
// Expect HOLD (durable-nonce alone) or REJECT (with dangerous ix)
// ---------------------------------------------------------------------------

function durableNonceMsg(
  variant: "bare" | "with-setauth" | "with-assign",
): string {
  const nonceAdvance = { prog: 1, accts: [2, 0], data: u32le(4) };
  if (variant === "bare") {
    const bytes = buildLegacyMsg([1, 0, 1], [1, SYSTEM, 3], [nonceAdvance]);
    return toB64(bytes);
  } else if (variant === "with-setauth") {
    const newKey = new Uint8Array(32).fill(0xcc);
    const setAuth = [6, 2, 1, ...Array.from(newKey)];
    const bytes = buildLegacyMsg(
      [1, 0, 1],
      [1, SYSTEM, 3, SPL_TOKEN, 5],
      [nonceAdvance, { prog: 3, accts: [4, 0], data: setAuth }],
    );
    return toB64(bytes);
  } else {
    // with-assign
    const newOwner = new Uint8Array(32).fill(0xaa);
    const data = [...u32le(1), ...Array.from(newOwner)];
    const bytes = buildLegacyMsg(
      [1, 0, 1],
      [1, SYSTEM, 3],
      [nonceAdvance, { prog: 1, accts: [2], data }],
    );
    return toB64(bytes);
  }
}

// ---------------------------------------------------------------------------
// Family 6: Token-2022 mint with PermanentDelegate (via frozen mintExtensions)
// Expect HOLD
// The tx itself is a TransferChecked, but the mint has a permanentDelegate extension.
// The malicious fixture carries an `accounts` entry so tests can inject it.
// ---------------------------------------------------------------------------

const MINT_BYTES_0x44 = new Uint8Array(32).fill(0x44);
const DELEGATE_BYTES_0xdd = new Uint8Array(32).fill(0xdd);
const MINT_B58 = b58Encode(MINT_BYTES_0x44);
const DELEGATE_B58 = b58Encode(DELEGATE_BYTES_0xdd);

/** Build a Token-2022 mint account with PermanentDelegate TLV extension. */
function buildMintWithPermanentDelegate(): Uint8Array {
  // Minimal Token-2022 mint account: 82 base bytes + accountType(1) + TLV
  // accountType = 0x01 (Mint)
  // PermanentDelegate extension: type=12 u16-LE, length=32 u16-LE, delegate pubkey
  const bytes: number[] = [];
  // Base mint (82 bytes) — we zero the fields except mintAuthority (optional, set to None => 0,0,0,0 + 32 zeros)
  // MintLayout: mint_authority Option<Pubkey> (4+32), supply u64, decimals u8, is_initialized bool, freeze_authority Option<Pubkey> (4+32)
  // We use all zeros for the base (is_initialized=0 but that doesn't matter for TLV parsing)
  for (let i = 0; i < 82; i++) bytes.push(0);
  // accountType byte (offset 165 in Token-2022 mint; but we build from offset 82 here since it's a MINT only)
  // Actually Token-2022 mint = 165 bytes base (same as account base length) + accountType + TLV
  // We need to pad to 165 bytes first (the account type offset)
  while (bytes.length < 165) bytes.push(0);
  bytes.push(0x01); // accountType = Mint
  // PermanentDelegate TLV: type=12 (u16-LE) + length=32 (u16-LE) + 32 bytes delegate
  bytes.push(12, 0); // type u16-LE = 12
  bytes.push(32, 0); // length u16-LE = 32
  bytes.push(...Array.from(DELEGATE_BYTES_0xdd)); // delegate pubkey
  return new Uint8Array(bytes);
}

function token2022TransferMsg(mintB58: string): string {
  const mintBytes = b58ToBytes32(mintB58);
  // A TransferChecked via Token-2022: disc=12, source, mint, dest, owner, amount u64, decimals u8
  // accounts: [source(0), mint(idx2), dest(3), owner(0)]
  const data = [12, ...u64le(1_000_000n), 6]; // 1 token with 6 decimals
  const out: number[] = [];
  out.push(1, 0, 1); // header
  out.push(...compactU16(4)); // 4 keys
  out.push(...key(1)); // idx0: signer/source
  out.push(...Array.from(b58ToBytes32(TOKEN_2022))); // idx1: Token-2022 program
  out.push(...Array.from(mintBytes)); // idx2: mint (dangerous!)
  out.push(...key(3)); // idx3: dest
  out.push(...key(250)); // blockhash
  out.push(...compactU16(1)); // 1 ix
  out.push(1); // programIdIndex = Token-2022 (idx1)
  out.push(...compactU16(4)); // 4 accounts
  out.push(0, 2, 3, 0); // source, mint, dest, owner
  out.push(...compactU16(data.length));
  out.push(...data);
  return toB64(Uint8Array.from(out));
}

// ---------------------------------------------------------------------------
// Family 7: Squads vaultTransactionExecute wrapping hidden authority change
// Expect REJECT/HOLD
// ---------------------------------------------------------------------------

function squadsHiddenAuthorityMsg(): string {
  // A top-level vaultTransactionExecute (Squads), with inner bytes that have UPDATE_ADMIN discriminator
  // Keys: idx0=feePayer(0x01), idx1=SQUADS_V4, idx2=vtPDA(0x77)
  const out: number[] = [];
  out.push(1, 0, 1); // header
  out.push(...compactU16(3)); // 3 static keys
  out.push(...key(1)); // idx0: feePayer (signer-writable)
  out.push(...Array.from(b58ToBytes32(SQUADS_V4))); // idx1: Squads program
  out.push(...key(0x77)); // idx2: VaultTransaction PDA
  out.push(...key(250)); // blockhash
  out.push(...compactU16(1)); // 1 ix
  out.push(1); // programIdIndex = Squads (idx1)
  out.push(...compactU16(3)); // 3 accounts: [feePayer, vtPDA, ...]
  out.push(0, 2, 2); // accts: [feePayer, vtPDA at idx2, vtPDA again]
  out.push(...compactU16(VAULT_TX_EXECUTE_DISC.length));
  out.push(...VAULT_TX_EXECUTE_DISC);
  return toB64(Uint8Array.from(out));
}

// VaultTransaction PDA address: key(0x77) base58
const VT_PDA_B58 = b58Encode(new Uint8Array(32).fill(0x77));

// ---------------------------------------------------------------------------
// Assemble the corpus
// ---------------------------------------------------------------------------

export const MALICIOUS_CORPUS: MaliciousFixture[] = [
  // ---- Family 1: SetAuthority (SPL Token) ----
  {
    family: "SetAuthority-AccountOwner",
    txB64: setAuthorityMsg(0x09),
    expectedDecision: "REJECT",
    note: "SPL Token SetAuthority(AccountOwner) changes account ownership to a new key",
  },
  {
    family: "SetAuthority-AccountOwner",
    txB64: setAuthorityMsg(0xaa),
    expectedDecision: "REJECT",
    note: "SPL Token SetAuthority(AccountOwner) second variant different new authority",
  },
  {
    family: "SetAuthority-AccountOwner",
    txB64: setAuthorityMsg(0xbb),
    expectedDecision: "REJECT",
    note: "SPL Token SetAuthority(AccountOwner) third variant",
  },
  {
    family: "SetAuthority-AccountOwner",
    txB64: setAuthorityMsg(0xcc),
    expectedDecision: "REJECT",
    note: "SPL Token SetAuthority(AccountOwner) fourth variant different key",
  },
  {
    family: "SetAuthority-AccountOwner",
    txB64: setAuthorityMsg(0xdd),
    expectedDecision: "REJECT",
    note: "SPL Token SetAuthority(AccountOwner) fifth variant",
  },
  {
    family: "SetAuthority-AccountOwner",
    txB64: setAuthorityMsg(0xee, TOKEN_2022),
    expectedDecision: "REJECT",
    note: "Token-2022 SetAuthority(AccountOwner) — same disc, different program",
  },
  {
    family: "SetAuthority-AccountOwner",
    txB64: setAuthorityMsg(0xff, TOKEN_2022),
    expectedDecision: "REJECT",
    note: "Token-2022 SetAuthority(AccountOwner) second variant",
  },

  // ---- Family 2: System Assign / AssignWithSeed ----
  {
    family: "System-Assign",
    txB64: systemAssignMsg("assign"),
    expectedDecision: "REJECT",
    note: "System Assign changes program owner of an account",
  },
  {
    family: "System-Assign",
    txB64: systemAssignMsg("assignWithSeed"),
    expectedDecision: "REJECT",
    note: "System AssignWithSeed changes program owner with seed derivation",
  },
  // Additional Assign variants (different layouts)
  {
    family: "System-Assign",
    txB64: (() => {
      // Assign to the BPFLoader
      const newOwner = new Uint8Array(32).fill(0x55);
      const data = [...u32le(1), ...Array.from(newOwner)];
      return toB64(
        buildLegacyMsg(
          [1, 0, 1],
          [1, SYSTEM, 3],
          [{ prog: 1, accts: [0], data }],
        ),
      );
    })(),
    expectedDecision: "REJECT",
    note: "System Assign to BPFLoader-like owner",
  },
  {
    family: "System-Assign",
    txB64: (() => {
      // Assign + ComputeBudget prefix
      const newOwner = new Uint8Array(32).fill(0x33);
      const data = [...u32le(1), ...Array.from(newOwner)];
      const COMPUTE_BUDGET = "ComputeBudget111111111111111111111111111111";
      const setLimit = [2, 128, 134, 1, 0]; // SetComputeUnitLimit(100000)
      return toB64(
        buildLegacyMsg(
          [1, 0, 1],
          [1, SYSTEM, 3, COMPUTE_BUDGET],
          [
            { prog: 3, accts: [], data: setLimit },
            { prog: 1, accts: [0], data },
          ],
        ),
      );
    })(),
    expectedDecision: "REJECT",
    note: "ComputeBudget + System Assign — compute prefix doesn't launder danger",
  },
  {
    family: "System-Assign",
    txB64: (() => {
      const newOwner = new Uint8Array(32).fill(0x22);
      const data = [...u32le(1), ...Array.from(newOwner)];
      return toB64(
        buildLegacyMsg(
          [1, 0, 1],
          [1, SYSTEM, 3],
          [{ prog: 1, accts: [2], data }],
        ),
      );
    })(),
    expectedDecision: "REJECT",
    note: "System Assign on a non-signer account (still dangerous)",
  },

  // ---- Family 3: SPL Approve / ApproveChecked ----
  {
    family: "SPL-Approve",
    txB64: splApproveMsg("approve"),
    expectedDecision: "HOLD",
    note: "SPL Token Approve grants spending authority to a non-signer delegate",
  },
  {
    family: "SPL-Approve",
    txB64: splApproveMsg("approveChecked"),
    expectedDecision: "HOLD",
    note: "SPL Token ApproveChecked with large amount to non-signer delegate",
  },
  {
    family: "SPL-Approve",
    txB64: splApproveMsg("approve", TOKEN_2022),
    expectedDecision: "HOLD",
    note: "Token-2022 Approve (same disc=4) to non-signer delegate",
  },
  {
    family: "SPL-Approve",
    txB64: splApproveMsg("approveChecked", TOKEN_2022),
    expectedDecision: "HOLD",
    note: "Token-2022 ApproveChecked to non-signer delegate",
  },
  {
    family: "SPL-Approve",
    txB64: (() => {
      // Approve with very large amount
      const data = [4, ...u64le(u64Max())];
      return toB64(
        buildLegacyMsg(
          [1, 0, 1],
          [1, SPL_TOKEN, 3, 4],
          [{ prog: 1, accts: [0, 3, 0], data }],
        ),
      );
    })(),
    expectedDecision: "HOLD",
    note: "SPL Token Approve with max u64 amount",
  },

  // ---- Family 4: Multi-transfer sweep ----
  {
    family: "Multi-Transfer-Sweep",
    txB64: multiTransferMsg(3),
    expectedDecision: "HOLD",
    note: "3 SOL transfers in one tx — total 3 SOL exceeds 1 SOL threshold",
  },
  {
    family: "Multi-Transfer-Sweep",
    txB64: multiTransferMsg(5),
    expectedDecision: "HOLD",
    note: "5 SOL transfers — total 5 SOL",
  },
  {
    family: "Multi-Transfer-Sweep",
    txB64: multiTransferMsg(10),
    expectedDecision: "HOLD",
    note: "10 SOL transfers — draining sweep pattern",
  },
  {
    family: "Multi-Transfer-Sweep",
    txB64: multiTransferMsg(2),
    expectedDecision: "HOLD",
    note: "2 SOL transfers — 2 SOL total (above threshold)",
  },
  {
    family: "Multi-Transfer-Sweep",
    txB64: multiTransferMsg(8),
    expectedDecision: "HOLD",
    note: "8 SOL transfers — major sweep",
  },

  // ---- Family 5: Durable nonce anchored tx ----
  {
    family: "Durable-Nonce-Sensitive",
    txB64: durableNonceMsg("bare"),
    expectedDecision: "HOLD",
    note: "Bare durable-nonce (AdvanceNonceAccount at ix0) — replay risk",
  },
  {
    family: "Durable-Nonce-Sensitive",
    txB64: durableNonceMsg("with-setauth"),
    expectedDecision: "REJECT",
    note: "Durable-nonce + SetAuthority — Drift attack shape (REJECT due to Drift composite)",
  },
  {
    family: "Durable-Nonce-Sensitive",
    txB64: durableNonceMsg("with-assign"),
    expectedDecision: "REJECT",
    note: "Durable-nonce + Assign — the combination is Drift-composite (REJECT)",
  },
  {
    family: "Durable-Nonce-Sensitive",
    txB64: (() => {
      // Durable nonce + large transfer
      const nonceAdvance = { prog: 1, accts: [2, 0], data: u32le(4) };
      const transfer = {
        prog: 1,
        accts: [0, 3],
        data: [...u32le(2), ...u64le(2_000_000_000n)],
      };
      return toB64(
        buildLegacyMsg([1, 0, 1], [1, SYSTEM, 3, 4], [nonceAdvance, transfer]),
      );
    })(),
    expectedDecision: "HOLD",
    note: "Durable-nonce + large SOL transfer — at least HOLD from nonce detection",
  },
  {
    family: "Durable-Nonce-Sensitive",
    txB64: (() => {
      // Durable nonce + SPL Approve
      const nonceAdvance = { prog: 1, accts: [2, 0], data: u32le(4) };
      const approve = [4, ...u64le(999_000_000_000n)];
      return toB64(
        buildLegacyMsg(
          [1, 0, 1],
          [1, SYSTEM, 3, SPL_TOKEN, 5],
          [nonceAdvance, { prog: 3, accts: [0, 4, 0], data: approve }],
        ),
      );
    })(),
    expectedDecision: "HOLD",
    note: "Durable-nonce + SPL Approve — dual danger (nonce HOLD + approve HOLD)",
  },

  // ---- Family 6: Token-2022 PermanentDelegate ----
  {
    family: "Token2022-PermanentDelegate",
    txB64: token2022TransferMsg(MINT_B58),
    accounts: {
      [MINT_B58]: Buffer.from(buildMintWithPermanentDelegate()).toString(
        "base64",
      ),
    },
    expectedDecision: "HOLD",
    note: "Token-2022 TransferChecked with PermanentDelegate mint extension → HOLD",
  },
  {
    family: "Token2022-PermanentDelegate",
    txB64: token2022TransferMsg(MINT_B58), // Second variant: same mint key, different amount
    accounts: {
      [MINT_B58]: Buffer.from(buildMintWithPermanentDelegate()).toString(
        "base64",
      ),
    },
    expectedDecision: "HOLD",
    note: "Token-2022 TransferChecked with PermanentDelegate — second variant (same mint, different fixture)",
  },
  {
    family: "Token2022-PermanentDelegate",
    txB64: token2022TransferMsg(b58Encode(new Uint8Array(32).fill(0x55))),
    accounts: (() => {
      const mintB58 = b58Encode(new Uint8Array(32).fill(0x55));
      return {
        [mintB58]: Buffer.from(buildMintWithPermanentDelegate()).toString(
          "base64",
        ),
      };
    })(),
    expectedDecision: "HOLD",
    note: "Token-2022 TransferChecked with PermanentDelegate — different mint",
  },
  {
    family: "Token2022-PermanentDelegate",
    txB64: token2022TransferMsg(b58Encode(new Uint8Array(32).fill(0x66))),
    accounts: (() => {
      const mintB58 = b58Encode(new Uint8Array(32).fill(0x66));
      // Mint with TransferHook extension: type=14 (0x0E)
      const bytes: number[] = [];
      for (let i = 0; i < 165; i++) bytes.push(0);
      bytes.push(0x01); // accountType = Mint
      bytes.push(14, 0); // type u16-LE = 14 (TransferHook)
      bytes.push(64, 0); // length u16-LE = 64 (hookProgramId(32) + hookAuthority(32))
      bytes.push(...new Array(32).fill(0xbb)); // hook program id
      bytes.push(...new Array(32).fill(0xcc)); // hook authority
      return {
        [mintB58]: Buffer.from(new Uint8Array(bytes)).toString("base64"),
      };
    })(),
    expectedDecision: "HOLD",
    note: "Token-2022 TransferChecked with TransferHook extension → HOLD",
  },
  {
    family: "Token2022-PermanentDelegate",
    txB64: token2022TransferMsg(b58Encode(new Uint8Array(32).fill(0x77))),
    accounts: (() => {
      const mintB58 = b58Encode(new Uint8Array(32).fill(0x77));
      // Both PermanentDelegate + TransferHook
      const bytes: number[] = [];
      for (let i = 0; i < 165; i++) bytes.push(0);
      bytes.push(0x01); // accountType = Mint
      bytes.push(12, 0); // PermanentDelegate type
      bytes.push(32, 0);
      bytes.push(...new Array(32).fill(0xdd));
      bytes.push(14, 0); // TransferHook type
      bytes.push(64, 0);
      bytes.push(...new Array(64).fill(0xee));
      return {
        [mintB58]: Buffer.from(new Uint8Array(bytes)).toString("base64"),
      };
    })(),
    expectedDecision: "HOLD",
    note: "Token-2022 with both PermanentDelegate AND TransferHook — dual extension danger",
  },

  // ---- Family 7: Squads vaultTransactionExecute wrapping authority change ----
  {
    family: "Squads-Hidden-Authority",
    txB64: squadsHiddenAuthorityMsg(),
    // No vaultTxBytes → HOLD (unverified)
    expectedDecision: "HOLD",
    note: "Squads vaultTransactionExecute without inner bytes → HOLD (squads-execute-unverified)",
  },
  {
    family: "Squads-Hidden-Authority",
    txB64: squadsHiddenAuthorityMsg(),
    vaultTxBytes: Array.from(buildVaultTxBytes(0, UPDATE_ADMIN_DISC)),
    expectedDecision: "REJECT",
    note: "Squads vaultTransactionExecute with inner update_admin discriminator → REJECT",
  },
  {
    family: "Squads-Hidden-Authority",
    txB64: squadsHiddenAuthorityMsg(),
    vaultTxBytes: Array.from(
      buildVaultTxBytes(0, [6, 2, 1, ...new Array(32).fill(0xaa)]),
    ),
    expectedDecision: "REJECT",
    note: "Squads execute with inner SetAuthority(AccountOwner) → REJECT",
  },
  {
    family: "Squads-Hidden-Authority",
    txB64: (() => {
      // Durable nonce + Squads execute (real Drift attack shape)
      const out: number[] = [];
      out.push(1, 0, 1); // header
      out.push(...compactU16(4)); // 4 keys
      out.push(...key(1)); // idx0: feePayer
      out.push(...Array.from(b58ToBytes32(SYSTEM))); // idx1: System
      out.push(...key(3)); // idx2: nonce account
      out.push(...Array.from(b58ToBytes32(SQUADS_V4))); // idx3: Squads
      // VT PDA would be passed as idx3 account in execute, but we use 2-key setup for simplicity
      out.push(...key(250)); // blockhash
      out.push(...compactU16(2)); // 2 ixs
      // ix0: AdvanceNonceAccount (System disc=4)
      out.push(1); // System = idx1
      out.push(...compactU16(2));
      out.push(2, 0); // nonce, feePayer
      out.push(...compactU16(4));
      out.push(...u32le(4));
      // ix1: vaultTransactionExecute (Squads)
      out.push(3); // Squads = idx3
      out.push(...compactU16(3));
      out.push(0, 2, 2); // feePayer, nonce(reused as VT PDA), nonce
      out.push(...compactU16(VAULT_TX_EXECUTE_DISC.length));
      out.push(...VAULT_TX_EXECUTE_DISC);
      return toB64(Uint8Array.from(out));
    })(),
    expectedDecision: "REJECT",
    note: "Durable-nonce + Squads execute = Drift composite → REJECT",
  },
  {
    family: "Squads-Hidden-Authority",
    txB64: squadsHiddenAuthorityMsg(),
    vaultTxBytes: Array.from(buildVaultTxBytes(5, UPDATE_ADMIN_DISC, 3)), // idx5 >= 3 keys → ALT-unresolved
    expectedDecision: "HOLD",
    note: "Squads execute with unresolved ALT inner program → HOLD (fail-closed)",
  },
];

function u64Max(): bigint {
  return 0xffffffffffffffffn;
}

/** Export the vaultPDA address for Squads tests (key(0x77)) */
export const SQUADS_VT_PDA_B58 = VT_PDA_B58;

/** Export the dangerous mint b58 addresses */
export const DANGER_MINT_B58 = MINT_B58;
export const DELEGATE_PUBKEY_B58 = DELEGATE_B58;
