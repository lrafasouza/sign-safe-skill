/**
 * generate.ts -- (re)generates the 10 .b64 fixture files using @solana/web3.js.
 *
 * The whole point: build REAL serialized Solana messages with the canonical
 * library, write them out as base64, and let our own wire parser (src/decode.ts)
 * decode them in the test suite. If our parser agrees with web3.js on the same
 * bytes, the parser is correct -- not merely self-consistent.
 *
 * Everything here is DETERMINISTIC: fixed keypairs from fixed 32-byte seeds and
 * a fixed blockhash, so regenerating produces byte-identical fixtures. This
 * file is NOT part of the core and is never imported by it.
 *
 * Run: npm run gen-fixtures
 */

import { writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import {
  Keypair,
  PublicKey,
  SystemProgram,
  TransactionInstruction,
  TransactionMessage,
  MessageV0,
  AddressLookupTableAccount,
} from "@solana/web3.js";

const HERE = dirname(fileURLToPath(import.meta.url));

// ---- deterministic actors -------------------------------------------------

/** Build a Keypair from a single repeated byte so fixtures are reproducible. */
function seededKeypair(byte: number): Keypair {
  return Keypair.fromSeed(Uint8Array.from(new Array(32).fill(byte)));
}

const SIGNER = seededKeypair(1); // the wallet being asked to sign
const RECIPIENT = seededKeypair(2);
const TOKEN_ACCOUNT = seededKeypair(3);
const MINT = seededKeypair(4);
const DELEGATE = seededKeypair(5);
const NEW_AUTHORITY = seededKeypair(6);
const NONCE_ACCOUNT = seededKeypair(7);
const PROGRAM_DATA = seededKeypair(8);
const PROGRAM_ACCOUNT = seededKeypair(9);
const BUFFER_ACCOUNT = seededKeypair(10);
const SPILL = seededKeypair(11);

// A fixed, valid-length blockhash (32 bytes -> base58). Deterministic.
const BLOCKHASH = new PublicKey(Uint8Array.from(new Array(32).fill(9))).toBase58();

// ---- canonical program ids -------------------------------------------------

const SPL_TOKEN = new PublicKey("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");
const TOKEN_2022 = new PublicKey("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb");
const BPF_UPGRADEABLE = new PublicKey("BPFLoaderUpgradeab1e11111111111111111111111");
const SYSTEM = new PublicKey("11111111111111111111111111111111");
const COMPUTE_BUDGET = new PublicKey("ComputeBudget111111111111111111111111111111");
const SYSVAR_RENT = new PublicKey("SysvarRent111111111111111111111111111111111");
const SYSVAR_CLOCK = new PublicKey("SysvarC1ock11111111111111111111111111111111");
// A deterministic, structurally-valid pubkey that is NOT in the catalog.
const RANDOM_PROGRAM = seededKeypair(99).publicKey;

// ---- instruction builders (raw, matching real native layouts) --------------

function u32le(n: number): Uint8Array {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n, true);
  return b;
}
function u64le(n: bigint): Uint8Array {
  const b = new Uint8Array(8);
  new DataView(b.buffer).setBigUint64(0, n, true);
  return b;
}
function concat(...arrs: Uint8Array[]): Buffer {
  return Buffer.concat(arrs.map((a) => Buffer.from(a)));
}

/** SPL Token SetAuthority (disc 6). */
function splSetAuthority(): TransactionInstruction {
  return new TransactionInstruction({
    programId: SPL_TOKEN,
    keys: [
      { pubkey: MINT.publicKey, isSigner: false, isWritable: true },
      { pubkey: SIGNER.publicKey, isSigner: true, isWritable: false },
    ],
    // [u8 6][u8 authorityType=0 (MintTokens)][u8 option=1][32 newAuthority]
    data: concat(
      Uint8Array.from([6, 0, 1]),
      NEW_AUTHORITY.publicKey.toBytes(),
    ),
  });
}

/** Token-2022 SetAuthority (disc 6) -- same layout, different program. */
function token2022SetAuthority(): TransactionInstruction {
  return new TransactionInstruction({
    programId: TOKEN_2022,
    keys: [
      { pubkey: MINT.publicKey, isSigner: false, isWritable: true },
      { pubkey: SIGNER.publicKey, isSigner: true, isWritable: false },
    ],
    data: concat(Uint8Array.from([6, 0, 1]), NEW_AUTHORITY.publicKey.toBytes()),
  });
}

/** BPF Loader Upgradeable: Upgrade (disc 3, u32-le). */
function bpfUpgrade(): TransactionInstruction {
  return new TransactionInstruction({
    programId: BPF_UPGRADEABLE,
    keys: [
      { pubkey: PROGRAM_DATA.publicKey, isSigner: false, isWritable: true },
      { pubkey: PROGRAM_ACCOUNT.publicKey, isSigner: false, isWritable: true },
      { pubkey: BUFFER_ACCOUNT.publicKey, isSigner: false, isWritable: true },
      { pubkey: SPILL.publicKey, isSigner: false, isWritable: true },
      { pubkey: SYSVAR_RENT, isSigner: false, isWritable: false },
      { pubkey: SYSVAR_CLOCK, isSigner: false, isWritable: false },
      { pubkey: SIGNER.publicKey, isSigner: true, isWritable: false },
    ],
    data: concat(u32le(3)),
  });
}

/** System AdvanceNonceAccount (disc 4, u32-le). */
function advanceNonce(): TransactionInstruction {
  return new TransactionInstruction({
    programId: SYSTEM,
    keys: [
      { pubkey: NONCE_ACCOUNT.publicKey, isSigner: false, isWritable: true },
      { pubkey: SYSVAR_RENT, isSigner: false, isWritable: false },
      { pubkey: SIGNER.publicKey, isSigner: true, isWritable: false },
    ],
    data: concat(u32le(4)),
  });
}

/** SPL Token Approve (disc 4) -> grant delegate spend authority. */
function splApprove(): TransactionInstruction {
  return new TransactionInstruction({
    programId: SPL_TOKEN,
    keys: [
      { pubkey: TOKEN_ACCOUNT.publicKey, isSigner: false, isWritable: true },
      { pubkey: DELEGATE.publicKey, isSigner: false, isWritable: false },
      { pubkey: SIGNER.publicKey, isSigner: true, isWritable: false },
    ],
    // [u8 4][u64 amount]
    data: concat(Uint8Array.from([4]), u64le(1_000_000n)),
  });
}

/** SPL Token CloseAccount (disc 9). */
function splCloseAccount(): TransactionInstruction {
  return new TransactionInstruction({
    programId: SPL_TOKEN,
    keys: [
      { pubkey: TOKEN_ACCOUNT.publicKey, isSigner: false, isWritable: true },
      { pubkey: RECIPIENT.publicKey, isSigner: false, isWritable: true },
      { pubkey: SIGNER.publicKey, isSigner: true, isWritable: false },
    ],
    data: concat(Uint8Array.from([9])),
  });
}

/** Token-2022 PermanentDelegate-related instruction (disc 35). */
function token2022PermanentDelegate(): TransactionInstruction {
  return new TransactionInstruction({
    programId: TOKEN_2022,
    keys: [
      { pubkey: MINT.publicKey, isSigner: false, isWritable: true },
      { pubkey: SIGNER.publicKey, isSigner: true, isWritable: false },
    ],
    // [u8 35][32 delegate] -- InitializePermanentDelegate
    data: concat(Uint8Array.from([35]), DELEGATE.publicKey.toBytes()),
  });
}

/** Instruction to a random/unknown program touching a writable account. */
function unknownProgramIx(): TransactionInstruction {
  return new TransactionInstruction({
    programId: RANDOM_PROGRAM,
    keys: [
      { pubkey: TOKEN_ACCOUNT.publicKey, isSigner: false, isWritable: true },
      { pubkey: SIGNER.publicKey, isSigner: true, isWritable: false },
    ],
    data: concat(Uint8Array.from([1, 2, 3, 4])),
  });
}

/** ComputeBudget setComputeUnitLimit (disc 2) -- benign metadata. */
function computeBudgetLimit(): TransactionInstruction {
  return new TransactionInstruction({
    programId: COMPUTE_BUDGET,
    keys: [],
    data: concat(Uint8Array.from([2]), u32le(200_000)),
  });
}

// ---- message assembly -------------------------------------------------------

function legacyB64(instructions: TransactionInstruction[]): string {
  const msg = new TransactionMessage({
    payerKey: SIGNER.publicKey,
    recentBlockhash: BLOCKHASH,
    instructions,
  }).compileToLegacyMessage();
  return Buffer.from(msg.serialize()).toString("base64");
}

function v0B64(
  instructions: TransactionInstruction[],
  lookupTables: AddressLookupTableAccount[] = [],
): string {
  const msg = new TransactionMessage({
    payerKey: SIGNER.publicKey,
    recentBlockhash: BLOCKHASH,
    instructions,
  }).compileToV0Message(lookupTables);
  return Buffer.from(msg.serialize()).toString("base64");
}

/**
 * Build a v0 message that genuinely carries addressTableLookups. We construct
 * a synthetic ALT containing the recipient address, then reference it from a
 * System Transfer so web3.js emits a real addressTableLookups entry.
 */
function v0WithAltB64(): string {
  const altAddress = seededKeypair(20).publicKey;
  const lut = new AddressLookupTableAccount({
    key: altAddress,
    state: {
      deactivationSlot: 2n ** 64n - 1n,
      lastExtendedSlot: 0,
      lastExtendedSlotStartIndex: 0,
      authority: SIGNER.publicKey,
      addresses: [RECIPIENT.publicKey],
    },
  });
  // A transfer whose destination is only reachable via the ALT.
  const ix = SystemProgram.transfer({
    fromPubkey: SIGNER.publicKey,
    toPubkey: RECIPIENT.publicKey,
    lamports: 10_000_000, // 0.01 SOL, below threshold; HOLD comes from the ALT
  });
  return v0B64([ix], [lut]);
}

// ---- the 10 fixtures --------------------------------------------------------

const fixtures: Array<{ name: string; b64: string }> = [
  {
    name: "01_safe_sol_transfer",
    b64: legacyB64([
      SystemProgram.transfer({
        fromPubkey: SIGNER.publicKey,
        toPubkey: RECIPIENT.publicKey,
        lamports: 10_000_000, // 0.01 SOL
      }),
    ]),
  },
  { name: "02_setauthority_reject", b64: legacyB64([splSetAuthority()]) },
  { name: "03_bpf_upgrade_reject", b64: legacyB64([bpfUpgrade()]) },
  {
    name: "04_durable_nonce_drift",
    // AdvanceNonceAccount (HOLD) + SetAuthority (REJECT) in one tx.
    b64: legacyB64([advanceNonce(), splSetAuthority()]),
  },
  { name: "05_approve_delegate_hold", b64: legacyB64([splApprove()]) },
  { name: "06_close_account_hold", b64: legacyB64([splCloseAccount()]) },
  {
    name: "07_large_transfer_hold",
    b64: legacyB64([
      SystemProgram.transfer({
        fromPubkey: SIGNER.publicKey,
        toPubkey: RECIPIENT.publicKey,
        lamports: 5_000_000_000, // 5 SOL, above 1 SOL threshold
      }),
    ]),
  },
  {
    name: "08_unknown_program_reject",
    // unknown program writes to a value-bearing (writable) account
    b64: legacyB64([computeBudgetLimit(), unknownProgramIx()]),
  },
  { name: "09_v0_alt_unverified", b64: v0WithAltB64() },
  {
    name: "10_token2022_permdelegate_hold",
    b64: legacyB64([token2022PermanentDelegate()]),
  },
];

for (const f of fixtures) {
  const path = join(HERE, `${f.name}.b64`);
  writeFileSync(path, f.b64 + "\n", "utf8");
  process.stdout.write(`wrote ${f.name}.b64 (${f.b64.length} b64 chars)\n`);
}

process.stdout.write(`\ngenerated ${fixtures.length} fixtures in ${HERE}\n`);
