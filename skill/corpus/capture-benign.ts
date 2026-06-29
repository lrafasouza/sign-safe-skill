/**
 * capture-benign.ts -- One-time dev script to capture benign mainnet transactions.
 *
 * Run with: node --import tsx skill/corpus/capture-benign.ts
 *
 * Hits the network once; output is committed to skill/corpus/benign/*.json.
 * Tests read only the committed JSON (fully offline, frozen fetcher).
 *
 * Pinned slots: 428290000 and 428289500 (hardcoded for reproducibility).
 */

import { createHash } from "node:crypto";
import {
  writeFileSync,
  mkdirSync,
  existsSync,
  readdirSync,
  readFileSync,
} from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import { decodeInput } from "../src/decode.ts";
import { extractVaultTransactionAddress } from "../src/squads.ts";

const HERE = dirname(fileURLToPath(import.meta.url));
const BENIGN_DIR = join(HERE, "benign");

const RPC_URL =
  process.env.SIGN_SAFE_RPC || "https://api.mainnet-beta.solana.com";
const PINNED_SLOTS = [
  428290000, 428289500, 429745000, 429746000, 429747000, 429748000, 429749000,
  429750000, 429751000, 429752000,
];
const MAX_PER_SLOT = 50;
const VOTE_PROGRAM = "Vote111111111111111111111111111111111111111";
const TOKEN_2022_PID = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";
const SLEEP_MS = 80; // between RPC calls to avoid rate limiting

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

async function rpcPost(method: string, params: unknown[]): Promise<unknown> {
  const body = JSON.stringify({ jsonrpc: "2.0", id: 1, method, params });
  const res = await fetch(RPC_URL, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body,
  });
  if (!res.ok) throw new Error(`HTTP ${res.status} for ${method}`);
  const json = (await res.json()) as {
    result?: unknown;
    error?: { message: string };
  };
  if (json.error) throw new Error(`RPC error: ${json.error.message}`);
  return json.result;
}

async function getAccountInfoB64(pubkey: string): Promise<string | null> {
  await sleep(SLEEP_MS);
  try {
    const result = await rpcPost("getAccountInfo", [
      pubkey,
      { encoding: "base64" },
    ]);
    const val = (result as { value: null | { data: [string, string] } }).value;
    if (!val) return null;
    return val.data[0] ?? null;
  } catch {
    // Retry once
    await sleep(200);
    try {
      const result = await rpcPost("getAccountInfo", [
        pubkey,
        { encoding: "base64" },
      ]);
      const val = (result as { value: null | { data: [string, string] } })
        .value;
      if (!val) return null;
      return val.data[0] ?? null;
    } catch {
      console.warn(`  getAccountInfo failed for ${pubkey} after retry`);
      return null;
    }
  }
}

interface TxEntry {
  transaction: [string, string]; // [base64, encoding]
  meta: { err: unknown } | null;
}

interface BlockResult {
  transactions?: TxEntry[];
}

async function getBlock(slot: number): Promise<BlockResult | null> {
  try {
    const result = await rpcPost("getBlock", [
      slot,
      {
        encoding: "base64",
        maxSupportedTransactionVersion: 0,
        transactionDetails: "full",
        rewards: false,
      },
    ]);
    return result as BlockResult;
  } catch (e) {
    console.warn(`  getBlock(${slot}) failed: ${e}`);
    return null;
  }
}

function isVoteOnly(programIds: string[]): boolean {
  return programIds.every(
    (p) =>
      p === VOTE_PROGRAM || p === "ComputeBudget111111111111111111111111111111",
  );
}

function getProgramIds(txB64: string): string[] {
  try {
    const { message } = decodeInput(txB64);
    return [...new Set(message.instructions.map((ix) => ix.programId))];
  } catch {
    return [];
  }
}

// Categorize a tx for stratification
function categorize(txB64: string): string {
  try {
    const { message } = decodeInput(txB64);
    const pids = new Set(message.instructions.map((ix) => ix.programId));
    const hasAlt = message.addressTableLookups.length > 0;
    const isV0 = message.version === 0;

    const JUP = "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4";
    const SPL_TOKEN = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
    const ASSOC_TOKEN = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJe1bRS";
    const COMPUTE_BUDGET = "ComputeBudget111111111111111111111111111111";

    if (pids.has(JUP)) return isV0 && hasAlt ? "swap-v0-alt" : "swap";
    if (pids.has(ASSOC_TOKEN)) return "ata-create";
    if (pids.has(TOKEN_2022_PID)) return "token2022";
    if (pids.has(SPL_TOKEN)) return isV0 && hasAlt ? "spl-v0-alt" : "spl";
    if (isV0 && hasAlt) return "v0-alt";
    if (isV0) return "v0-no-alt";
    if (pids.has(COMPUTE_BUDGET)) return "legacy-compute";
    return "legacy-other";
  } catch {
    return "unknown";
  }
}

interface Fixture {
  slot: number;
  index: number;
  version: "legacy" | 0;
  txB64: string;
  accounts: Record<string, string>;
  programIds: string[];
}

async function captureSlot(slot: number): Promise<Fixture[]> {
  console.log(`\n=== Fetching slot ${slot} ===`);
  await sleep(SLEEP_MS);
  const block = await getBlock(slot);
  if (!block || !block.transactions) {
    console.log(`  Block not available for slot ${slot}`);
    return [];
  }

  const allTxs = block.transactions;
  console.log(`  Total transactions in block: ${allTxs.length}`);

  // Filter: no errors + no vote-only
  const eligible: Array<{ txB64: string; origIndex: number }> = [];
  for (let i = 0; i < allTxs.length; i++) {
    const tx = allTxs[i]!;
    if (tx.meta?.err !== null) continue; // skip failed txns

    const txB64 = tx.transaction[0];
    const pids = getProgramIds(txB64);
    if (pids.length === 0) continue; // decode failed
    if (isVoteOnly(pids)) continue; // skip vote transactions

    eligible.push({ txB64, origIndex: i });
  }
  console.log(`  Eligible (non-vote, successful): ${eligible.length}`);

  // Stratified sampling: collect up to MAX_PER_SLOT txns with variety
  const categoryBuckets = new Map<
    string,
    Array<{ txB64: string; origIndex: number }>
  >();
  for (const e of eligible) {
    const cat = categorize(e.txB64);
    if (!categoryBuckets.has(cat)) categoryBuckets.set(cat, []);
    categoryBuckets.get(cat)!.push(e);
  }

  console.log("  Categories found:", [...categoryBuckets.keys()].join(", "));

  // Round-robin sampling from categories until MAX_PER_SLOT
  const selected: Array<{ txB64: string; origIndex: number }> = [];
  const catNames = [...categoryBuckets.keys()];
  let round = 0;
  while (selected.length < MAX_PER_SLOT) {
    let added = false;
    for (const cat of catNames) {
      if (selected.length >= MAX_PER_SLOT) break;
      const bucket = categoryBuckets.get(cat)!;
      const idx = round;
      if (idx < bucket.length) {
        selected.push(bucket[idx]!);
        added = true;
      }
    }
    if (!added) break;
    round++;
  }

  console.log(`  Selected: ${selected.length} transactions`);

  // For each selected tx: decode, collect accounts, build fixture
  const fixtures: Fixture[] = [];
  const accountCache = new Map<string, string | null>();

  for (let fi = 0; fi < selected.length; fi++) {
    const { txB64, origIndex } = selected[fi]!;
    console.log(
      `  Processing tx ${fi + 1}/${selected.length} (origIndex=${origIndex})`,
    );

    let decoded: ReturnType<typeof decodeInput>;
    try {
      decoded = decodeInput(txB64);
    } catch (e) {
      console.warn(`    Decode failed: ${e}`);
      continue;
    }

    const { message } = decoded;
    const accounts: Record<string, string> = {};

    // Collect ALT table accounts
    const altPubkeys = message.addressTableLookups.map((l) => l.accountKey);

    // Collect Token-2022 mint accounts from TransferChecked (disc=12)
    const mintPubkeys: string[] = [];
    for (const ix of message.instructions) {
      if (ix.programId !== TOKEN_2022_PID) continue;
      if (ix.data.length < 1) continue;
      const disc = ix.data[0] as number;
      if (disc !== 12) continue;
      const mintIdx = ix.accountIndexes[1];
      if (mintIdx !== undefined && mintIdx < message.staticAccountKeys.length) {
        const mint = message.staticAccountKeys[mintIdx];
        if (mint) mintPubkeys.push(mint);
      }
    }

    // Collect Squads VaultTransaction PDA
    const vtAddr = extractVaultTransactionAddress(message);
    const vtPubkeys: string[] = vtAddr ? [vtAddr] : [];

    const allPubkeys = [
      ...new Set([...altPubkeys, ...mintPubkeys, ...vtPubkeys]),
    ];

    for (const pubkey of allPubkeys) {
      if (!accountCache.has(pubkey)) {
        console.log(`    Fetching account: ${pubkey.slice(0, 16)}...`);
        const b64 = await getAccountInfoB64(pubkey);
        accountCache.set(pubkey, b64);
      }
      const cached = accountCache.get(pubkey);
      if (cached !== null && cached !== undefined) {
        accounts[pubkey] = cached;
      }
    }

    const programIds = [
      ...new Set(message.instructions.map((ix) => ix.programId)),
    ];

    fixtures.push({
      slot,
      index: fi,
      version: message.version,
      txB64,
      accounts,
      programIds,
    });
  }

  return fixtures;
}

async function main(): Promise<void> {
  mkdirSync(BENIGN_DIR, { recursive: true });

  const allFixtures: Fixture[] = [];

  for (const slot of PINNED_SLOTS) {
    const fixtures = await captureSlot(slot);
    allFixtures.push(...fixtures);

    for (const fixture of fixtures) {
      const filename = `${fixture.slot}-${fixture.index}.json`;
      const filepath = join(BENIGN_DIR, filename);
      if (existsSync(filepath)) continue; // preserve frozen fixtures on re-run
      writeFileSync(filepath, JSON.stringify(fixture, null, 2));
      console.log(`  Written: ${filename}`);
    }
  }

  // Manifest: sha256 of every benign fixture on disk (frozen-stable across re-runs).
  const manifest = readdirSync(BENIGN_DIR)
    .filter((f) => f.endsWith(".json") && f !== "manifest.json")
    .sort()
    .map((filename) => {
      const content = readFileSync(join(BENIGN_DIR, filename), "utf8");
      const fx = JSON.parse(content) as {
        slot: number;
        index: number;
        version: unknown;
        programIds: string[];
      };
      return {
        filename,
        sha256: createHash("sha256").update(content).digest("hex"),
        slot: fx.slot,
        index: fx.index,
        version: String(fx.version),
        programIds: fx.programIds,
      };
    });

  const manifestPath = join(BENIGN_DIR, "manifest.json");
  writeFileSync(manifestPath, JSON.stringify(manifest, null, 2));
  console.log(`\nManifest written: ${manifestPath}`);
  console.log(`Total fixtures: ${allFixtures.length}`);

  // Summary stats
  const uniqueAccounts = new Set<string>();
  for (const f of allFixtures) {
    Object.keys(f.accounts).forEach((k) => uniqueAccounts.add(k));
  }
  console.log(`Unique accounts captured: ${uniqueAccounts.size}`);

  const versionCounts: Record<string, number> = {};
  for (const f of allFixtures) {
    const v = String(f.version);
    versionCounts[v] = (versionCounts[v] ?? 0) + 1;
  }
  console.log("Version breakdown:", versionCounts);
}

main().catch((e) => {
  console.error("FATAL:", e);
  process.exit(1);
});
