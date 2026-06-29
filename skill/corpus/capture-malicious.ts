/**
 * capture-malicious.ts -- One-time dev script to capture REAL, publicly-documented
 * attack transactions (raw signed bytes) for the offline replay corpus.
 *
 * Run with: SIGN_SAFE_RPC="https://mainnet.helius-rpc.com/?api-key=XXX" \
 *           node --import tsx skill/corpus/capture-malicious.ts
 *
 * Reads skill/corpus/malicious/INCIDENTS.json, fetches each signature's raw tx via
 * getTransaction(base64) from an ARCHIVAL RPC (old txns are pruned by public nodes),
 * and writes one frozen JSON per tx to skill/corpus/malicious/<incident>__<sig8>.json.
 *
 * SECRETS: the RPC URL (with API key) is read from $SIGN_SAFE_RPC and is NEVER written
 * to any committed file. Frozen fixtures contain only the public on-chain bytes + provenance.
 * Tests read only the committed JSON (fully offline, frozen).
 */

import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const HERE = dirname(fileURLToPath(import.meta.url));
const DIR = join(HERE, "malicious");
const RPC_URL = process.env.SIGN_SAFE_RPC;

if (!RPC_URL) {
  console.error(
    "SIGN_SAFE_RPC is required (an archival RPC with getTransaction base64). " +
      'e.g. SIGN_SAFE_RPC="https://mainnet.helius-rpc.com/?api-key=XXX"',
  );
  process.exit(1);
}

interface Incident {
  incident: string;
  title: string;
  date: string;
  threat_class: string;
  signature: string;
  source_url: string;
  explorer: string;
}

async function getTxBase64(signature: string): Promise<{
  b64: string;
  slot: number;
  blockTime: number | null;
  err: unknown;
}> {
  const res = await fetch(RPC_URL as string, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method: "getTransaction",
      params: [
        signature,
        { encoding: "base64", maxSupportedTransactionVersion: 0 },
      ],
    }),
  });
  if (!res.ok) throw new Error(`HTTP ${res.status} for ${signature}`);
  const json = (await res.json()) as {
    result?: {
      slot: number;
      blockTime: number | null;
      meta?: { err: unknown };
      transaction: [string, string];
    } | null;
    error?: { message: string };
  };
  if (json.error) throw new Error(`RPC error: ${json.error.message}`);
  if (!json.result)
    throw new Error(`Transaction not found / not retained: ${signature}`);
  return {
    b64: json.result.transaction[0],
    slot: json.result.slot,
    blockTime: json.result.blockTime,
    err: json.result.meta?.err ?? null,
  };
}

async function main(): Promise<void> {
  const { incidents } = JSON.parse(
    readFileSync(join(DIR, "INCIDENTS.json"), "utf8"),
  ) as { incidents: Incident[] };

  for (const inc of incidents) {
    const tx = await getTxBase64(inc.signature);
    const out = {
      signature: inc.signature,
      slot: tx.slot,
      blockTime: tx.blockTime,
      cluster: "mainnet-beta",
      onchain_status: tx.err === null ? "success" : "failed",
      b64: tx.b64,
      meta: {
        incident: inc.incident,
        title: inc.title,
        date: inc.date,
        threat_class: inc.threat_class,
        source_url: inc.source_url,
        explorer: inc.explorer,
      },
    };
    const file = `${inc.incident}__${inc.signature.slice(0, 8)}.json`;
    writeFileSync(join(DIR, file), JSON.stringify(out, null, 2) + "\n");
    console.log(`wrote ${file} (slot ${tx.slot}, ${tx.b64.length} b64 chars)`);
  }
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
