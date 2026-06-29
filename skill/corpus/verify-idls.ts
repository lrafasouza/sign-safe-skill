/**
 * verify-idls.ts -- One-time dev audit: cross-check every anchor-8 registry ixName
 * against the program's CANONICAL on-chain Anchor IDL.
 *
 * Run with: SIGN_SAFE_RPC="https://mainnet.helius-rpc.com/?api-key=XXX" \
 *           node --import tsx skill/corpus/verify-idls.ts
 *
 * The offline recompute test (skill/test/registry-discriminators.test.ts) already locks
 * discHex == sha256("global:"+ixName)[0..8]. THIS script additionally proves each ixName
 * is a REAL instruction of the deployed program (not a self-consistent invention) by
 * reading the on-chain IDL account and matching names snake<->camel. Frozen result +
 * provenance: skill/catalog/idl-sources.json. SECRET: RPC URL via $SIGN_SAFE_RPC, never committed.
 */
import { PublicKey, Connection } from "@solana/web3.js";
import zlib from "node:zlib";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const RPC = process.env.SIGN_SAFE_RPC;
if (!RPC) {
  console.error(
    'SIGN_SAFE_RPC is required (archival RPC). e.g. "https://mainnet.helius-rpc.com/?api-key=XXX"',
  );
  process.exit(1);
}
const HERE = dirname(fileURLToPath(import.meta.url));
const reg = JSON.parse(
  readFileSync(join(HERE, "..", "catalog", "program-registry.json"), "utf8"),
) as {
  programs: Array<{
    id: string;
    programId: string;
    discriminatorScheme: string;
    safeInstructions?: Array<{ ixName?: string }>;
    dangerousInstructions?: Array<{ ixName?: string }>;
  }>;
};

const conn = new Connection(RPC, "confirmed");
const toCamel = (s: string): string =>
  s.replace(/_([a-z0-9])/g, (_m, c: string) => c.toUpperCase());

async function idlNames(programId: string): Promise<Set<string> | null> {
  const pid = new PublicKey(programId);
  const base = PublicKey.findProgramAddressSync([], pid)[0];
  const idlAddr = await PublicKey.createWithSeed(base, "anchor:idl", pid);
  const acc = await conn.getAccountInfo(idlAddr);
  if (!acc) return null;
  const len = acc.data.readUInt32LE(40);
  const idl = JSON.parse(
    zlib.inflateSync(acc.data.subarray(44, 44 + len)).toString("utf8"),
  ) as { instructions?: Array<{ name: string }> };
  return new Set((idl.instructions ?? []).map((i) => i.name));
}

let anyMissing = false;
for (const p of reg.programs) {
  if (p.discriminatorScheme !== "anchor-8") continue;
  const ix = [...(p.dangerousInstructions ?? []), ...(p.safeInstructions ?? [])]
    .map((i) => i.ixName)
    .filter((n): n is string => Boolean(n));
  if (ix.length === 0) continue;
  try {
    const names = await idlNames(p.programId);
    if (!names) {
      console.log(
        `${p.id}: no on-chain IDL account (cross-check manually vs the published SDK IDL)`,
      );
      continue;
    }
    const missing = ix.filter((n) => !names.has(n) && !names.has(toCamel(n)));
    if (missing.length) anyMissing = true;
    console.log(
      `${p.id}: ${ix.length} ixNames vs ${names.size} IDL ix -> ${missing.length === 0 ? "ALL VERIFIED" : "MISSING: " + missing.join(", ")}`,
    );
  } catch (e) {
    console.log(`${p.id}: ERROR ${(e as Error).message}`);
  }
}
process.exit(anyMissing ? 1 : 0);
