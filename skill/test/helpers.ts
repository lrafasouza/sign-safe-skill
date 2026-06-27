/**
 * helpers.ts -- shared, OFFLINE test utilities for the vitest suite.
 *
 * Hand-built message-byte builders (legacy + v0) so role/classify/decode tests
 * can construct exact wire bytes without going through @solana/web3.js (which is
 * reserved for the independent cross-check). Pure functions; no network.
 */

import { readFileSync, readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

export const HERE = dirname(fileURLToPath(import.meta.url));
export const FIXTURES = join(HERE, "..", "fixtures");
export const REAL_FIXTURES = join(FIXTURES, "real");

export function u8(n: number): number[] {
  return [n & 0xff];
}
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

/**
 * Canonical compact-u16 encoder (matches short-vec/src/lib.rs). Used to build
 * multi-byte length prefixes for boundary tests (T4.3). 1-3 bytes, little-endian
 * 7-bit groups, 0x80 continuation.
 */
export function encodeCompactU16(value: number): number[] {
  if (value < 0 || value > 0xffff) {
    throw new RangeError(`compact-u16 out of range: ${value}`);
  }
  const out: number[] = [];
  let rem = value;
  for (;;) {
    let byte = rem & 0x7f;
    rem >>= 7;
    if (rem === 0) {
      out.push(byte);
      break;
    }
    byte |= 0x80;
    out.push(byte);
  }
  return out;
}

/** A 32-byte key filled with a single byte value. */
export function key(byte: number): number[] {
  return new Array(32).fill(byte);
}

export interface IxSpec {
  prog: number;
  accts: number[];
  data: number[];
}
export interface LutSpec {
  table: number;
  writable: number[];
  readonly: number[];
}

/**
 * Hand-build a raw LEGACY message.
 *   header = [numRequiredSignatures, numReadonlySigned, numReadonlyUnsigned]
 *   keyBytes: each entry becomes a 32-byte key filled with that byte.
 */
export function legacyBytes(
  header: [number, number, number],
  keyBytes: number[],
  ixs: IxSpec[],
  blockhashByte = 250,
): Uint8Array {
  const out: number[] = [];
  out.push(...header);
  out.push(...encodeCompactU16(keyBytes.length));
  for (const kb of keyBytes) out.push(...key(kb));
  out.push(...key(blockhashByte));
  out.push(...encodeCompactU16(ixs.length));
  for (const ix of ixs) {
    out.push(ix.prog);
    out.push(...encodeCompactU16(ix.accts.length));
    out.push(...ix.accts);
    out.push(...encodeCompactU16(ix.data.length));
    out.push(...ix.data);
  }
  return Uint8Array.from(out);
}

/** Hand-build a raw v0 message with address-table lookups. */
export function v0Bytes(
  header: [number, number, number],
  keyBytes: number[],
  ixs: IxSpec[],
  luts: LutSpec[],
  blockhashByte = 250,
): Uint8Array {
  const out: number[] = [];
  out.push(0x80); // v0 version prefix
  out.push(...header);
  out.push(...encodeCompactU16(keyBytes.length));
  for (const kb of keyBytes) out.push(...key(kb));
  out.push(...key(blockhashByte));
  out.push(...encodeCompactU16(ixs.length));
  for (const ix of ixs) {
    out.push(ix.prog);
    out.push(...encodeCompactU16(ix.accts.length));
    out.push(...ix.accts);
    out.push(...encodeCompactU16(ix.data.length));
    out.push(...ix.data);
  }
  out.push(...encodeCompactU16(luts.length));
  for (const lut of luts) {
    out.push(...key(lut.table));
    out.push(...encodeCompactU16(lut.writable.length));
    out.push(...lut.writable);
    out.push(...encodeCompactU16(lut.readonly.length));
    out.push(...lut.readonly);
  }
  return Uint8Array.from(out);
}

export function toB64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64");
}

export function listFixtures(): string[] {
  return readdirSync(FIXTURES)
    .filter((f) => f.endsWith(".b64"))
    .sort()
    .map((f) => f.replace(/\.b64$/, ""));
}

export function readFixtureB64(name: string): string {
  return readFileSync(join(FIXTURES, `${name}.b64`), "utf8").trim();
}

export function readFixtureGolden(name: string): unknown {
  return JSON.parse(
    readFileSync(join(FIXTURES, `${name}.verdict.json`), "utf8"),
  );
}

export function listRealFixtures(): string[] {
  let entries: string[];
  try {
    entries = readdirSync(REAL_FIXTURES);
  } catch {
    return [];
  }
  return entries
    .filter((f) => f.endsWith(".b64"))
    .sort()
    .map((f) => f.replace(/\.b64$/, ""));
}

export function readRealFixtureB64(name: string): string {
  return readFileSync(join(REAL_FIXTURES, `${name}.b64`), "utf8").trim();
}

export function readRealFixtureMeta(name: string): {
  signature: string;
  slot: number;
  cluster: string;
  capturedDate: string;
  source: string;
  version: "legacy" | 0;
  altCount: number;
  numStaticKeys: number;
  programIds: string[];
} {
  return JSON.parse(
    readFileSync(join(REAL_FIXTURES, `${name}.meta.json`), "utf8"),
  );
}
