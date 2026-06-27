/**
 * run.ts -- the offline, deterministic test runner.
 *
 * Four kinds of checks, all offline, all deterministic:
 *
 *   1. GOLDEN      -- for each NN_name.b64, decode + verdict with OUR core and
 *                     deep-equal the result against the golden NN_name.verdict.json.
 *   2. CROSS-CHECK -- for >=2 fixtures, deserialize the SAME bytes with
 *                     @solana/web3.js and assert our decoded program ids and
 *                     static account keys match web3.js's. Proves the parser is
 *                     correct against an independent implementation.
 *   3. DETERMINISM -- run the full decode+verdict twice and assert identical JSON.
 *   4. FAIL-CLOSED -- feed truncated/garbage base64 and assert a REJECT verdict
 *                     with decodeFailed=true, and that nothing throws uncaught.
 *
 * Exit code is nonzero if any check fails.
 */

import { readFileSync, readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { deepStrictEqual } from "node:assert";
import { VersionedMessage } from "@solana/web3.js";

import { reviewBase64, verdictToJson } from "../src/verdict.ts";
import {
  decodeBase64Message,
  decodeMessageBytes,
  base58Encode,
} from "../src/decode.ts";
import { deriveRoles } from "../src/roles.ts";
import { findBannedPhrase } from "../src/banned.ts";

const HERE = dirname(fileURLToPath(import.meta.url));
const FIXTURES = join(HERE, "..", "fixtures");

let passed = 0;
let failed = 0;

function ok(name: string): void {
  passed++;
  process.stdout.write(`  PASS  ${name}\n`);
}
function bad(name: string, detail: string): void {
  failed++;
  process.stdout.write(`  FAIL  ${name}\n        ${detail}\n`);
}

function listFixtures(): string[] {
  return readdirSync(FIXTURES)
    .filter((f) => f.endsWith(".b64"))
    .sort()
    .map((f) => f.replace(/\.b64$/, ""));
}

// ---- 1. GOLDEN --------------------------------------------------------------

function runGolden(names: string[]): void {
  process.stdout.write(
    "\n[1] Golden verdicts (our core vs committed verdict.json)\n",
  );
  for (const name of names) {
    const b64 = readFileSync(join(FIXTURES, `${name}.b64`), "utf8");
    const golden = JSON.parse(
      readFileSync(join(FIXTURES, `${name}.verdict.json`), "utf8"),
    );
    const actual = JSON.parse(verdictToJson(reviewBase64(b64)));
    try {
      deepStrictEqual(actual, golden);
      ok(`${name} -> ${golden.decision}`);
    } catch (e) {
      bad(name, (e as Error).message.split("\n").slice(0, 6).join(" "));
    }
  }
}

// ---- 2. CROSS-CHECK against @solana/web3.js --------------------------------

function runCrossCheck(names: string[]): void {
  process.stdout.write(
    "\n[2] Cross-validation (our parser vs @solana/web3.js)\n",
  );
  // Cross-check EVERY fixture against the independent web3.js deserializer, not
  // a hand-picked subset. The parser and the fixture generator must agree with
  // a third implementation on every byte stream, so a regression in either one
  // cannot quietly co-evolve undetected.
  const chosen = names;
  if (chosen.length < 2) {
    bad("cross-check", "fewer than 2 cross-check fixtures available");
    return;
  }
  for (const name of chosen) {
    const b64 = readFileSync(join(FIXTURES, `${name}.b64`), "utf8").trim();
    const raw = new Uint8Array(Buffer.from(b64, "base64"));
    const w3 = VersionedMessage.deserialize(raw);
    const mine = decodeBase64Message(b64);

    const w3Keys = w3.staticAccountKeys.map((k) => k.toBase58());
    const w3Progs = w3.compiledInstructions.map(
      (ci) => w3Keys[ci.programIdIndex],
    );
    const myProgs = mine.instructions.map((i) => i.programId);
    const w3Version = w3.version === "legacy" ? "legacy" : w3.version;

    try {
      deepStrictEqual(mine.staticAccountKeys, w3Keys);
      deepStrictEqual(myProgs, w3Progs);
      deepStrictEqual(mine.version, w3Version);
      deepStrictEqual(
        mine.addressTableLookups.length,
        w3.addressTableLookups.length,
      );
      ok(
        `${name}: static keys + program ids + version + ALT count match web3.js`,
      );
    } catch (e) {
      bad(
        `${name} cross-check`,
        (e as Error).message.split("\n").slice(0, 6).join(" "),
      );
    }
  }
}

// ---- 2b. CROSS-CHECK against @solana/kit (modern stack) ---------------------

/**
 * Second, fully independent cross-check against @solana/kit (the current
 * @solana/web3.js@2 successor). kit's getCompiledTransactionMessageDecoder
 * decodes the SAME serialized message bytes our parser consumes, so agreeing
 * with BOTH web3.js (v1) and kit (v2) on every fixture proves our wire parser
 * is correct against two separate, current implementations -- not merely
 * self-consistent, and not pinned to a single legacy library.
 *
 * Graceful: if @solana/kit is not installed (e.g. a minimal checkout), the
 * section reports a SKIP rather than failing, so the offline no-install review
 * flow stays green. kit IS a declared dependency, so CI exercises it.
 */
async function runKitCrossCheck(names: string[]): Promise<void> {
  process.stdout.write(
    "\n[2b] Cross-validation (our parser vs @solana/kit, modern stack)\n",
  );
  let kit: typeof import("@solana/kit");
  try {
    kit = await import("@solana/kit");
  } catch {
    process.stdout.write(
      "  SKIP  @solana/kit not installed (run `npm install` to enable)\n",
    );
    return;
  }
  const decoder = kit.getCompiledTransactionMessageDecoder();
  for (const name of names) {
    const b64 = readFileSync(join(FIXTURES, `${name}.b64`), "utf8").trim();
    const raw = new Uint8Array(Buffer.from(b64, "base64"));
    const km = decoder.decode(raw) as {
      version: number | "legacy";
      staticAccounts: string[];
      instructions: Array<{ programAddressIndex: number }>;
      addressTableLookups?: unknown[];
    };
    const mine = decodeBase64Message(b64);

    const kitKeys = km.staticAccounts.map((a) => a.toString());
    const kitProgs = km.instructions.map((i) => kitKeys[i.programAddressIndex]);
    const myProgs = mine.instructions.map((i) => i.programId);
    const kitAlts = km.addressTableLookups?.length ?? 0;

    try {
      deepStrictEqual(mine.staticAccountKeys, kitKeys);
      deepStrictEqual(myProgs, kitProgs);
      deepStrictEqual(mine.version, km.version);
      deepStrictEqual(mine.addressTableLookups.length, kitAlts);
      ok(
        `${name}: static keys + program ids + version + ALT count match @solana/kit`,
      );
    } catch (e) {
      bad(
        `${name} kit cross-check`,
        (e as Error).message.split("\n").slice(0, 6).join(" "),
      );
    }
  }
}

// ---- 3. DETERMINISM ---------------------------------------------------------

function runDeterminism(names: string[]): void {
  process.stdout.write(
    "\n[3] Determinism (same bytes -> identical JSON, twice)\n",
  );
  for (const name of names) {
    const b64 = readFileSync(join(FIXTURES, `${name}.b64`), "utf8");
    const a = verdictToJson(reviewBase64(b64));
    const b = verdictToJson(reviewBase64(b64));
    if (a === b) ok(`${name} stable`);
    else bad(`${name} determinism`, "two runs produced different JSON");
  }
}

// ---- 4. FAIL-CLOSED ---------------------------------------------------------

function runFailClosed(): void {
  process.stdout.write(
    "\n[4] Fail-closed (malformed input -> REJECT, never throws)\n",
  );
  const cases: Array<{ label: string; input: string }> = [
    { label: "empty string", input: "" },
    { label: "garbage non-base64", input: "!!!! not base64 @@@@" },
    {
      label: "truncated legacy message",
      input: truncated("01_safe_sol_transfer"),
    },
    { label: "truncated v0 message", input: truncated("09_v0_alt_unverified") },
    {
      label: "random base64 bytes",
      input: Buffer.from([0xff, 0xfe, 0xfd, 0x10, 0x20]).toString("base64"),
    },
    {
      label: "trailing-byte tamper",
      input: tampered("02_setauthority_reject"),
    },
  ];
  for (const c of cases) {
    let verdict;
    try {
      verdict = reviewBase64(c.input);
    } catch (e) {
      bad(c.label, `threw uncaught: ${(e as Error).message}`);
      continue;
    }
    if (verdict.decision === "REJECT" && verdict.flags.decodeFailed) {
      ok(`${c.label} -> REJECT (decodeFailed)`);
    } else {
      bad(c.label, `expected REJECT+decodeFailed, got ${verdict.decision}`);
    }
  }
}

/** Chop a fixture's bytes in half to simulate truncation. */
function truncated(name: string): string {
  const b64 = readFileSync(join(FIXTURES, `${name}.b64`), "utf8").trim();
  const raw = Buffer.from(b64, "base64");
  return raw
    .subarray(0, Math.max(1, Math.floor(raw.length / 2)))
    .toString("base64");
}

/** Append junk bytes so the parser sees trailing data and must reject. */
function tampered(name: string): string {
  const b64 = readFileSync(join(FIXTURES, `${name}.b64`), "utf8").trim();
  const raw = Buffer.from(b64, "base64");
  return Buffer.concat([raw, Buffer.from([0x00, 0x01, 0x02])]).toString(
    "base64",
  );
}

// ---- 5. BANNED PHRASES ------------------------------------------------------

/**
 * No verdict-emitted prose may contain a banned reassurance phrase. We assert
 * this directly over every fixture's verdict (reason + all finding strings),
 * and we also sanity-check the matcher itself so it cannot silently degrade to
 * "matches nothing".
 */
function runBannedPhrases(names: string[]): void {
  process.stdout.write(
    "\n[5] Banned-phrase enforcement (no reassurance in any verdict)\n",
  );

  // Matcher sanity: standalone reassurance words ARE caught...
  const positives = [
    "this is safe to sign",
    "no risk here",
    "looks fine to me",
    "nothing dangerous found",
  ];
  // ...but the skill name and allowed compounds are NOT false positives.
  const negatives = [
    "sign-safe/verdict@1",
    "the sign-safe gate is fail-closed",
    "value-bearing account",
    "recognized instructions within thresholds",
  ];
  let matcherOk = true;
  for (const p of positives)
    if (findBannedPhrase(p) === null) {
      matcherOk = false;
      bad("banned matcher", `missed banned phrase in: ${p}`);
    }
  for (const nstr of negatives)
    if (findBannedPhrase(nstr) !== null) {
      matcherOk = false;
      bad("banned matcher", `false positive on: ${nstr}`);
    }
  if (matcherOk)
    ok("matcher catches reassurance words but not the skill name / compounds");

  for (const name of names) {
    const b64 = readFileSync(join(FIXTURES, `${name}.b64`), "utf8");
    const v = reviewBase64(b64);
    const fields = [
      v.reason,
      ...v.findings.flatMap((f) => [f.label, f.detail, f.mapsToLoss]),
    ];
    const hit =
      fields.map((t) => findBannedPhrase(t)).find((h) => h !== null) ?? null;
    if (hit === null) ok(`${name}: no banned phrase in verdict prose`);
    else bad(`${name} banned phrase`, `found "${hit}"`);
  }
}

// ---- 6. BEHAVIORAL GUARDS (synthetic messages) ------------------------------

function u8(n: number): number[] {
  return [n & 0xff];
}
function u32le(n: number): number[] {
  return [n & 0xff, (n >>> 8) & 0xff, (n >>> 16) & 0xff, (n >>> 24) & 0xff];
}
function u64le(n: bigint): number[] {
  const out: number[] = [];
  for (let i = 0; i < 8; i++) {
    out.push(Number(n & 0xffn));
    n >>= 8n;
  }
  return out;
}
function key(byte: number): number[] {
  return new Array(32).fill(byte);
}

/**
 * Hand-build a raw legacy message. header = [numSigners, roSigned, roUnsigned];
 * keys is an array of 32-byte filler bytes; ixs are { prog, accts, data }.
 */
function legacyBytes(
  header: [number, number, number],
  keyBytes: number[],
  ixs: Array<{ prog: number; accts: number[]; data: number[] }>,
): Uint8Array {
  const out: number[] = [];
  out.push(...header);
  out.push(keyBytes.length); // compact-u16 (small => 1 byte)
  for (const kb of keyBytes) out.push(...key(kb));
  out.push(...key(250)); // blockhash
  out.push(ixs.length);
  for (const ix of ixs) {
    out.push(ix.prog);
    out.push(ix.accts.length);
    out.push(...ix.accts);
    out.push(ix.data.length);
    out.push(...ix.data);
  }
  return Uint8Array.from(out);
}

/**
 * Hand-build a raw v0 message with address-table lookups so we can exercise the
 * unknown-program-via-ALT and multi-table ALT-ordering paths precisely.
 */
function v0Bytes(
  header: [number, number, number],
  keyBytes: number[],
  ixs: Array<{ prog: number; accts: number[]; data: number[] }>,
  luts: Array<{ table: number; writable: number[]; readonly: number[] }>,
): Uint8Array {
  const out: number[] = [];
  out.push(0x80); // v0
  out.push(...header);
  out.push(keyBytes.length);
  for (const kb of keyBytes) out.push(...key(kb));
  out.push(...key(250));
  out.push(ixs.length);
  for (const ix of ixs) {
    out.push(ix.prog);
    out.push(ix.accts.length);
    out.push(...ix.accts);
    out.push(ix.data.length);
    out.push(...ix.data);
  }
  out.push(luts.length);
  for (const lut of luts) {
    out.push(...key(lut.table));
    out.push(lut.writable.length);
    out.push(...lut.writable);
    out.push(lut.readonly.length);
    out.push(...lut.readonly);
  }
  return Uint8Array.from(out);
}

function b64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64");
}

function runBehavioral(): void {
  process.stdout.write(
    "\n[6] Behavioral guards (decoder & verdict fail-closed correctness)\n",
  );

  // a) Outflow precision: a System Transfer above 2^53 lamports must survive as
  //    an EXACT decimal string (a JS number would round it).
  {
    // Construct a message where program-id index 0 resolves to the real System
    // base58 by placing 32 zero bytes as key[0] (the System program id is all
    // zeroes -> base58 "111...1"). signer is key[1].
    const big = 9_007_199_254_740_993n; // 2^53 + 1
    const data = [...u32le(2), ...u64le(big)];
    // keys: [signer(1), system(0), recipient(2)]
    // header: 1 signer, 0 ro-signed, 1 ro-unsigned => index 0 signer-writable,
    // index 1 writable, index 2 readonly. The System program id is key index 1
    // (all-zero key -> base58 "111..."). The funding account (accts[0]) must be
    // the signer at index 0.
    const keyBytes = [1, 0, 2];
    const bytes = legacyBytes([1, 0, 1], keyBytes, [
      { prog: 1, accts: [0, 2], data },
    ]);
    const v = reviewBase64(b64(bytes));
    if (v.outflow.lamports === big.toString()) {
      ok(`outflow preserves ${big} lamports exactly as a string`);
    } else {
      bad(
        "outflow precision",
        `expected "${big}", got "${v.outflow.lamports}"`,
      );
    }
    if (v.decision === "HOLD" && v.outflow.exceedsLamportThreshold) {
      ok("large outflow above 2^53 still triggers HOLD");
    } else {
      bad("outflow threshold", `expected HOLD/exceeds, got ${v.decision}`);
    }
  }

  // b) Unknown program writing ONLY to an ALT-sourced account must not SIGN
  //    (the ALT-hiding attack). In DEFAULT mode -> HOLD; in STRICT mode -> REJECT.
  //    Neither SIGNs. The key invariant: fail-closed on unknown programs.
  {
    // keys: [signer(0)] only; an unknown program id at index... we need an
    // unknown program in the STATIC set. Put unknown program at key index 1.
    // header: 1 signer, 0 ro-signed, 1 ro-unsigned => key[1] readonly (program).
    // The instruction references account index 1 (>= numStaticKeys? no, =1<2).
    // We need the referenced account to be ALT-sourced: index >= numStaticKeys.
    // numStaticKeys = 2, so account index 2 is the first ALT writable entry.
    const ix = { prog: 1, accts: [2], data: [9, 9, 9] }; // unknown prog -> 1 ALT acct
    const bytes = v0Bytes(
      [1, 0, 1],
      [0, 77], // key[0]=signer (all-zero=system, but it's only the payer/signer), key[1]=unknown prog filler 77
      [ix],
      [{ table: 50, writable: [0], readonly: [] }], // one ALT writable -> account index 2
    );
    const v = reviewBase64(b64(bytes));
    // key[1] (filler 77) is not a known program -> unknown; it touches account
    // index 2 which is ALT-sourced -> must be treated as writable.
    // DEFAULT mode: unknownProgramWritable → HOLD (not SIGN, not REJECT).
    // The fail-closed invariant: never SIGN when an unknown program writes.
    if (
      (v.decision === "HOLD" || v.decision === "REJECT") &&
      v.flags.unknownProgramPresent
    ) {
      ok(
        "unknown program touching only an ALT-sourced account -> not SIGN (ALT-hiding closed, DEFAULT=HOLD)",
      );
    } else {
      bad(
        "alt-hiding",
        `expected HOLD or REJECT (not SIGN), got ${v.decision} (flags=${JSON.stringify(v.flags)})`,
      );
    }
  }

  // c) BPF Loader Upgradeable matched on the FULL u32 tag, not byte[0]. A
  //    crafted [3,1,0,0] is NOT a clean Upgrade(3) and must not match.
  {
    // u32-tag programs (System, BPF Loader Upgradeable) must match on the FULL
    // 4-byte tag, never on byte[0]. The BPF-Upgrade positive is golden 03; here
    // we assert the negative on the same code path: a System payload whose tag
    // bytes are [2,1,0,0] is NOT a clean Transfer(2) and must not be classified
    // as one (byte[0] spoofing closed). u32 LE [2,1,0,0] = 258 != 2.
    const data = [2, 1, 0, 0, ...u64le(5_000_000_000n)]; // corrupt u32 tag
    const keyBytes = [0, 1, 2]; // system(0), signer(1), recipient(2)
    const bytes = legacyBytes([1, 0, 1], keyBytes, [
      { prog: 0, accts: [1, 2], data },
    ]);
    const v = reviewBase64(b64(bytes));
    // tag != 2 -> not a Transfer -> no large-transfer finding, outflow stays 0.
    if (
      v.outflow.lamports === "0" &&
      !v.findings.some((f) => f.id === "system-large-transfer")
    ) {
      ok(
        "u32-tag programs reject crafted [tag,1,0,0] (byte[0] spoofing closed)",
      );
    } else {
      bad(
        "u32-tag strictness",
        `crafted tag leaked: ${JSON.stringify(v.outflow)}`,
      );
    }
  }

  // d) durable-nonce-initialize detail distinguishes Initialize(6) vs Authorize(7).
  {
    for (const [tag, wantVariant] of [
      [6, "InitializeNonceAccount"],
      [7, "AuthorizeNonceAccount"],
    ] as const) {
      const data = u32le(tag);
      const keyBytes = [0, 1, 2]; // system(0), signer(1), nonce-acct(2)
      const bytes = legacyBytes([1, 0, 1], keyBytes, [
        { prog: 0, accts: [2, 1], data },
      ]);
      const v = reviewBase64(b64(bytes));
      const f = v.findings.find((x) => x.id === "durable-nonce-initialize");
      if (
        f &&
        f.detail.includes(String(tag)) &&
        f.detail.includes(wantVariant)
      ) {
        ok(`nonce tag ${tag} detail names ${wantVariant}`);
      } else {
        bad(
          "nonce variant detail",
          `tag ${tag}: ${f ? f.detail : "no finding"}`,
        );
      }
    }
  }

  // e) Multi-table ALT roles follow Solana's canonical two-pass order:
  //    [static] then ALL writable across tables, then ALL readonly across tables.
  {
    // 2 tables, each with 1 writable + 1 readonly.
    const bytes = v0Bytes(
      [1, 0, 0],
      [0], // single static key (signer)
      [], // no instructions needed for role-order check
      [
        { table: 60, writable: [11], readonly: [12] },
        { table: 61, writable: [21], readonly: [22] },
      ],
    );
    const msg = decodeMessageBytes(bytes);
    const roles = deriveRoles(msg);
    // static index 0, then writables (tables in order), then readonlies.
    const altRoles = roles.filter((r) => !r.verified).map((r) => r.address);
    const expected = [
      "alt:" + base58Of(60) + "#w11",
      "alt:" + base58Of(61) + "#w21",
      "alt:" + base58Of(60) + "#r12",
      "alt:" + base58Of(61) + "#r22",
    ];
    try {
      deepStrictEqual(altRoles, expected);
      ok(
        "multi-table ALT roles use canonical writable-then-readonly two-pass order",
      );
    } catch (e) {
      bad(
        "alt role order",
        (e as Error).message.split("\n").slice(0, 4).join(" "),
      );
    }
  }

  // f) An instruction account index beyond the resolvable account set is a
  //    decode error -> fail-closed REJECT (was previously accepted as a HOLD).
  {
    // legacy, 2 static keys, instruction references account index 200.
    const bytes = legacyBytes(
      [1, 0, 1],
      [1, 5],
      [{ prog: 1, accts: [200], data: [0] }],
    );
    const v = reviewBase64(b64(bytes));
    if (v.decision === "REJECT" && v.flags.decodeFailed) {
      ok("out-of-range instruction account index -> REJECT (decodeFailed)");
    } else {
      bad("oob acct index", `expected REJECT+decodeFailed, got ${v.decision}`);
    }
  }
}

/** base58 of a 32-byte all-`byte` key, matching decode.ts's encoder output. */
function base58Of(byte: number): string {
  const bytes = Uint8Array.from(new Array(32).fill(byte));
  // Reuse the production encoder for exactness.
  return base58Encode(bytes);
}

// ---- main -------------------------------------------------------------------

async function main(): Promise<void> {
  const names = listFixtures();
  process.stdout.write(`sign-safe test suite -- ${names.length} fixtures\n`);

  runGolden(names);
  runCrossCheck(names);
  await runKitCrossCheck(names);
  runDeterminism(names);
  runFailClosed();
  runBannedPhrases(names);
  runBehavioral();

  process.stdout.write(`\n----------------------------------------\n`);
  process.stdout.write(`PASS ${passed}   FAIL ${failed}\n`);
  if (failed > 0) {
    process.stdout.write("RESULT: FAILED\n");
    process.exit(1);
  }
  process.stdout.write("RESULT: ALL GREEN\n");
}

main().catch((e) => {
  // The runner itself must never crash silently; surface any unexpected error
  // as a hard failure with a nonzero exit code.
  process.stderr.write(`test runner crashed: ${(e as Error).stack ?? e}\n`);
  process.exit(1);
});
