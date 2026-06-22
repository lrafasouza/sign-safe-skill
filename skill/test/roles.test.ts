/**
 * roles.test.ts -- account-role derivation (CORRECTNESS-SPEC section B).
 * Golden SDK vectors T5.1 (is_writable_index), T5.2 (is_maybe_writable demotion),
 * T5.3 (program-id demotion flip), T5.4 (multi-lookup ordering), T5.5 (reserved
 * vs Incinerator), T5.7 (loaded positional writability).
 */

import { describe, it, expect } from "vitest";
import {
  deriveRoles,
  isWritableIndex,
  RESERVED_ACCOUNT_KEYS,
  INCINERATOR,
} from "../src/roles.ts";
import { decodeMessageBytes } from "../src/decode.ts";
import { v0Bytes, legacyBytes, key } from "./helpers.ts";
import { base58Encode } from "../src/decode.ts";

const BPF_LOADER_UPGRADEABLE = "BPFLoaderUpgradeab1e11111111111111111111111";
const SYSTEM = "11111111111111111111111111111111";

describe("T5.1 test_is_writable_index golden (R3/R4/R8)", () => {
  // 4 static + 1 W-loaded + 1 R-loaded; header S=2, Rs=1, Ru=1.
  const msg = decodeMessageBytes(
    v0Bytes(
      [2, 1, 1],
      [1, 2, 3, 4], // 4 distinct static keys
      [],
      [{ table: 50, writable: [9], readonly: [8] }], // 1 writable + 1 readonly loaded
    ),
  );
  const roles = deriveRoles(msg); // None mode: partition only

  it("is_writable_index true at 0,2,4 and false at 1,3,5", () => {
    const writable = roles.map((r) => r.writablePartition);
    expect(writable).toEqual([true, false, true, false, true, false]);
  });

  it("is_signer true only at 0,1", () => {
    const signer = roles.map(
      (r) => r.role === "signer-writable" || r.role === "signer-readonly",
    );
    expect(signer).toEqual([true, true, false, false, false, false]);
  });

  it("matches the raw isWritableIndex helper for every combined index", () => {
    const args = {
      numRequiredSignatures: 2,
      numReadonlySignedAccounts: 1,
      numReadonlyUnsignedAccounts: 1,
      numStaticKeys: 4,
      numLoadedWritable: 1,
    };
    expect([0, 1, 2, 3, 4, 5].map((i) => isWritableIndex(i, args))).toEqual([
      true, false, true, false, true, false,
    ]);
  });
});

describe("T5.2 test_is_maybe_writable demotion golden (R5/R6/R9)", () => {
  // SDK legacy.rs `test_is_maybe_writable`: header S=3, Rs=2, Ru=1, K=7. The
  // assertions are all on is_maybe_writable(i, Some(reserved)) (the DEMOTED
  // result), except index 3 which is checked under both None and Some:
  //   Some: 0 W; 1,2 RO; 3 RO; 4 W; 5,6 RO.   None: 3 W.
  // The partition math puts writable-unsigned at [S, K-Ru) = [3, 6) (indices
  // 3,4,5 writable) and readonly at [6,7) (index 6). So indices 3 AND 5 are
  // readonly-under-Some ONLY via reserved-key demotion, while index 4 stays
  // writable. We therefore place reserved keys (distinct sysvars/System) at
  // indices 3 and 5; index 6 is readonly by partition anyway.
  function buildMsg() {
    const out: number[] = [];
    out.push(3, 2, 1); // header S=3, Rs=2, Ru=1
    out.push(7); // 7 static keys
    // idx0 fee payer, idx1,2 readonly signers, idx3 reserved, idx4 plain,
    // idx5 reserved, idx6 plain (readonly by partition).
    out.push(...key(10)); // 0
    out.push(...key(11)); // 1
    out.push(...key(12)); // 2
    out.push(...new Array(32).fill(0)); // 3 = System (reserved)
    out.push(...key(14)); // 4
    out.push(...padTo32(sysvarRentBytes())); // 5 = SysvarRent (reserved)
    out.push(...key(16)); // 6
    out.push(...key(250)); // blockhash
    out.push(0); // no instructions
    return Uint8Array.from(out);
  }
  const msg = decodeMessageBytes(buildMsg());

  it("index 3 (reserved key): writable with None, readonly after demotion", () => {
    const none = deriveRoles(msg); // is_maybe_writable(i, None)
    const some = deriveRoles(msg, { reservedAccountKeys: RESERVED_ACCOUNT_KEYS });
    expect(msg.staticAccountKeys[3]).toBe(SYSTEM);
    expect(none[3]!.writablePartition).toBe(true);
    expect(none[3]!.writableRuntime).toBe(true); // None mode: no demotion
    expect(some[3]!.writablePartition).toBe(true);
    expect(some[3]!.writableRuntime).toBe(false); // demoted by reserved set
    expect(some[3]!.demotedToReadonly).toBe(true);
    expect(some[3]!.role).toBe("readonly");
  });

  it("partition (None): writable-unsigned region is [3,6); index 6 readonly", () => {
    const none = deriveRoles(msg);
    const w = none.map((r) => r.writablePartition);
    expect(w).toEqual([true, false, false, true, true, true, false]);
  });

  it("demoted (Some): is_maybe_writable matches the SDK assertions exactly", () => {
    const some = deriveRoles(msg, { reservedAccountKeys: RESERVED_ACCOUNT_KEYS });
    const w = some.map((r) => r.writableRuntime);
    // 0 W; 1,2 RO; 3 RO(reserved); 4 W; 5 RO(reserved); 6 RO(partition).
    expect(w).toEqual([true, false, false, false, true, false, false]);
  });
});

describe("T5.3 program-id demotion flip (R5 branch b)", () => {
  // A program account sits in the writable-non-signer partition and is called as
  // a program. With the upgradeable loader ABSENT it resolves READONLY; adding
  // the loader to the combined list flips it back to WRITABLE.
  // header [1,0,1]: idx0 writable signer (fee payer); idx1 writable non-signer
  // ... we need the program in a WRITABLE partition. With K=2, S=1, Ru=1:
  //   writable-nonsigner region [S=1, K-Ru=1) -> EMPTY. So use K=3, Ru=1:
  //   region [1, 2) writable; idx2 readonly. Put program at idx1 (writable),
  //   and have an instruction call programIdIndex=1.
  function build(withLoader: boolean) {
    // keys: idx0 fee payer (byte 1), idx1 program (byte 2), idx2 something.
    // If withLoader, make idx2 the upgradeable loader.
    const out: number[] = [];
    out.push(1, 0, 1); // S=1, Rs=0, Ru=1 => idx0 writable signer, idx1 writable, idx2 readonly
    out.push(3);
    out.push(...key(1)); // idx0 fee payer
    out.push(...key(2)); // idx1 program (writable partition)
    if (withLoader) {
      // idx2 = BPF Loader Upgradeable. Encode its real bytes.
      out.push(...Array.from(loaderBytes()));
    } else {
      out.push(...key(3)); // idx2 arbitrary readonly
    }
    out.push(...key(250));
    out.push(1); // 1 instruction
    out.push(1); // programIdIndex = 1
    out.push(0); // 0 accounts
    out.push(0); // 0 data
    return Uint8Array.from(out);
  }

  it("program in writable partition demotes to readonly when loader absent", () => {
    const msg = decodeMessageBytes(build(false));
    const roles = deriveRoles(msg, { reservedAccountKeys: RESERVED_ACCOUNT_KEYS });
    expect(roles[1]!.writablePartition).toBe(true);
    expect(roles[1]!.writableRuntime).toBe(false);
    expect(roles[1]!.demotedToReadonly).toBe(true);
  });

  it("same program flips back to writable when the upgradeable loader is present", () => {
    const msg = decodeMessageBytes(build(true));
    expect(msg.staticAccountKeys.includes(BPF_LOADER_UPGRADEABLE)).toBe(true);
    const roles = deriveRoles(msg, { reservedAccountKeys: RESERVED_ACCOUNT_KEYS });
    expect(roles[1]!.writablePartition).toBe(true);
    expect(roles[1]!.writableRuntime).toBe(true);
    expect(roles[1]!.demotedToReadonly).toBe(false);
  });
});

describe("T5.4 / T5.7 multi-lookup ordering + loaded positional writability (R1/R4/R11)", () => {
  // Two ALTs each contributing 2 writable + 1 readonly => combined order
  // [static...][W t0][W t1][R t0][R t1].
  const msg = decodeMessageBytes(
    v0Bytes(
      [1, 0, 0],
      [1], // single static key (fee payer)
      [],
      [
        { table: 60, writable: [11, 12], readonly: [31] },
        { table: 61, writable: [21, 22], readonly: [41] },
      ],
    ),
  );
  const roles = deriveRoles(msg, { reservedAccountKeys: RESERVED_ACCOUNT_KEYS });

  it("flattens all writable across tables, then all readonly", () => {
    const altAddrs = roles.filter((r) => !r.addressVerified).map((r) => r.address);
    expect(altAddrs).toEqual([
      `alt:${base58Encode(Uint8Array.from(key(60)))}#w11`,
      `alt:${base58Encode(Uint8Array.from(key(60)))}#w12`,
      `alt:${base58Encode(Uint8Array.from(key(61)))}#w21`,
      `alt:${base58Encode(Uint8Array.from(key(61)))}#w22`,
      `alt:${base58Encode(Uint8Array.from(key(60)))}#r31`,
      `alt:${base58Encode(Uint8Array.from(key(61)))}#r41`,
    ]);
  });

  it("loaded account at i is writable iff (i-K) < W (T5.7)", () => {
    // K=1, W=4. Combined indices 1..4 writable; 5..6 readonly.
    expect(roles.map((r) => r.writablePartition)).toEqual([
      true, // static fee payer
      true,
      true,
      true,
      true, // [1,4] writable region
      false,
      false, // readonly region
    ]);
  });

  it("ALT-loaded accounts have addressVerified=false but a real writable/readonly role", () => {
    const loaded = roles.filter((r) => !r.addressVerified);
    expect(loaded.length).toBe(6);
    expect(loaded.slice(0, 4).every((r) => r.role === "writable")).toBe(true);
    expect(loaded.slice(4).every((r) => r.role === "readonly")).toBe(true);
  });
});

describe("T5.5 reserved-key vs Incinerator (R7)", () => {
  // System Program in a writable partition resolves READONLY with a reserved set;
  // the Incinerator stays WRITABLE.
  function build(idx1Byte: "system" | "incinerator") {
    const out: number[] = [];
    out.push(1, 0, 1); // S=1, Rs=0, Ru=1 => idx1 writable non-signer, idx2 readonly
    out.push(3);
    out.push(...key(1)); // fee payer
    if (idx1Byte === "system") out.push(...new Array(32).fill(0)); // System
    else out.push(...incineratorBytes());
    out.push(...key(3)); // idx2 readonly
    out.push(...key(250));
    out.push(0); // no instructions (so not called-as-program)
    return Uint8Array.from(out);
  }

  it("System Program in writable partition is demoted to readonly", () => {
    const msg = decodeMessageBytes(build("system"));
    expect(msg.staticAccountKeys[1]).toBe(SYSTEM);
    const roles = deriveRoles(msg, { reservedAccountKeys: RESERVED_ACCOUNT_KEYS });
    expect(roles[1]!.writablePartition).toBe(true);
    expect(roles[1]!.writableRuntime).toBe(false);
  });

  it("Incinerator stays WRITABLE even with the reserved set applied", () => {
    const msg = decodeMessageBytes(build("incinerator"));
    expect(msg.staticAccountKeys[1]).toBe(INCINERATOR);
    expect(RESERVED_ACCOUNT_KEYS.has(INCINERATOR)).toBe(false);
    const roles = deriveRoles(msg, { reservedAccountKeys: RESERVED_ACCOUNT_KEYS });
    expect(roles[1]!.writablePartition).toBe(true);
    expect(roles[1]!.writableRuntime).toBe(true);
    expect(roles[1]!.demotedToReadonly).toBe(false);
  });
});

// ---- helpers to embed real program-id bytes -------------------------------

function decodeBase58ToBytes(b58: string): Uint8Array {
  // tiny base58 decode (Bitcoin alphabet) for test key embedding
  const ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  const map: Record<string, number> = {};
  for (let i = 0; i < ALPHABET.length; i++) map[ALPHABET[i]!] = i;
  let bytes: number[] = [0];
  for (const ch of b58) {
    let carry = map[ch]!;
    for (let j = 0; j < bytes.length; j++) {
      carry += bytes[j]! * 58;
      bytes[j] = carry & 0xff;
      carry >>= 8;
    }
    while (carry > 0) {
      bytes.push(carry & 0xff);
      carry >>= 8;
    }
  }
  // leading '1's -> leading zero bytes
  for (const ch of b58) {
    if (ch === "1") bytes.push(0);
    else break;
  }
  return Uint8Array.from(bytes.reverse());
}

function loaderBytes(): Uint8Array {
  const b = decodeBase58ToBytes(BPF_LOADER_UPGRADEABLE);
  return padTo32(b);
}
function incineratorBytes(): Uint8Array {
  return padTo32(decodeBase58ToBytes(INCINERATOR));
}
function sysvarRentBytes(): Uint8Array {
  return padTo32(decodeBase58ToBytes("SysvarRent111111111111111111111111111111111"));
}
function padTo32(b: Uint8Array): Uint8Array {
  if (b.length === 32) return b;
  const out = new Uint8Array(32);
  out.set(b, 32 - b.length);
  return out;
}
