import { describe, expect, it } from "vitest";
import verdictSchema from "../schema/verdict.schema.json" with { type: "json" };
import { decodeInput } from "../src/decode.ts";
import { handleMcpRequest } from "../src/mcp.ts";
import { reviewBase64 } from "../src/verdict.ts";
import {
  key,
  listFixtures,
  readFixtureB64,
  readFixtureGolden,
  toB64,
  u32le,
} from "./helpers.ts";

type JsonValue =
  | null
  | boolean
  | number
  | string
  | JsonValue[]
  | { [key: string]: JsonValue };

type JsonObject = { [key: string]: JsonValue };

const verdictSchemaJson = verdictSchema as unknown as JsonValue;

function isObject(value: unknown): value is JsonObject {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function pointerGet(root: JsonValue, pointer: string): JsonValue {
  if (!pointer.startsWith("#/")) {
    throw new Error(`unsupported ref ${pointer}`);
  }
  return pointer
    .slice(2)
    .split("/")
    .reduce<JsonValue>((node, segment) => {
      if (!isObject(node)) throw new Error(`invalid ref ${pointer}`);
      const key = segment.replace(/~1/g, "/").replace(/~0/g, "~");
      const next = node[key];
      if (next === undefined) throw new Error(`missing ref ${pointer}`);
      return next;
    }, root);
}

function validate(
  schema: JsonValue,
  value: JsonValue,
  root: JsonValue = schema,
  path = "$",
): string[] {
  if (!isObject(schema)) return [];

  const ref = schema["$ref"];
  if (typeof ref === "string") {
    return validate(pointerGet(root, ref), value, root, path);
  }

  const errors: string[] = [];
  const type = schema["type"];
  if (typeof type === "string" && !matchesType(type, value)) {
    return [`${path} must be ${type}`];
  }

  if ("const" in schema && value !== schema["const"]) {
    errors.push(`${path} must equal ${JSON.stringify(schema["const"])}`);
  }

  const enumValues = schema["enum"];
  if (
    Array.isArray(enumValues) &&
    !enumValues.some((item) => item === value)
  ) {
    errors.push(`${path} must be one of ${JSON.stringify(enumValues)}`);
  }

  const pattern = schema["pattern"];
  if (typeof pattern === "string" && typeof value === "string") {
    if (!new RegExp(pattern).test(value)) {
      errors.push(`${path} must match ${pattern}`);
    }
  }

  const minimum = schema["minimum"];
  if (typeof minimum === "number" && typeof value === "number") {
    if (value < minimum) errors.push(`${path} must be >= ${minimum}`);
  }

  if (isObject(value)) {
    const required = schema["required"];
    if (Array.isArray(required)) {
      for (const key of required) {
        if (typeof key === "string" && !(key in value)) {
          errors.push(`${path}.${key} is required`);
        }
      }
    }

    const properties = schema["properties"];
    if (isObject(properties)) {
      for (const [key, propertySchema] of Object.entries(properties)) {
        const propertyValue = value[key];
        if (propertySchema !== undefined && propertyValue !== undefined) {
          errors.push(
            ...validate(propertySchema, propertyValue, root, `${path}.${key}`),
          );
        }
      }
    }
  }

  if (Array.isArray(value)) {
    const items = schema["items"];
    if (items !== undefined) {
      value.forEach((item, index) => {
        errors.push(...validate(items, item, root, `${path}[${index}]`));
      });
    }
  }

  const allOf = schema["allOf"];
  if (Array.isArray(allOf)) {
    for (const item of allOf) {
      errors.push(...validate(item, value, root, path));
    }
  }

  const anyOf = schema["anyOf"];
  if (Array.isArray(anyOf)) {
    const matched = anyOf.some(
      (item) => validate(item, value, root, path).length === 0,
    );
    if (!matched) errors.push(`${path} must match at least one allowed schema`);
  }

  const condition = schema["if"];
  const thenSchema = schema["then"];
  if (condition !== undefined && thenSchema !== undefined) {
    if (validate(condition, value, root, path).length === 0) {
      errors.push(...validate(thenSchema, value, root, path));
    }
  }

  return errors;
}

function matchesType(type: string, value: JsonValue): boolean {
  switch (type) {
    case "array":
      return Array.isArray(value);
    case "boolean":
      return typeof value === "boolean";
    case "integer":
      return Number.isInteger(value);
    case "number":
      return typeof value === "number";
    case "object":
      return isObject(value);
    case "string":
      return typeof value === "string";
    default:
      throw new Error(`unsupported schema type ${type}`);
  }
}

const CONTEXT = { lamportThreshold: 1_000_000_000 };
const SQUADS_V4 = "SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf";
const VAULT_TX_EXECUTE_DISC = [0xc2, 0x08, 0xa1, 0x57, 0x99, 0xa4, 0x19, 0xab];
const VAULT_TX_ACCOUNT_DISC = [0xa8, 0xfa, 0xa2, 0x64, 0x51, 0x0e, 0xa2, 0xcf];

function expectSchemaAccepts(label: string, value: unknown): void {
  const errors = validate(verdictSchemaJson, value as JsonValue);
  expect(errors, label).toEqual([]);
}

function base58ToBytes(b58: string): Uint8Array {
  const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  const map: Record<string, number> = {};
  for (let i = 0; i < alphabet.length; i++) map[alphabet[i]!] = i;

  let bytes: number[] = [];
  for (const ch of b58) {
    const value = map[ch];
    if (value === undefined) throw new Error(`invalid base58 character ${ch}`);
    let carry = value;
    for (let i = 0; i < bytes.length; i++) {
      carry += bytes[i]! * 58;
      bytes[i] = carry & 0xff;
      carry >>= 8;
    }
    while (carry > 0) {
      bytes.push(carry & 0xff);
      carry >>= 8;
    }
  }

  let leadingZeroes = 0;
  for (const ch of b58) {
    if (ch === "1") leadingZeroes++;
    else break;
  }

  const out = new Uint8Array(32);
  const body = bytes.reverse();
  const offset = 32 - body.length - leadingZeroes;
  for (let i = 0; i < body.length; i++) out[offset + i] = body[i]!;
  return out;
}

function buildSquadsExecuteMessage(): Uint8Array {
  const out: number[] = [];
  out.push(1, 0, 1); // one signer, Squads program readonly
  out.push(2);
  out.push(...key(1));
  out.push(...Array.from(base58ToBytes(SQUADS_V4)));
  out.push(...key(250));
  out.push(1);
  out.push(1); // programIdIndex = Squads
  out.push(1);
  out.push(0);
  out.push(VAULT_TX_EXECUTE_DISC.length);
  out.push(...VAULT_TX_EXECUTE_DISC);
  return Uint8Array.from(out);
}

function buildUnresolvedVaultTx(): Uint8Array {
  const bytes: number[] = [];
  bytes.push(...VAULT_TX_ACCOUNT_DISC);
  bytes.push(...new Array(32).fill(0x01)); // multisig
  bytes.push(...new Array(32).fill(0x02)); // creator
  bytes.push(1, 0, 0, 0, 0, 0, 0, 0); // index u64
  bytes.push(255, 0, 254); // bump, vault_index, vault_bump
  bytes.push(0, 0, 0, 0); // ephemeral_signer_bumps Vec<u8>
  bytes.push(1, 1, 1); // num_signers, num_writable_signers, num_writable_non_signers
  bytes.push(...u32le(3));
  bytes.push(...new Array(32).fill(0x10));
  bytes.push(...new Array(32).fill(0x11));
  bytes.push(...new Array(32).fill(0x12));
  bytes.push(...u32le(1)); // one inner instruction
  bytes.push(5); // >= accountKeys.len => ALT-sourced/unresolved program id
  bytes.push(...u32le(0)); // accounts
  bytes.push(...u32le(8));
  bytes.push(0xde, 0xad, 0xbe, 0xef, 0, 0, 0, 0);
  bytes.push(...u32le(0)); // no address table lookups
  return Uint8Array.from(bytes);
}

describe("sign-safe/verdict@1 schema", () => {
  for (const name of listFixtures()) {
    it(`accepts fixture verdict ${name}`, () => {
      expectSchemaAccepts(name, readFixtureGolden(name));
    });
  }

  it("accepts runtime contextual findings with tx-level index and empty program id", () => {
    const b64 = readFixtureB64("01_safe_sol_transfer");
    const { message } = decodeInput(b64);
    const touchedAccount = message.staticAccountKeys[0]!;
    const delegate = message.staticAccountKeys[1]!;

    const verdict = reviewBase64(b64, {
      ...CONTEXT,
      holdOutboundTransfers: true,
      mintExtensions: new Map([[touchedAccount, { permanentDelegate: delegate }]]),
      simulation: {
        ok: false,
        err: "offline schema regression probe",
        signerSolDelta: 0n,
        tokenDeltas: [],
        outflowsToNonSigner: [],
      },
    });

    for (const id of [
      "policy-outbound-transfer",
      "token2022-permanent-delegate",
      "simulation-failed",
    ]) {
      const finding = verdict.findings.find((item) => item.id === id);
      expect(finding).toMatchObject({
        instructionIndex: -1,
        programId: "",
      });
    }
    expectSchemaAccepts("contextual tx-level findings", verdict);
  });

  it("accepts runtime Squads findings with base58 and synthetic program ids", () => {
    const b64 = toB64(buildSquadsExecuteMessage());

    const unverified = reviewBase64(b64, CONTEXT);
    expect(unverified.findings).toContainEqual(
      expect.objectContaining({
        id: "squads-execute-unverified",
        instructionIndex: -1,
        programId: SQUADS_V4,
      }),
    );
    expectSchemaAccepts("unverified Squads execute finding", unverified);

    const unresolvedInner = reviewBase64(b64, CONTEXT, buildUnresolvedVaultTx());
    expect(unresolvedInner.findings).toContainEqual(
      expect.objectContaining({
        id: "squads-inner-unresolved",
        programId: "squads-inner:unresolved",
      }),
    );
    expectSchemaAccepts("unresolved Squads inner finding", unresolvedInner);
  });

  it("rejects invalid finding indexes and unsupported synthetic program ids", () => {
    const verdict = JSON.parse(
      JSON.stringify(reviewBase64(readFixtureB64("02_setauthority_reject"))),
    ) as JsonObject;
    const findings = verdict["findings"];
    if (!Array.isArray(findings) || !isObject(findings[0])) {
      throw new Error("fixture verdict must contain at least one object finding");
    }

    findings[0]["instructionIndex"] = -2;
    findings[0]["programId"] = "not-a-real:sentinel";

    const errors = validate(verdictSchemaJson, verdict);
    expect(errors).toEqual(
      expect.arrayContaining([
        "$.findings[0].instructionIndex must be >= -1",
        "$.findings[0].programId must match at least one allowed schema",
      ]),
    );
  });

  it("is published as the review_transaction MCP outputSchema", async () => {
    const response = await handleMcpRequest({
      jsonrpc: "2.0",
      id: "schema",
      method: "tools/list",
      params: {},
    });
    const wireResponse = JSON.parse(JSON.stringify(response)) as {
      result: {
        tools: Array<{ name: string; outputSchema?: unknown }>;
      };
    };
    const result = wireResponse.result;

    expect(result.tools).toHaveLength(1);
    expect(result.tools[0]).toMatchObject({
      name: "review_transaction",
      outputSchema: verdictSchema,
    });

    const directResult = response?.result as {
      tools: Array<{ name: string; outputSchema?: unknown }>;
    };
    expect(directResult.tools[0]?.outputSchema).toEqual(verdictSchema);
  });
});
