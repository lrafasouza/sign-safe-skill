import { describe, expect, it } from "vitest";
import packageJson from "../../package.json" with { type: "json" };
import {
  MAX_MCP_LINE_LENGTH,
  MAX_MCP_TRANSACTION_BASE64_LENGTH,
  createMcpLineProcessor,
  handleMcpLine,
  handleMcpRequest,
} from "../src/mcp.ts";
import { readFixtureB64 } from "./helpers.ts";

describe("review_transaction MCP server", () => {
  it("returns a well-formed initialize result", async () => {
    const response = await handleMcpRequest({
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: {
        protocolVersion: "2025-06-18",
        capabilities: {},
        clientInfo: { name: "test", version: "1.0.0" },
      },
    });

    expect(response).toEqual({
      jsonrpc: "2.0",
      id: 1,
      result: {
        protocolVersion: "2025-06-18",
        capabilities: { tools: {} },
        serverInfo: {
          name: "sign-safe",
          version: packageJson.version,
        },
      },
    });
  });

  it("reports an MCP server version matching package.json", async () => {
    const response = await handleMcpRequest({
      jsonrpc: "2.0",
      id: 11,
      method: "initialize",
    });
    const result = response?.result as {
      serverInfo: { version: string };
    };
    expect(result.serverInfo.version).toBe(packageJson.version);
  });

  it("lists only the review_transaction tool with its input schema", async () => {
    const response = await handleMcpRequest({
      jsonrpc: "2.0",
      id: "tools",
      method: "tools/list",
      params: {},
    });

    expect(response?.jsonrpc).toBe("2.0");
    expect(response?.id).toBe("tools");
    expect(response?.result).toEqual({
      tools: [
        {
          name: "review_transaction",
          title: "Review Solana Transaction",
          description:
            "Review a base64-encoded Solana transaction offline and return the sign-safe verdict.",
          inputSchema: {
            type: "object",
            properties: {
              transaction: {
                type: "string",
                description:
                  "Base64-encoded Solana message or full transaction.",
              },
              strict: {
                type: "boolean",
                description: "Enable strict fail-closed review policy.",
              },
            },
            required: ["transaction"],
            additionalProperties: false,
          },
          annotations: {
            readOnlyHint: true,
          },
        },
      ],
    });
  });

  it("returns the verdict JSON from review_transaction", async () => {
    const response = await handleMcpRequest({
      jsonrpc: "2.0",
      id: 2,
      method: "tools/call",
      params: {
        name: "review_transaction",
        arguments: {
          transaction: readFixtureB64("02_setauthority_reject"),
          strict: true,
        },
      },
    });
    const result = response?.result as {
      content: { type: string; text: string }[];
      structuredContent: { decision: string };
      isError: boolean;
    };

    expect(response?.jsonrpc).toBe("2.0");
    expect(response?.id).toBe(2);
    expect(result.structuredContent.decision).toBe("REJECT");
    expect(JSON.parse(result.content[0]!.text).decision).toBe("REJECT");
    expect(result.isError).toBe(false);
  });

  it("returns batch review_transaction responses in request order", async () => {
    const response = await handleMcpLine(
      JSON.stringify([
        {
          jsonrpc: "2.0",
          id: "first",
          method: "tools/call",
          params: {
            name: "review_transaction",
            arguments: {
              transaction: readFixtureB64("01_safe_sol_transfer"),
            },
          },
        },
        {
          jsonrpc: "2.0",
          id: "second",
          method: "tools/call",
          params: {
            name: "review_transaction",
            arguments: {
              transaction: readFixtureB64("02_setauthority_reject"),
            },
          },
        },
      ]),
    );

    if (!Array.isArray(response)) throw new Error("expected batch response");
    const responses = response;
    expect(responses.map((item) => item.id)).toEqual(["first", "second"]);
    expect(
      responses.map(
        (item) =>
          (
            item.result as {
              structuredContent: { decision: string };
            }
          ).structuredContent.decision,
      ),
    ).toEqual(["SIGN", "REJECT"]);
  });

  it("omits notification responses from a mixed JSON-RPC batch", async () => {
    const response = await handleMcpLine(
      JSON.stringify([
        {
          jsonrpc: "2.0",
          method: "tools/list",
        },
        {
          jsonrpc: "2.0",
          id: 12,
          method: "tools/list",
        },
      ]),
    );

    expect(response).toEqual([
      {
        jsonrpc: "2.0",
        id: 12,
        result: {
          tools: expect.any(Array),
        },
      },
    ]);
  });

  it("rejects an empty JSON-RPC batch as invalid request", async () => {
    const response = await handleMcpLine("[]");

    expect(response).toEqual({
      jsonrpc: "2.0",
      id: null,
      error: {
        code: -32600,
        message: "Invalid Request",
      },
    });
  });

  it("rejects oversize review_transaction input with invalid params", async () => {
    const response = await handleMcpRequest({
      jsonrpc: "2.0",
      id: 3,
      method: "tools/call",
      params: {
        name: "review_transaction",
        arguments: {
          transaction: "A".repeat(MAX_MCP_TRANSACTION_BASE64_LENGTH + 1),
        },
      },
    });

    expect(response?.error?.code).toBe(-32602);
  });

  it("rejects oversize JSON-RPC lines before parsing", async () => {
    const response = await handleMcpLine("x".repeat(MAX_MCP_LINE_LENGTH + 1));

    if (Array.isArray(response)) throw new Error("expected single response");
    expect(response?.error?.code).toBe(-32600);
  });

  it("maps malformed, null, and bad-jsonrpc envelopes to spec error codes", async () => {
    const badJson = await handleMcpLine("{");
    const nullRequest = await handleMcpLine("null");
    const badJsonrpc = await handleMcpLine(
      JSON.stringify({ jsonrpc: "1.0", id: 4, method: "tools/list" }),
    );

    if (Array.isArray(badJson)) throw new Error("expected single response");
    if (Array.isArray(nullRequest)) throw new Error("expected single response");
    if (Array.isArray(badJsonrpc)) throw new Error("expected single response");
    expect(badJson?.error?.code).toBe(-32700);
    expect(nullRequest?.error?.code).toBe(-32600);
    expect(badJsonrpc?.error?.code).toBe(-32600);
  });

  it("returns method-not-found for a valid unknown method", async () => {
    const response = await handleMcpRequest({
      jsonrpc: "2.0",
      id: 5,
      method: "unknown/method",
    });

    expect(response?.error?.code).toBe(-32601);
  });

  it("processes line requests sequentially and writes responses in request order", async () => {
    const writes: string[] = [];
    const seen: number[] = [];
    let releaseFirst: (() => void) | undefined;
    const processor = createMcpLineProcessor(
      (line) => writes.push(line),
      async (line) => {
        const request = JSON.parse(line) as { id: number };
        seen.push(request.id);
        if (request.id === 1) {
          await new Promise<void>((resolve) => {
            releaseFirst = resolve;
          });
        }
        return {
          jsonrpc: "2.0",
          id: request.id,
          result: { id: request.id },
        };
      },
    );

    processor(JSON.stringify({ jsonrpc: "2.0", id: 1, method: "a" }));
    processor(JSON.stringify({ jsonrpc: "2.0", id: 2, method: "b" }));
    await Promise.resolve();
    expect(seen).toEqual([1]);
    releaseFirst?.();
    await new Promise((resolve) => setTimeout(resolve, 0));
    await new Promise((resolve) => setTimeout(resolve, 0));

    expect(writes.map((line) => JSON.parse(line).id)).toEqual([1, 2]);
  });
});
