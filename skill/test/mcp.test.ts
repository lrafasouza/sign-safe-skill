import { describe, expect, it } from "vitest";
import { handleMcpRequest } from "../src/mcp.ts";
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
          version: "0.4.0",
        },
      },
    });
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
});
