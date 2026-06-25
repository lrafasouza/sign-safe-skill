#!/usr/bin/env node

import { createInterface } from "node:readline";
import { pathToFileURL } from "node:url";
import { reviewBase64, verdictToJson } from "./verdict.ts";
import { DEFAULT_CONTEXT } from "./types.ts";

export interface McpRequest {
  jsonrpc: "2.0";
  id?: string | number | null;
  method: string;
  params?: unknown;
}

export interface McpResponse {
  jsonrpc: "2.0";
  id: string | number | null;
  result?: unknown;
  error?: {
    code: number;
    message: string;
  };
}

const PROTOCOL_VERSION = "2025-06-18";
const REVIEW_TRANSACTION_TOOL = {
  name: "review_transaction",
  title: "Review Solana Transaction",
  description:
    "Review a base64-encoded Solana transaction offline and return the sign-safe verdict.",
  inputSchema: {
    type: "object",
    properties: {
      transaction: {
        type: "string",
        description: "Base64-encoded Solana message or full transaction.",
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
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export async function handleMcpRequest(
  request: McpRequest,
): Promise<McpResponse | null> {
  if (request.id === undefined) return null;

  if (request.method === "initialize") {
    return {
      jsonrpc: "2.0",
      id: request.id,
      result: {
        protocolVersion: PROTOCOL_VERSION,
        capabilities: { tools: {} },
        serverInfo: {
          name: "sign-safe",
          version: "0.4.0",
        },
      },
    };
  }

  if (request.method === "tools/list") {
    return {
      jsonrpc: "2.0",
      id: request.id,
      result: {
        tools: [REVIEW_TRANSACTION_TOOL],
      },
    };
  }

  if (request.method === "tools/call") {
    if (
      !isRecord(request.params) ||
      request.params.name !== "review_transaction"
    ) {
      return {
        jsonrpc: "2.0",
        id: request.id,
        error: {
          code: -32602,
          message: "Unknown tool: expected review_transaction",
        },
      };
    }
    const args = request.params.arguments;
    if (
      !isRecord(args) ||
      typeof args.transaction !== "string" ||
      (args.strict !== undefined && typeof args.strict !== "boolean")
    ) {
      return {
        jsonrpc: "2.0",
        id: request.id,
        error: {
          code: -32602,
          message: "Invalid review_transaction arguments",
        },
      };
    }

    const verdict = reviewBase64(
      args.transaction,
      args.strict === true
        ? { ...DEFAULT_CONTEXT, strict: true }
        : DEFAULT_CONTEXT,
    );
    const verdictJson = verdictToJson(verdict);
    return {
      jsonrpc: "2.0",
      id: request.id,
      result: {
        content: [
          {
            type: "text",
            text: verdictJson,
          },
        ],
        structuredContent: JSON.parse(verdictJson),
        isError: false,
      },
    };
  }

  return {
    jsonrpc: "2.0",
    id: request.id,
    error: {
      code: -32601,
      message: `Method not found: ${request.method}`,
    },
  };
}

export function runMcpStdio(): void {
  const lines = createInterface({
    input: process.stdin,
    crlfDelay: Infinity,
  });

  lines.on("line", async (line) => {
    if (line.trim() === "") return;
    let response: McpResponse | null;
    try {
      const request = JSON.parse(line) as McpRequest;
      response = await handleMcpRequest(request);
    } catch {
      response = {
        jsonrpc: "2.0",
        id: null,
        error: {
          code: -32700,
          message: "Parse error",
        },
      };
    }
    if (response !== null) {
      process.stdout.write(`${JSON.stringify(response)}\n`);
    }
  });
}

if (
  process.argv[1] !== undefined &&
  import.meta.url === pathToFileURL(process.argv[1]).href
) {
  runMcpStdio();
}
