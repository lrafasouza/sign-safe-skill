#!/usr/bin/env node

import { createInterface } from "node:readline";
import { pathToFileURL } from "node:url";
import { reviewBase64, verdictToJson } from "./verdict.ts";
import { DEFAULT_CONTEXT } from "./types.ts";
import packageJson from "../../package.json" with { type: "json" };

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

export type McpLineResponse = McpResponse | McpResponse[];

type McpValidationResult =
  | { ok: true; request: McpRequest }
  | { ok: false; response: McpResponse };

const PROTOCOL_VERSION = "2025-06-18";
export const MCP_SERVER_VERSION = packageJson.version;
export const MAX_MCP_LINE_LENGTH = 1_000_000;
export const MAX_MCP_TRANSACTION_BASE64_LENGTH = 100_000;
export const MAX_MCP_PENDING_REQUESTS = 32;
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

function isValidId(id: unknown): id is string | number | null {
  return (
    id === null ||
    typeof id === "string" ||
    (typeof id === "number" && Number.isSafeInteger(id))
  );
}

function errorResponse(
  id: string | number | null,
  code: number,
  message: string,
): McpResponse {
  return {
    jsonrpc: "2.0",
    id,
    error: { code, message },
  };
}

function validateMcpRequest(value: unknown): McpValidationResult {
  if (!isRecord(value)) {
    return {
      ok: false,
      response: errorResponse(null, -32600, "Invalid Request"),
    };
  }
  const id = value["id"];
  if (id !== undefined && !isValidId(id)) {
    return {
      ok: false,
      response: errorResponse(null, -32600, "Invalid Request"),
    };
  }
  if (value["jsonrpc"] !== "2.0") {
    return {
      ok: false,
      response: errorResponse(
        id === undefined ? null : id,
        -32600,
        "Invalid Request",
      ),
    };
  }
  if (typeof value["method"] !== "string" || value["method"].length === 0) {
    return {
      ok: false,
      response: errorResponse(
        id === undefined ? null : id,
        -32600,
        "Invalid Request",
      ),
    };
  }
  return {
    ok: true,
    request: {
      jsonrpc: "2.0",
      id: id as string | number | null | undefined,
      method: value["method"],
      params: value["params"],
    },
  };
}

export async function handleMcpRequest(
  rawRequest: unknown,
): Promise<McpResponse | null> {
  const validation = validateMcpRequest(rawRequest);
  if (!validation.ok) return validation.response;
  const request = validation.request;
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
          version: MCP_SERVER_VERSION,
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
    if (args.transaction.length > MAX_MCP_TRANSACTION_BASE64_LENGTH) {
      return {
        jsonrpc: "2.0",
        id: request.id,
        error: {
          code: -32602,
          message:
            "Invalid review_transaction arguments: transaction is too large",
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

export async function handleMcpLine(
  line: string,
): Promise<McpLineResponse | null> {
  if (line.trim() === "") return null;
  if (line.length > MAX_MCP_LINE_LENGTH) {
    return errorResponse(null, -32600, "Invalid Request: line too large");
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(line);
  } catch {
    return errorResponse(null, -32700, "Parse error");
  }
  if (Array.isArray(parsed)) {
    if (parsed.length === 0) {
      return errorResponse(null, -32600, "Invalid Request");
    }
    const responses: McpResponse[] = [];
    for (const item of parsed) {
      const response = await handleMcpRequest(item);
      if (response !== null) responses.push(response);
    }
    return responses.length === 0 ? null : responses;
  }
  return handleMcpRequest(parsed);
}

export function createMcpLineProcessor(
  writeResponse: (line: string) => void,
  handler: (line: string) => Promise<McpLineResponse | null> = handleMcpLine,
  maxPending = MAX_MCP_PENDING_REQUESTS,
): (line: string) => void {
  let pending = 0;
  let tail = Promise.resolve();
  return (line: string): void => {
    if (line.trim() === "") return;
    if (pending >= maxPending) {
      writeResponse(
        `${JSON.stringify(errorResponse(null, -32600, "Invalid Request: server queue full"))}\n`,
      );
      return;
    }
    pending++;
    tail = tail
      .then(async () => {
        const response = await handler(line);
        if (response !== null) {
          writeResponse(`${JSON.stringify(response)}\n`);
        }
      })
      .catch(() => {
        writeResponse(
          `${JSON.stringify(errorResponse(null, -32603, "Internal error"))}\n`,
        );
      })
      .finally(() => {
        pending--;
      });
  };
}

export function runMcpStdio(): void {
  const lines = createInterface({
    input: process.stdin,
    crlfDelay: Infinity,
  });
  const processLine = createMcpLineProcessor((line) =>
    process.stdout.write(line),
  );

  lines.on("line", processLine);
}

if (
  process.argv[1] !== undefined &&
  import.meta.url === pathToFileURL(process.argv[1]).href
) {
  runMcpStdio();
}
