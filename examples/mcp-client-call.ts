/**
 * examples/mcp-client-call.ts
 *
 * Demonstrates how to call the sign-safe MCP server programmatically using its
 * exported helpers. This exercises the same JSON-RPC 2.0 path that a real MCP
 * host (e.g. Claude Code) uses over stdio.
 *
 * Protocol: JSON-RPC 2.0, protocol version 2025-06-18.
 * Tool name: review_transaction
 * Input:  { transaction: string (base64), strict?: boolean }
 * Output: verdict JSON (sign-safe/verdict@1 schema)
 *
 * Run (no build needed):
 *   node --import tsx examples/mcp-client-call.ts
 */

import { readFileSync } from "node:fs";
import { handleMcpRequest } from "../skill/src/mcp.ts";
import type { McpResponse } from "../skill/src/mcp.ts";
import type { Verdict } from "../skill/src/types.ts";

// ── 1. Load a real fixture (02_setauthority_reject.b64 — REJECT by spl-set-authority)

const fixtureBase64 = readFileSync(
  new URL("../skill/fixtures/02_setauthority_reject.b64", import.meta.url),
  "utf8",
).trim();

// ── 2. MCP lifecycle: initialize

const initResponse = await handleMcpRequest({
  jsonrpc: "2.0",
  id: 1,
  method: "initialize",
  params: {
    protocolVersion: "2025-06-18",
    capabilities: {},
    clientInfo: { name: "example-client", version: "0.0.0" },
  },
});

if (!initResponse || "error" in initResponse) {
  console.error("initialize failed:", initResponse);
  process.exit(1);
}
const initResult = initResponse.result as {
  protocolVersion: string;
  capabilities: { tools: Record<string, unknown> };
  serverInfo: { name: string; version: string };
};
console.log(
  `MCP server: ${initResult.serverInfo.name} v${initResult.serverInfo.version}`,
);
console.log(`Protocol version: ${initResult.protocolVersion}`);

// ── 3. List tools (should return review_transaction)

const listResponse = await handleMcpRequest({
  jsonrpc: "2.0",
  id: 2,
  method: "tools/list",
  params: {},
});

if (!listResponse || "error" in listResponse) {
  console.error("tools/list failed:", listResponse);
  process.exit(1);
}
const tools = (listResponse.result as { tools: Array<{ name: string }> }).tools;
console.log(`Available tools: ${tools.map((t) => t.name).join(", ")}`);

// ── 4. Call review_transaction with the fixture

const callResponse: McpResponse | null = await handleMcpRequest({
  jsonrpc: "2.0",
  id: 3,
  method: "tools/call",
  params: {
    name: "review_transaction",
    arguments: {
      transaction: fixtureBase64,
      strict: false,
    },
  },
});

if (!callResponse || "error" in callResponse) {
  console.error("tools/call failed:", callResponse);
  process.exit(1);
}

// ── 5. Parse the verdict from the structured content

const callResult = callResponse.result as {
  content: Array<{ type: string; text: string }>;
  structuredContent: Verdict;
  isError: boolean;
};

const verdict: Verdict = callResult.structuredContent;

console.log("\n── Verdict ─────────────────────────────────────────");
console.log(`Decision : ${verdict.decision}`);
console.log(`Reason   : ${verdict.reason}`);
console.log(`Findings : ${verdict.findings.length}`);
for (const f of verdict.findings) {
  console.log(`  [${f.severity}] ${f.id}: ${f.label}`);
}
console.log(
  `Flags    : unknownProgram=${verdict.flags.unknownProgramPresent} alt=${verdict.flags.altLookupsPresent} unverifiedRoles=${verdict.flags.rolesUnverified}`,
);
console.log("────────────────────────────────────────────────────");

// ── 6. Verify the decision matches the fixture's expected verdict

if (verdict.decision !== "REJECT") {
  console.error(
    `Expected REJECT for 02_setauthority_reject but got ${verdict.decision}`,
  );
  process.exit(1);
}
console.log("Gate decision (expected REJECT): PASS");
