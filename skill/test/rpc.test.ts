/**
 * rpc.test.ts -- TDD for A5a: makeRpcAccountFetcher in skill/src/rpc.ts
 *
 * All tests use a synthetic fetchImpl (no real network). Asserts:
 *   (a) The request body is correct JSON-RPC getAccountInfo with pubkey + base64 encoding
 *   (b) base64-encoded data in the response is decoded to the correct Uint8Array
 *   (c) result.value = null → fetcher returns null
 *   (d) RPC error object → fetcher throws
 *   (e) HTTP error status → fetcher throws
 */

import { describe, it, expect, vi } from "vitest";
import { makeRpcAccountFetcher } from "../src/rpc.ts";

const TEST_PUBKEY = "11111111111111111111111111111112";
const TEST_RPC_URL = "https://api.mainnet-beta.solana.com";

/** Build a minimal JSON-RPC success response with base64-encoded data. */
function makeSuccessResponse(dataBytes: number[]): string {
  const b64 = Buffer.from(dataBytes).toString("base64");
  return JSON.stringify({
    jsonrpc: "2.0",
    id: 1,
    result: {
      value: {
        data: [b64, "base64"],
        executable: false,
        lamports: 1000000,
        owner: "11111111111111111111111111111111",
        rentEpoch: 0,
        space: dataBytes.length,
      },
    },
  });
}

/** Build a JSON-RPC response where value is null (account not found). */
function makeNullResponse(): string {
  return JSON.stringify({
    jsonrpc: "2.0",
    id: 1,
    result: { value: null },
  });
}

/** Build a JSON-RPC error response. */
function makeErrorResponse(code: number, message: string): string {
  return JSON.stringify({
    jsonrpc: "2.0",
    id: 1,
    error: { code, message },
  });
}

describe("A5a: makeRpcAccountFetcher", () => {
  it("A5a.1 sends correct JSON-RPC getAccountInfo request with pubkey and base64 encoding", async () => {
    let capturedUrl: string | undefined;
    let capturedBody: unknown;

    const fakeFetch = vi.fn(async (url: string, init?: RequestInit) => {
      capturedUrl = url;
      capturedBody = JSON.parse(init?.body as string);
      return new Response(makeSuccessResponse([0x01, 0x02, 0x03]), { status: 200 });
    });

    const fetcher = makeRpcAccountFetcher(TEST_RPC_URL, fakeFetch as unknown as typeof fetch);
    await fetcher(TEST_PUBKEY);

    expect(capturedUrl).toBe(TEST_RPC_URL);
    expect(capturedBody).toMatchObject({
      jsonrpc: "2.0",
      method: "getAccountInfo",
      params: [TEST_PUBKEY, { encoding: "base64" }],
    });
    // id can be anything but must be present
    expect((capturedBody as { id: unknown }).id).toBeDefined();
  });

  it("A5a.2 decodes base64 data from response to the correct Uint8Array bytes", async () => {
    const expectedBytes = [0xde, 0xad, 0xbe, 0xef, 0x42];

    const fakeFetch = vi.fn(async () =>
      new Response(makeSuccessResponse(expectedBytes), { status: 200 }),
    );

    const fetcher = makeRpcAccountFetcher(TEST_RPC_URL, fakeFetch as unknown as typeof fetch);
    const result = await fetcher(TEST_PUBKEY);

    expect(result).not.toBeNull();
    expect(result!.data).toBeInstanceOf(Uint8Array);
    expect(Array.from(result!.data)).toEqual(expectedBytes);
  });

  it("A5a.3 returns null when result.value is null (account not found)", async () => {
    const fakeFetch = vi.fn(async () =>
      new Response(makeNullResponse(), { status: 200 }),
    );

    const fetcher = makeRpcAccountFetcher(TEST_RPC_URL, fakeFetch as unknown as typeof fetch);
    const result = await fetcher(TEST_PUBKEY);

    expect(result).toBeNull();
  });

  it("A5a.4 throws when the RPC returns an error object", async () => {
    const fakeFetch = vi.fn(async () =>
      new Response(makeErrorResponse(-32600, "Invalid request"), { status: 200 }),
    );

    const fetcher = makeRpcAccountFetcher(TEST_RPC_URL, fakeFetch as unknown as typeof fetch);
    await expect(fetcher(TEST_PUBKEY)).rejects.toThrow();
  });

  it("A5a.5 throws on HTTP error status (non-2xx)", async () => {
    const fakeFetch = vi.fn(async () =>
      new Response("Internal Server Error", { status: 500 }),
    );

    const fetcher = makeRpcAccountFetcher(TEST_RPC_URL, fakeFetch as unknown as typeof fetch);
    await expect(fetcher(TEST_PUBKEY)).rejects.toThrow();
  });

  it("A5a.6 uses globalThis.fetch as default when no fetchImpl is provided (smoke: just check it is defined)", () => {
    // This test only verifies the factory doesn't crash without a fetchImpl.
    // It does NOT call fetch (no real network) -- just checks the factory accepts no fetchImpl.
    expect(() => makeRpcAccountFetcher(TEST_RPC_URL)).not.toThrow();
  });

  it("A5a.7 passes the Content-Type header as application/json", async () => {
    let capturedContentType: string | undefined;

    const fakeFetch = vi.fn(async (_url: string, init?: RequestInit) => {
      const headers = init?.headers as Record<string, string> | undefined;
      capturedContentType = headers?.["Content-Type"] ?? headers?.["content-type"];
      return new Response(makeSuccessResponse([0xab]), { status: 200 });
    });

    const fetcher = makeRpcAccountFetcher(TEST_RPC_URL, fakeFetch as unknown as typeof fetch);
    await fetcher(TEST_PUBKEY);

    expect(capturedContentType).toBe("application/json");
  });
});
