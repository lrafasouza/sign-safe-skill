/**
 * rpc.test.ts -- TDD for A5a: makeRpcAccountFetcher in skill/src/rpc.ts
 *                   + v0.5 hardening: timeout, URL validation, makeRpcSimulator
 *
 * All tests use a synthetic fetchImpl (no real network). Asserts:
 *   (a) The request body is correct JSON-RPC getAccountInfo with pubkey + base64 encoding
 *   (b) base64-encoded data in the response is decoded to the correct Uint8Array
 *   (c) result.value = null → fetcher returns null
 *   (d) RPC error object → fetcher throws
 *   (e) HTTP error status → fetcher throws
 *   (f) v0.5: AbortController timeout → fetcher rejects with clear message
 *   (g) v0.5: non-http(s) URL → throws at construction time
 *   (h) v0.5: makeRpcSimulator basic request shape
 */

import { describe, it, expect, vi } from "vitest";
import { makeRpcAccountFetcher, makeRpcSimulator } from "../src/rpc.ts";

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

// ─────────────────────────────────────────────────────────────────────────────
// v0.5 Part 1: RPC hardening — URL validation + AbortController timeout
// ─────────────────────────────────────────────────────────────────────────────

describe("v0.5 Part 1a: URL scheme validation (makeRpcAccountFetcher)", () => {
  it("P1a.1 http:// URL is accepted (loopback — legitimate local validator)", () => {
    // Loopback must NOT be blocked: a local validator at 127.0.0.1 is a valid use case.
    expect(() => makeRpcAccountFetcher("http://127.0.0.1:8899")).not.toThrow();
  });

  it("P1a.2 https:// URL is accepted", () => {
    expect(() => makeRpcAccountFetcher("https://api.mainnet-beta.solana.com")).not.toThrow();
  });

  it("P1a.3 ws:// URL throws (websocket scheme not supported)", () => {
    expect(() => makeRpcAccountFetcher("ws://api.mainnet-beta.solana.com")).toThrow(/http/i);
  });

  it("P1a.4 file:// URL throws", () => {
    expect(() => makeRpcAccountFetcher("file:///etc/passwd")).toThrow(/http/i);
  });

  it("P1a.5 data: URL throws", () => {
    expect(() => makeRpcAccountFetcher("data:text/plain,hello")).toThrow(/http/i);
  });

  it("P1a.6 unparseable string throws with clear message", () => {
    expect(() => makeRpcAccountFetcher("not a url at all")).toThrow();
  });

  it("P1a.7 RFC-1918 private-network http:// URL is accepted (proportionate fix: scheme only)", () => {
    // We block by scheme, not by host. A private-network RPC is a valid use case.
    expect(() => makeRpcAccountFetcher("http://192.168.1.1:8899")).not.toThrow();
  });
});

describe("v0.5 Part 1b: AbortController timeout (makeRpcAccountFetcher)", () => {
  it("P1b.1 fetch that never resolves -> rejects after timeoutMs", async () => {
    // Use a very short timeout (20 ms) so the test runs fast.
    // The fetchImpl returns a promise that never settles.
    const hangingFetch = vi.fn(
      () => new Promise<Response>(() => { /* never resolves */ }),
    );

    const fetcher = makeRpcAccountFetcher(
      "https://api.mainnet-beta.solana.com",
      hangingFetch as unknown as typeof fetch,
      { timeoutMs: 20 },
    );

    await expect(fetcher(TEST_PUBKEY)).rejects.toThrow(/timeout/i);
  }, 2000 /* test-level timeout of 2 s */);

  it("P1b.2 fast-responding fetch (within timeout) -> succeeds normally", async () => {
    const fastFetch = vi.fn(async () =>
      new Response(makeSuccessResponse([0x01]), { status: 200 }),
    );

    const fetcher = makeRpcAccountFetcher(
      "https://api.mainnet-beta.solana.com",
      fastFetch as unknown as typeof fetch,
      { timeoutMs: 5000 },
    );

    const result = await fetcher(TEST_PUBKEY);
    expect(result).not.toBeNull();
    expect(Array.from(result!.data)).toEqual([0x01]);
  });

  it("P1b.3 default timeout is 10000 ms (smoke: factory does not throw with no opts)", () => {
    const fakeFetch = vi.fn(async () =>
      new Response(makeSuccessResponse([]), { status: 200 }),
    );
    // Construct without opts -- uses default 10000 ms.
    expect(() =>
      makeRpcAccountFetcher(TEST_RPC_URL, fakeFetch as unknown as typeof fetch),
    ).not.toThrow();
  });
});

describe("v0.5 Part 1c: URL scheme validation (makeRpcSimulator)", () => {
  it("P1c.1 https:// URL is accepted", () => {
    expect(() => makeRpcSimulator("https://api.mainnet-beta.solana.com")).not.toThrow();
  });

  it("P1c.2 ws:// URL throws", () => {
    expect(() => makeRpcSimulator("ws://invalid")).toThrow(/http/i);
  });

  it("P1c.3 http:// loopback accepted (local validator)", () => {
    expect(() => makeRpcSimulator("http://127.0.0.1:8899")).not.toThrow();
  });
});

describe("v0.5 Part 1d: makeRpcSimulator basic request shape", () => {
  /** Build a minimal simulateTransaction success response with no accounts. */
  function makeSimResponse(err: null | string = null): string {
    return JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      result: {
        value: {
          err,
          logs: [],
          accounts: [],
        },
      },
    });
  }

  it("P1d.1 sends correct JSON-RPC simulateTransaction request", async () => {
    let capturedBody: unknown;
    const fakeFetch = vi.fn(async (_url: string, init?: RequestInit) => {
      capturedBody = JSON.parse(init?.body as string);
      return new Response(makeSimResponse(), { status: 200 });
    });

    const simulator = makeRpcSimulator(TEST_RPC_URL, fakeFetch as unknown as typeof fetch);
    const result = await simulator("AQAAABBB==", ["addr1", "addr2"]);

    expect((capturedBody as { method: string }).method).toBe("simulateTransaction");
    const params = (capturedBody as { params: unknown[] }).params;
    expect(params[0]).toBe("AQAAABBB==");
    const opts = params[1] as Record<string, unknown>;
    expect(opts["sigVerify"]).toBe(false);
    expect(opts["replaceRecentBlockhash"]).toBe(true);
    expect(opts["encoding"]).toBe("base64");
    const accounts = opts["accounts"] as Record<string, unknown>;
    expect(accounts["encoding"]).toBe("base64");
    expect(accounts["addresses"]).toEqual(["addr1", "addr2"]);

    expect(result.err).toBeNull();
  });

  it("P1d.2 simulator returns SimulateResult with err field when simulation fails", async () => {
    const fakeFetch = vi.fn(async () =>
      new Response(makeSimResponse("InstructionError"), { status: 200 }),
    );
    const simulator = makeRpcSimulator(TEST_RPC_URL, fakeFetch as unknown as typeof fetch);
    const result = await simulator("AQAAABBB==", []);
    expect(result.err).toBe("InstructionError");
  });

  it("P1d.3 simulator timeout -> rejects with clear message", async () => {
    const hangingFetch = vi.fn(
      () => new Promise<Response>(() => { /* never resolves */ }),
    );
    const simulator = makeRpcSimulator(
      TEST_RPC_URL,
      hangingFetch as unknown as typeof fetch,
      { timeoutMs: 20 },
    );
    await expect(simulator("AQAAABBB==", [])).rejects.toThrow(/timeout/i);
  }, 2000);
});
