/**
 * simulate.test.ts -- TDD for v0.5 Part 2: simulateAssetDiff (skill/src/simulate.ts)
 *
 * All tests use FROZEN/SYNTHETIC SimulateFn and AccountFetcher (no real network).
 *
 * Test groups:
 *   S1  sim succeeds with SOL drain to non-signer → verdict gains simulation-outflow HOLD
 *   S2  sim error (ok=false) with --simulate requested → verdict gains simulation-failed HOLD
 *   S3  benign sim (no outflows) → no extra finding
 *   S4  sim never downgrades a static REJECT to SIGN
 *   S5  sim REJECT escalation when outflow recipient is blocklisted
 *   S6  simulateAssetDiff unit: zero signers → ok=true, deltas empty
 *   S7  simulateAssetDiff unit: sim error → ok=false
 *   S8  reviewWithEnrichment + simulate=true + frozen sim that fails → simulation-failed HOLD
 *   S9  reviewWithEnrichment + simulate=true + frozen sim drain → simulation-outflow HOLD
 *   S10 simulation NEVER turns static REJECT into SIGN
 */

import { describe, it, expect } from "vitest";
import { simulateAssetDiff } from "../src/simulate.ts";
import { reviewWithEnrichment } from "../src/review-online.ts";
import { reviewBase64 } from "../src/verdict.ts";
import { DEFAULT_CONTEXT, type VerdictContext } from "../src/types.ts";
import type { SimulateFn, SimulateResult } from "../src/simulate.ts";
import { legacyBytes, v0Bytes, toB64, key, u64le } from "./helpers.ts";

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

const SYSTEM = "11111111111111111111111111111111";
const NOOP_FETCHER = async (_pk: string) => null;

/** Build a minimal legacy System Transfer message: signer → recipient, amount lamports. */
function buildTransferMsg(lamports: bigint): { raw: Uint8Array; b64: string } {
  // tag=2 (Transfer), lamports=u64-LE
  const data = [2, 0, 0, 0, ...u64le(lamports)];
  const raw = legacyBytes(
    [1, 0, 1], // 1 signer, 0 readonly signed, 1 readonly unsigned
    [0x01, 0x02, 0x00], // [0]=signer(0x01), [1]=recipient(0x02), [2]=SystemProgram(0x00)
    [{ prog: 2, accts: [0, 1], data }],
  );
  return { raw, b64: toB64(raw) };
}

/** Build a SimulateResult with the signer losing `solLoss` lamports. */
function makeDrainSimResult(
  signerPk: string,
  preLamports: bigint,
  postLamports: bigint,
): SimulateResult & { preBalances: bigint[] } {
  void signerPk; // captured in the closure for assertion clarity
  return {
    err: null,
    logs: [],
    accounts: [{ lamports: postLamports, data: Buffer.alloc(0), owner: SYSTEM }],
    preBalances: [preLamports],
  };
}

/** Build a SimulateResult that errors. */
function makeErrorSimResult(err: string): SimulateResult {
  return { err, logs: [], accounts: [] };
}

/** Build a benign SimulateResult with no delta (signer keeps same lamports). */
function makeBenignSimResult(lamports: bigint): SimulateResult & { preBalances: bigint[] } {
  return {
    err: null,
    logs: [],
    accounts: [{ lamports, data: Buffer.alloc(0), owner: SYSTEM }],
    preBalances: [lamports],
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// S6-S7: simulateAssetDiff unit tests (pure function exercised directly)
// ─────────────────────────────────────────────────────────────────────────────

describe("S6: simulateAssetDiff unit — zero signers", () => {
  it("S6.1 zero signerPubkeys → ok=true, zero deltas", async () => {
    const dummySim: SimulateFn = async () => ({
      err: null, logs: [], accounts: [],
    });
    const result = await simulateAssetDiff("AQAAABBB==", [], dummySim, NOOP_FETCHER);
    expect(result.ok).toBe(true);
    expect(result.signerSolDelta).toBe(0n);
    expect(result.tokenDeltas).toHaveLength(0);
    expect(result.outflowsToNonSigner).toHaveLength(0);
  });
});

describe("S7: simulateAssetDiff unit — sim error → ok=false", () => {
  it("S7.1 simulator returns err → ok=false with err message", async () => {
    const errSim: SimulateFn = async () => makeErrorSimResult("InstructionError at 0");
    const result = await simulateAssetDiff("AQAAABBB==", ["signer1"], errSim, NOOP_FETCHER);
    expect(result.ok).toBe(false);
    expect(result.err).toMatch(/InstructionError/);
    expect(result.signerSolDelta).toBe(0n);
  });

  it("S7.2 simulator throws → ok=false (fail-closed)", async () => {
    const throwSim: SimulateFn = async () => {
      throw new Error("network failure");
    };
    const result = await simulateAssetDiff("AQAAABBB==", ["signer1"], throwSim, NOOP_FETCHER);
    expect(result.ok).toBe(false);
    expect(result.err).toMatch(/network failure/);
  });
});

describe("S7b: simulateAssetDiff unit — SOL drain to non-signer", () => {
  it("S7b.1 signer loses 2 SOL → signerSolDelta < 0, outflow reported", async () => {
    const pre = 5_000_000_000n; // 5 SOL
    const post = 3_000_000_000n; // 3 SOL (2 SOL drain)
    const drainSim: SimulateFn = async (_b64, _addrs) =>
      makeDrainSimResult("signerPk", pre, post);

    const result = await simulateAssetDiff(
      "AQAAABBB==", ["signerPk"], drainSim, NOOP_FETCHER,
    );
    expect(result.ok).toBe(true);
    expect(result.signerSolDelta).toBe(post - pre); // -2_000_000_000n
    expect(result.signerSolDelta).toBeLessThan(0n);
    expect(result.outflowsToNonSigner.length).toBeGreaterThan(0);
    const solOutflow = result.outflowsToNonSigner.find((o) => o.kind === "sol");
    expect(solOutflow).toBeDefined();
    expect(solOutflow!.amount).toBe(2_000_000_000n);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// S1: verdict gains simulation-outflow HOLD when sim drains signer SOL
// ─────────────────────────────────────────────────────────────────────────────

describe("S1: sim SOL drain to non-signer → simulation-outflow HOLD in verdict", () => {
  it("S1.1 sim drain of signer SOL → simulation-outflow HOLD added (escalate-only)", async () => {
    // Build a benign 0-lamport transfer (normally SIGN or HOLD due to threshold)
    const { b64 } = buildTransferMsg(100n); // 100 lamports, way below threshold

    // Get the signer's address from the message
    const { decodeInput } = await import("../src/decode.ts");
    const { message } = decodeInput(b64);
    const signerPk = message.staticAccountKeys[0]!;

    // Frozen sim returns: signer loses 2 SOL post-simulation
    const pre = 5_000_000_000n;
    const post = 3_000_000_000n;
    const frozenSim: SimulateFn = async (_b64, _addrs) =>
      makeDrainSimResult(signerPk, pre, post);

    const ctx: VerdictContext = {
      ...DEFAULT_CONTEXT,
      // Inject the simulation result directly into the context for unit testing.
      simulation: {
        ok: true,
        signerSolDelta: post - pre, // -2_000_000_000n
        tokenDeltas: [],
        outflowsToNonSigner: [
          { to: "_non-signer_", amount: 2_000_000_000n, kind: "sol" },
        ],
      },
    };

    const verdict = reviewBase64(b64, ctx);
    // Should gain simulation-outflow finding
    const simFinding = verdict.findings.find((f) => f.id === "simulation-outflow");
    expect(simFinding).toBeDefined();
    expect(simFinding!.severity).toBe("HOLD");
    // The verdict should be at least HOLD
    expect(verdict.decision).not.toBe("SIGN");
  });

  it("S1.2 reviewWithEnrichment + frozen drain sim → simulation-outflow HOLD", async () => {
    const { b64 } = buildTransferMsg(100n);

    const { decodeInput } = await import("../src/decode.ts");
    const { message } = decodeInput(b64);
    const signerPk = message.staticAccountKeys[0]!;

    const pre = 5_000_000_000n;
    const post = 3_000_000_000n;
    const frozenSim: SimulateFn = async (_b64, _addrs) =>
      makeDrainSimResult(signerPk, pre, post);

    const ctx: VerdictContext = DEFAULT_CONTEXT;
    const verdict = await reviewWithEnrichment(b64, ctx, NOOP_FETCHER, {
      simulate: true,
      simulateFn: frozenSim,
      rpcUrl: "http://127.0.0.1:8899",
    });

    const simFinding = verdict.findings.find((f) => f.id === "simulation-outflow");
    expect(simFinding).toBeDefined();
    expect(simFinding!.severity).toBe("HOLD");
    expect(verdict.decision).not.toBe("SIGN");
    // Enrichment provenance must be set
    expect(verdict.enrichment).toBeDefined();
    expect(verdict.enrichment!.simulated).toBe(true);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// S2: sim error with --simulate → simulation-failed HOLD
// ─────────────────────────────────────────────────────────────────────────────

describe("S2: sim error when simulate requested → simulation-failed HOLD", () => {
  it("S2.1 inject simulation.ok=false into ctx → simulation-failed HOLD finding", () => {
    const { b64 } = buildTransferMsg(100n);
    const ctx: VerdictContext = {
      ...DEFAULT_CONTEXT,
      simulation: {
        ok: false,
        err: "simulateTransaction failed: blockhash expired",
        signerSolDelta: 0n,
        tokenDeltas: [],
        outflowsToNonSigner: [],
      },
    };
    const verdict = reviewBase64(b64, ctx);
    const simFinding = verdict.findings.find((f) => f.id === "simulation-failed");
    expect(simFinding).toBeDefined();
    expect(simFinding!.severity).toBe("HOLD");
    expect(verdict.decision).not.toBe("SIGN");
  });

  it("S2.2 reviewWithEnrichment + frozen error sim → simulation-failed HOLD", async () => {
    const { b64 } = buildTransferMsg(100n);
    const errSim: SimulateFn = async () => makeErrorSimResult("InstructionError at ix 0");

    const verdict = await reviewWithEnrichment(b64, DEFAULT_CONTEXT, NOOP_FETCHER, {
      simulate: true,
      simulateFn: errSim,
      rpcUrl: "https://api.mainnet-beta.solana.com",
    });

    const simFinding = verdict.findings.find((f) => f.id === "simulation-failed");
    expect(simFinding).toBeDefined();
    expect(simFinding!.severity).toBe("HOLD");
    expect(verdict.decision).toBe("HOLD");
  });

  it("S2.3 reviewWithEnrichment + throwing sim → simulation-failed HOLD (fail-closed)", async () => {
    const { b64 } = buildTransferMsg(100n);
    const throwSim: SimulateFn = async () => { throw new Error("network down"); };

    const verdict = await reviewWithEnrichment(b64, DEFAULT_CONTEXT, NOOP_FETCHER, {
      simulate: true,
      simulateFn: throwSim,
      rpcUrl: "https://api.mainnet-beta.solana.com",
    });

    // Fail-closed: any sim error → simulation-failed HOLD
    const simFinding = verdict.findings.find((f) => f.id === "simulation-failed");
    expect(simFinding).toBeDefined();
    expect(simFinding!.severity).toBe("HOLD");
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// S3: benign sim (no outflows) → no extra finding
// ─────────────────────────────────────────────────────────────────────────────

describe("S3: benign sim → no extra simulation finding", () => {
  it("S3.1 sim shows zero delta (signer keeps same SOL) → no simulation-outflow finding", () => {
    const { b64 } = buildTransferMsg(0n); // 0 lamport transfer
    const ctx: VerdictContext = {
      ...DEFAULT_CONTEXT,
      simulation: {
        ok: true,
        signerSolDelta: 0n,
        tokenDeltas: [],
        outflowsToNonSigner: [], // no outflows
      },
    };
    const verdict = reviewBase64(b64, ctx);
    const simFinding = verdict.findings.find(
      (f) => f.id === "simulation-outflow" || f.id === "simulation-failed",
    );
    expect(simFinding).toBeUndefined();
  });

  it("S3.2 reviewWithEnrichment + frozen benign sim → no sim finding", async () => {
    const { b64 } = buildTransferMsg(0n);

    const { decodeInput } = await import("../src/decode.ts");
    const { message } = decodeInput(b64);
    const signerPk = message.staticAccountKeys[0]!;

    const benignSim: SimulateFn = async (_b64, _addrs) =>
      makeBenignSimResult(5_000_000_000n); // same before and after

    // We need to ensure the sim result has preBalances set to get a zero delta
    const customSim: SimulateFn = async (_b64, _addrs) => ({
      err: null,
      logs: [],
      accounts: [{ lamports: 5_000_000_000n, data: Buffer.alloc(0), owner: SYSTEM }],
      preBalances: [5_000_000_000n], // same pre = zero delta
    } as SimulateResult & { preBalances: bigint[] });

    void signerPk; // used to confirm we got the right address

    const verdict = await reviewWithEnrichment(b64, DEFAULT_CONTEXT, NOOP_FETCHER, {
      simulate: true,
      simulateFn: customSim,
      rpcUrl: "https://api.mainnet-beta.solana.com",
    });

    const simFinding = verdict.findings.find(
      (f) => f.id === "simulation-outflow" || f.id === "simulation-failed",
    );
    expect(simFinding).toBeUndefined();
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// S4: simulation NEVER downgrades a static REJECT to SIGN
// ─────────────────────────────────────────────────────────────────────────────

describe("S4: simulation escalate-only — never downgrades static REJECT", () => {
  it("S4.1 static REJECT + benign sim → still REJECT", () => {
    // Build a SetAuthority (disc=6) which is REJECT-class in the catalog
    // Actually let's just inject a simulation onto a known REJECT verdict.
    // The BPF Upgradeable Loader upgrade instruction is always REJECT.
    // Use a simpler approach: static REJECT fixture + benign simulation in ctx.
    //
    // We'll use the setauthority fixture known to produce REJECT.
    // Build: SPL Token SetAuthority (disc=6, type=1=MintTokens, new authority set)
    // This is a REJECT in the catalog.
    const setAuthData = [
      6,   // disc = SetAuthority
      1,   // authority_type = MintTokens
      1,   // COption<Pubkey> = Some
      ...key(0x22), // new authority pubkey (32 bytes)
    ];
    const splTokenBytes = (() => {
      // Base58-decode SPL Token program ID "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
      // Use a fill to approximate it in helper format
      // Actually let's use legacyBytes with the SPL Token programId pattern
      // The SPL token program bytes when base58-decoded are specific.
      // For test purposes, we inject the simulation directly via ctx.simulation.
      return null;
    })();
    void setAuthData; void splTokenBytes;

    // Simpler: build a message that we KNOW static analysis will REJECT,
    // then attach a "benign" simulation and verify REJECT is preserved.
    // We'll use a ctx with an explicit simulation and a known-bad verdict from
    // a fixture.
    //
    // Build a static REJECT scenario: unknown program writing to writable account
    // in strict mode (strict=true → unknown writable → REJECT).
    const raw = legacyBytes(
      [1, 0, 0], // 1 signer, 0 ro signed, 0 ro unsigned (so key[1] is writable)
      [0x01, 0xff], // [0]=signer (writable), [1]=unknown program (all 0xFF)
      [{ prog: 1, accts: [0], data: [0xde, 0xad] }],
    );
    const b64 = toB64(raw);

    const ctx: VerdictContext = {
      ...DEFAULT_CONTEXT,
      strict: true, // unknown writable → REJECT in strict mode
      simulation: {
        ok: true,
        signerSolDelta: 0n, // "benign" simulation shows no loss
        tokenDeltas: [],
        outflowsToNonSigner: [], // no outflows
      },
    };

    const verdict = reviewBase64(b64, ctx);
    // Static analysis in strict mode → REJECT due to unknown program
    // The benign simulation must NOT downgrade this to SIGN
    expect(verdict.decision).toBe("REJECT");
    // Simulation-outflow finding should NOT be present (benign sim)
    expect(verdict.findings.find((f) => f.id === "simulation-outflow")).toBeUndefined();
  });

  it("S4.2 static REJECT + drain sim → still REJECT (simulation can escalate but not downgrade)", () => {
    // Unknown program in strict mode → REJECT. Drain sim also fires simulation-outflow
    // but can't further escalate beyond REJECT, and certainly can't downgrade it.
    const raw = legacyBytes(
      [1, 0, 0],
      [0x01, 0xff],
      [{ prog: 1, accts: [0], data: [0xde, 0xad] }],
    );
    const b64 = toB64(raw);

    const ctx: VerdictContext = {
      ...DEFAULT_CONTEXT,
      strict: true,
      simulation: {
        ok: true,
        signerSolDelta: -2_000_000_000n,
        tokenDeltas: [],
        outflowsToNonSigner: [{ to: "_non-signer_", amount: 2_000_000_000n, kind: "sol" }],
      },
    };

    const verdict = reviewBase64(b64, ctx);
    expect(verdict.decision).toBe("REJECT");
    // simulation-outflow finding is added (escalate-only), but verdict stays REJECT
    expect(verdict.findings.find((f) => f.id === "simulation-outflow")).toBeDefined();
  });

  it("S4.3 absent simulation (ctx.simulation undefined) → verdict byte-identical to pre-simulation", () => {
    // No simulation → verdict must match the offline baseline exactly.
    const { b64 } = buildTransferMsg(100n);
    const ctxWithoutSim: VerdictContext = DEFAULT_CONTEXT;
    const ctxWithUndefinedSim: VerdictContext = { ...DEFAULT_CONTEXT, simulation: undefined };

    const v1 = reviewBase64(b64, ctxWithoutSim);
    const v2 = reviewBase64(b64, ctxWithUndefinedSim);

    // Decisions, findings count, and reason must match
    expect(v1.decision).toBe(v2.decision);
    expect(v1.findings.length).toBe(v2.findings.length);
    expect(v1.reason).toBe(v2.reason);
    // No simulation findings in either
    expect(v1.findings.find((f) => f.id.startsWith("simulation-"))).toBeUndefined();
    expect(v2.findings.find((f) => f.id.startsWith("simulation-"))).toBeUndefined();
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// S5: sim REJECT when outflow recipient is blocklisted
// ─────────────────────────────────────────────────────────────────────────────

describe("S5: sim outflow to blocklisted recipient → REJECT", () => {
  it("S5.1 sim outflow to known-bad address + blocklist → simulation-outflow REJECT", () => {
    const { b64 } = buildTransferMsg(100n);
    const badAddress = "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM";
    const ctx: VerdictContext = {
      ...DEFAULT_CONTEXT,
      recipientBlocklist: [badAddress],
      simulation: {
        ok: true,
        signerSolDelta: -100n,
        tokenDeltas: [],
        outflowsToNonSigner: [{ to: badAddress, amount: 100n, kind: "sol" }],
      },
    };

    const verdict = reviewBase64(b64, ctx);
    const simFinding = verdict.findings.find((f) => f.id === "simulation-outflow");
    expect(simFinding).toBeDefined();
    expect(simFinding!.severity).toBe("REJECT");
    expect(verdict.decision).toBe("REJECT");
  });

  it("S5.2 sim outflow to non-blocklisted address → HOLD (not REJECT)", () => {
    const { b64 } = buildTransferMsg(100n);
    const ctx: VerdictContext = {
      ...DEFAULT_CONTEXT,
      recipientBlocklist: ["9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM"], // different bad addr
      simulation: {
        ok: true,
        signerSolDelta: -100n,
        tokenDeltas: [],
        outflowsToNonSigner: [
          // to: _non-signer_ sentinel — not in blocklist
          { to: "_non-signer_", amount: 100n, kind: "sol" },
        ],
      },
    };

    const verdict = reviewBase64(b64, ctx);
    const simFinding = verdict.findings.find((f) => f.id === "simulation-outflow");
    expect(simFinding).toBeDefined();
    expect(simFinding!.severity).toBe("HOLD");
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// S8-S10: reviewWithEnrichment integration tests
// ─────────────────────────────────────────────────────────────────────────────

describe("S8: reviewWithEnrichment simulate=true + enrichment provenance", () => {
  it("S8.1 enrichment provenance is set when simulate is used", async () => {
    const { b64 } = buildTransferMsg(100n);
    const benignSim: SimulateFn = async () => ({
      err: null, logs: [], accounts: [
        { lamports: 5_000_000_000n, data: Buffer.alloc(0), owner: SYSTEM },
      ],
      preBalances: [5_000_000_000n],
    } as SimulateResult & { preBalances: bigint[] });

    const verdict = await reviewWithEnrichment(b64, DEFAULT_CONTEXT, NOOP_FETCHER, {
      simulate: true,
      simulateFn: benignSim,
      rpcUrl: "https://my-rpc.example.com",
    });

    expect(verdict.enrichment).toBeDefined();
    expect(verdict.enrichment!.rpcUrl).toBe("https://my-rpc.example.com");
    expect(verdict.enrichment!.simulated).toBe(true);
    expect(verdict.enrichment!.trustNote).toContain("RPC");
    expect(verdict.enrichment!.trustNote).toContain("digest");
  });

  it("S8.2 enrichment provenance is set even when simulate=false (not simulated)", async () => {
    const { b64 } = buildTransferMsg(100n);
    const verdict = await reviewWithEnrichment(b64, DEFAULT_CONTEXT, NOOP_FETCHER, {
      rpcUrl: "https://my-rpc.example.com",
    });

    expect(verdict.enrichment).toBeDefined();
    expect(verdict.enrichment!.simulated).toBe(false);
  });

  it("S8.3 offline reviewBase64 (no enrichment) never sets verdict.enrichment", () => {
    const { b64 } = buildTransferMsg(100n);
    const verdict = reviewBase64(b64, DEFAULT_CONTEXT);
    // Pure offline path: enrichment is never set
    expect(verdict.enrichment).toBeUndefined();
  });
});

describe("S9: simulate=true without simulateFn → fail-closed HOLD", () => {
  it("S9.1 simulate=true but no simulateFn → simulation-failed HOLD (fail-closed)", async () => {
    const { b64 } = buildTransferMsg(100n);
    const verdict = await reviewWithEnrichment(b64, DEFAULT_CONTEXT, NOOP_FETCHER, {
      simulate: true,
      // simulateFn intentionally omitted
      rpcUrl: "https://api.mainnet-beta.solana.com",
    });
    // Should fail-closed: simulation-failed HOLD
    const simFinding = verdict.findings.find((f) => f.id === "simulation-failed");
    expect(simFinding).toBeDefined();
    expect(simFinding!.severity).toBe("HOLD");
    expect(verdict.decision).toBe("HOLD");
  });
});

describe("S10: simulation invariant — never SIGN after adding simulation", () => {
  it("S10.1 adding simulation (ok=true) to an already-SIGN verdict keeps it SIGN when sim is benign", () => {
    // A truly benign tx (0 lamports, no findings) is SIGN offline.
    // Attaching a benign simulation should NOT change it.
    const { b64 } = buildTransferMsg(0n);
    const baseVerdict = reviewBase64(b64, DEFAULT_CONTEXT);
    expect(baseVerdict.decision).toBe("SIGN");

    const ctx: VerdictContext = {
      ...DEFAULT_CONTEXT,
      simulation: { ok: true, signerSolDelta: 0n, tokenDeltas: [], outflowsToNonSigner: [] },
    };
    const withSim = reviewBase64(b64, ctx);
    // Still SIGN — benign sim adds nothing
    expect(withSim.decision).toBe("SIGN");
  });

  it("S10.2 drain sim on SIGN baseline upgrades to HOLD (escalate-only)", () => {
    const { b64 } = buildTransferMsg(0n);
    const baseVerdict = reviewBase64(b64, DEFAULT_CONTEXT);
    expect(baseVerdict.decision).toBe("SIGN");

    // Now attach a drain simulation — must escalate to HOLD, not stay SIGN
    const ctx: VerdictContext = {
      ...DEFAULT_CONTEXT,
      simulation: {
        ok: true,
        signerSolDelta: -1_000_000_000n, // 1 SOL drain
        tokenDeltas: [],
        outflowsToNonSigner: [{ to: "_non-signer_", amount: 1_000_000_000n, kind: "sol" }],
      },
    };
    const withSim = reviewBase64(b64, ctx);
    expect(withSim.decision).toBe("HOLD");
    // The simulation finding is there
    expect(withSim.findings.find((f) => f.id === "simulation-outflow")).toBeDefined();
  });
});
