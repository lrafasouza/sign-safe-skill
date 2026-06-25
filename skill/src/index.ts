/**
 * Review a base64-encoded Solana message or full transaction offline.
 */
export { reviewBase64, verdictToJson } from "./verdict.ts";

/**
 * Review with caller-injected account enrichment and optional simulation.
 */
export { reviewWithEnrichment } from "./review-online.ts";

/**
 * Decode a base64 Solana message or full transaction into the stable wire model.
 */
export { decodeInput } from "./decode.ts";

/**
 * Default deterministic review policy (1 SOL large-transfer threshold).
 */
export { DEFAULT_CONTEXT } from "./types.ts";

export type { Finding, Verdict, VerdictContext } from "./types.ts";
export type { AccountFetcher } from "./enrich.ts";
export type { ReviewEnrichmentOpts } from "./review-online.ts";
export type { SimulateFn } from "./simulate.ts";
