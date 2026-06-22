import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["skill/test/**/*.test.ts"],
    // Offline + deterministic. No globals; we import expect/describe explicitly.
    environment: "node",
    // Fail the run if any test file has zero assertions wired up by mistake.
    passWithNoTests: false,
    // Generous timeout: PBT runs can be a few seconds, all offline.
    testTimeout: 30_000,
  },
});
