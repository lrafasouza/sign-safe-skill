/**
 * gen-goldens.ts -- regenerate the checked-in NN_name.verdict.json golden files
 * from the current core. Run AFTER reviewing that each fixture's decision is
 * intended (the goldens are a security contract: never regenerate blindly).
 *
 * Run: npm run gen-goldens
 */

import { readFileSync, writeFileSync, readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { reviewBase64, verdictToJson } from "../src/verdict.ts";

const HERE = dirname(fileURLToPath(import.meta.url));

const names = readdirSync(HERE)
  .filter((f) => /^\d\d_.*\.b64$/.test(f))
  .sort()
  .map((f) => f.replace(/\.b64$/, ""));

for (const name of names) {
  const b64 = readFileSync(join(HERE, `${name}.b64`), "utf8");
  const json = verdictToJson(reviewBase64(b64));
  writeFileSync(join(HERE, `${name}.verdict.json`), json + "\n", "utf8");
  process.stdout.write(`wrote ${name}.verdict.json\n`);
}
process.stdout.write(`\nregenerated ${names.length} golden verdicts\n`);
