#!/usr/bin/env node

import { spawnSync } from "node:child_process";

const checks = [
  ["npm", ["run", "build"], "TypeScript build"],
  ["npm", ["test"], "Vitest suite"],
  ["npm", ["run", "test:fixtures"], "Deterministic fixture runner"],
  ["npm", ["run", "demo:attack-pack"], "Attack replay pack"],
  ["npm", ["pack", "--dry-run"], "Package dry-run"],
  ["npm", ["audit", "--omit=dev"], "Production dependency audit"],
];

for (const [command, args, label] of checks) {
  console.log("");
  console.log(`==> ${label}`);
  console.log(`$ ${command} ${args.join(" ")}`);
  const result = spawnSync(command, args, {
    cwd: process.cwd(),
    stdio: "inherit",
    shell: false,
  });

  if (result.error) {
    console.error(`${label} failed to start: ${result.error.message}`);
    process.exit(1);
  }
  if (result.status !== 0) {
    console.error(`${label} failed with exit ${result.status}`);
    process.exit(result.status ?? 1);
  }
}

console.log("");
console.log("verify:all passed");
