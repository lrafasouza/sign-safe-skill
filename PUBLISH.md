# Publishing `sign-safe` to npm

> Prepared for v0.6.0. **You run the publish** (it needs your npm credential). Nothing is published from the build session.

## What ships

- Package name: **`sign-safe`** (verified available on npm) → `npx sign-safe <tx.b64>` and the `sign-safe-mcp` server work after publish.
- Bins: `sign-safe` → `dist/src/cli.js`, `sign-safe-mcp` → `dist/src/mcp.js`.
- Version: **0.6.0**.

## Dry-run (already verified green)

```
$ npm pack --dry-run
npm notice name: sign-safe
npm notice version: 0.6.0
npm notice filename: sign-safe-0.6.0.tgz
npm notice package size: 220.1 kB
npm notice unpacked size: 883.6 kB
npm notice total files: 106
```

Contents are limited by `package.json` `files[]`: `dist/`, `skill/SKILL.md` + `skill/catalog|schema|references|rules`, `commands/`, `examples/`, `scripts/`, `DEMO.md`, `SECURITY.md`, `SUBMISSION.md`, `RUBRIC_CHECKLIST.md`, `docs/precision-report.md`, `docs/evaluator-transcript.md`, `docs/real-attacks.md`. No fixtures, corpus, tests, or secrets ship.

## Steps to publish

```bash
# 1. From the repo root, on a clean checkout of the v0.6.0 release commit:
npm ci                 # clean install (no postinstall)
npm run verify:all     # full gate must be green (build + tests + fixtures + attack replay + pack + audit)

# 2. Log in to your npm account (one-time):
npm login              # or: npm whoami  to confirm you're already logged in

# 3. Publish (prepublishOnly runs the build automatically):
npm publish --access public

# 4. Verify:
npm view sign-safe version    # -> 0.6.0
npx sign-safe skill/fixtures/02_setauthority_reject.b64   # -> REJECT (exit 20)
```

## After publishing

- Add the npm badge / `npx sign-safe` line to the README's Evaluator Quickstart.
- The bounty/kit submission can then say "installable: `npx sign-safe`".
