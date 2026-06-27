# Security Policy

sign-safe is a pre-signing transaction review gate for Solana agents, wallets,
and signing workflows. It decodes transaction bytes before signature and returns
a SIGN, HOLD, or REJECT verdict for automation.

## Security Boundary

sign-safe:

- reviews base64 Solana messages or transactions before signing;
- classifies known dangerous primitives and fail-closed unknown shapes;
- can use optional RPC enrichment for ALT, Squads, Token-2022, and simulation context;
- can wrap signer calls so REJECT transactions are stopped before a key is touched.

sign-safe does not custody funds, does not hold private keys, and does not enforce limits on-chain.
It is not a multisig, not a spending-limit program, not a wallet, and not a
replacement for on-chain controls such as Squads policies or program-level
authorization.

## Threat Model

In scope:

- blind-signing opaque transaction bytes;
- hidden authority changes;
- durable nonce replay risk;
- dangerous SPL Token and Token-2022 authority/delegate/close flows;
- Squads v4 execute shells whose inner instruction is missing or dangerous;
- unknown writable programs and unresolved ALT roles;
- simulation-only economic drains when `--simulate` is explicitly enabled.

Out of scope:

- compromised private keys after a transaction is approved;
- malicious wallet UI outside the bytes sent to sign-safe;
- off-chain database policy enforcement;
- proving that a SIGN verdict matches human intent;
- guaranteeing population-wide malicious recall beyond the committed corpus.

## Safe Usage Rules

- Never send private keys, seed phrases, or keypair files to sign-safe.
- Treat SIGN as "recognized and within configured thresholds", not as a guarantee of safety.
- Treat HOLD as a required human-review stop for autonomous agents.
- Treat REJECT as a hard stop.
- Use on-chain controls for custody, spending limits, multisig governance, and recovery.

## Dependency Posture

The deterministic core has no runtime dependencies. The package uses optional
peer dependencies for adapters and development dependencies for fixture
generation, differential tests, and the local test runner. The CI and
`npm run verify:all` gate use `npm audit --omit=dev`, because production runtime
risk is the relevant package boundary.

## Responsible Disclosure

We welcome responsible disclosure for security-sensitive findings.

Please report security-sensitive issues through GitHub Security Advisories if
available, or email the maintainer listed in `package.json`. For non-sensitive
bugs, open a GitHub issue with a minimal transaction fixture and expected
verdict.
