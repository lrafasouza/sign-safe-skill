# sign-safe evaluator demo

This walkthrough is intentionally short. It shows how sign-safe behaves on three
pre-sign cases without needing RPC, a wallet, a keypair, or devnet funds.

Run from the repository root after `npm ci`.

## Scenario 1: benign transfer

The fixture is a small, recognized System transfer. It should return `SIGN`
because the instruction shape is known and no danger primitive is present.

```bash
node --import tsx skill/src/cli.ts skill/fixtures/01_safe_sol_transfer.b64
```

Expected decision:

```text
[ SIGN ]
```

Interpretation: sign-safe found no known dangerous primitive in the message.
This does not prove the business intent is correct; it means the bytes match a
recognized benign shape under the current policy.

## Scenario 2: authority transfer

The fixture changes SPL Token authority. It should return `REJECT` before any key
is touched.

```bash
node --import tsx skill/src/cli.ts skill/fixtures/02_setauthority_reject.b64 || true
```

Expected decision:

```text
[ REJECT ]
SPL Token SetAuthority
```

Interpretation: authority or ownership changes are treated as high-risk signing
events because they can hand future control to another party without an immediate
balance delta.

## Scenario 3: hidden proposal risk

The attack replay pack includes curated hidden-authority and durable-nonce cases,
including Squads-shaped proposal/execution flows. It should hold or reject every
fixture before signing.

```bash
npm run demo:attack-pack
```

Expected summary:

```text
Squads-Hidden-Authority          5/5       1      4     0
Caught before signing: 37/37
False SIGN: 0
RESULT: 37/37 attack fixtures held or rejected before signing
```

Interpretation: the replay pack is a reproducible evaluator proof over a curated
attack corpus. It is not a claim that every malicious Solana transaction is
detected.

## Safe claims

- sign-safe decodes and classifies transaction bytes before signing.
- sign-safe reduces blind-signing risk for humans, wallets, and agents.
- sign-safe flags known dangerous primitives and fails closed on malformed,
  unknown, or unresolved cases.
- sign-safe can be used as a pre-sign gate through CLI, JSON, MCP, API, and
  guarded signing wrappers.

## Boundaries

- sign-safe is pre-signing analysis, not on-chain enforcement.
- `SIGN` means the current static policy recognized the transaction shape as
  benign; it still requires recipient, amount, intent, and policy review.
- Detection is limited to implemented primitives, registries, fixtures, and
  available transaction context.
- sign-safe complements review, simulation, policy, custody controls, and human
  approval; it does not replace them.
