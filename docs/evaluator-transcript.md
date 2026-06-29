# Evaluator transcript

This file captures the expected high-signal output from a clean reviewer run.
It is intentionally abbreviated; the commands themselves remain the source of
truth.

## One-command verification

```bash
npm run verify:all
```

Expected checkpoints:

```text
==> TypeScript build
$ npm run build

==> Vitest suite
$ npm test

 Test Files  38 passed (38)
      Tests  764 passed (764)

==> Deterministic fixture runner
$ npm run test:fixtures

PASS 70   FAIL 0
RESULT: ALL GREEN

==> Attack replay pack
$ npm run demo:attack-pack

False SIGN: 0
RESULT: 37/37 attack fixtures held or rejected before signing

==> Package dry-run
$ npm pack --dry-run

==> Production dependency audit
$ npm audit --omit=dev
found 0 vulnerabilities

verify:all passed
```

## Attack replay summary

```text
Family                           Caught    REJECT HOLD  SIGN
-------------------------------- --------- ------ ----- ----
Durable-Nonce-Sensitive          5/5       2      3     0
Multi-Transfer-Sweep             5/5       0      5     0
SPL-Approve                      5/5       0      5     0
SetAuthority-AccountOwner        7/7       7      0     0
Squads-Hidden-Authority          5/5       1      4     0
System-Assign                    5/5       5      0     0
Token2022-PermanentDelegate      5/5       0      5     0

Total attack fixtures: 37
Caught before signing: 37/37
False SIGN: 0
RESULT: 37/37 attack fixtures held or rejected before signing
```

## Verdict interpretation

- `REJECT`: known dangerous shape or untrusted bytes; do not sign.
- `HOLD`: unclear, policy-sensitive, or human-review case; do not auto-sign.
- `SIGN`: recognized benign shape under the current static policy.

SIGN does not mean safe. It means sign-safe did not find a known dangerous
primitive under the current policy. Recipient, amount, business intent,
counterparty reputation, custody policy, and human approval can still matter.

## Safe claims

- sign-safe reviews Solana transaction bytes before signing.
- sign-safe produces a machine-readable `SIGN` / `HOLD` / `REJECT` verdict.
- sign-safe catches the curated attack replay pack before a signing function is
  called.
- sign-safe fails closed for malformed input, unresolved ALT-dependent input, and
  unknown risky shapes under policy.

## Boundaries

- sign-safe is a pre-signing analysis layer, not an on-chain enforcement layer.
- `SIGN` does not mean safe; it means the current static policy recognized the
  transaction shape as benign.
- Coverage is limited to implemented primitives, registries, fixtures, and
  available transaction context.
- sign-safe complements audit, simulation, custody policy, multisig policy, and
  human review; it does not replace them.
