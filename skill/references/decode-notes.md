# Decode Notes

Implementation notes for `src/decode.ts` and `src/roles.ts`. These explain the
wire format we parse and the conservative choices that keep the gate fail-closed.
For a full canonical reference on the Solana transaction/message format, defer to
the core **solana-dev** skill (by name); for reproducing a *landed* transaction,
defer to the **debug-user-tx** command (by name). We do not link those with
fragile relative paths because they live in sibling skills, not this repo.

## Message versions: legacy vs v0

The first byte of a serialized message disambiguates the version:

- **High bit set** (`byte & 0x80`): a **versioned** message. The low 7 bits are
  the version number. Only version `0` is currently defined; anything else is a
  hard decode error (fail-closed).
- **High bit clear:** a **legacy** message, and that first byte is already the
  first header byte (`numRequiredSignatures`).

## Layout we parse

```
legacy:
  [numRequiredSignatures u8]
  [numReadonlySignedAccounts u8]
  [numReadonlyUnsignedAccounts u8]
  [compact-u16 numStaticKeys] [pubkey * 32]...
  [recentBlockhash 32]
  [compact-u16 numInstructions]
    ( [programIdIndex u8]
      [compact-u16 numAccounts] [accountIndex u8]...
      [compact-u16 dataLen] [data]... )

v0:
  [0x80 | version]                  # version byte first
  ...same header + keys + blockhash + instructions as legacy...
  [compact-u16 numLookups]
    ( [lookupTableKey 32]
      [compact-u16 numWritable] [index u8]...
      [compact-u16 numReadonly] [index u8]... )
```

### compact-u16 (ShortVec)

Array lengths are encoded as a little-endian base-128 varint capped at 3 bytes /
16 bits. We reject:
- continuation past 3 bytes,
- values above `0xFFFF` (3rd byte > `0x03`),
- non-minimal / alias encodings (a trailing zero continuation byte),
- truncation (a continuation bit with no following byte).

The exact rejection set (`[0x80,0x00]`, `[0xff,0x00]`, `[0x80,0x80,0x00]`,
`[0x81,0x80,0x00]`, `[0x80]`, `[0x80,0x80,0x80,0x00]`, `[0x80,0x80,0x04]`,
`[0x80,0x80,0x06]`) and the canonical encode vectors are pinned in
`skill/test/decode.test.ts` and exercised by a fast-check property over the full
`[0, 65535]` range (`skill/test/pbt.test.ts`).

### Sanitization invariants (enforced at decode)

Beyond key-count consistency, the decoder rejects messages that the runtime/Squads
sanitize logic also rejects:
- `numRequiredSignatures >= 1` (there is always a fee payer),
- `numReadonlySignedAccounts < numRequiredSignatures` (**strict** — index 0 is
  always a *writable* signer / fee payer; equality would mean no writable fee
  payer and is invalid),
- `numRequiredSignatures + numReadonlyUnsignedAccounts <= numStaticKeys`,
- no duplicate keys in the static account list. (The full combined-list duplicate
  check, including ALT-resolved addresses, is online-only and deferred to the
  resolver.)

### Trailing bytes => reject

A well-formed message consumes **all** of its bytes. If any bytes remain after
parsing, we refuse to trust the partial parse and raise a decode error (which the
verdict layer turns into REJECT). This is what catches truncation and tampering.

## Header role math — TWO LAYERS (partition + demotion)

`roles.ts` reproduces the runtime's two-stage writability decision and exposes
BOTH on every `AccountRole` (`writablePartition` and `writableRuntime`), so the
output is reproducible whether or not a reserved set was supplied.

**Layer 1 — partition (`is_writable_index`, == `is_maybe_writable(i, None)`).**
Pure positional math over the header counts and the combined-list ordering. With
`K = numStaticKeys`, `S = numRequiredSignatures`, `Rs = numReadonlySignedAccounts`,
`Ru = numReadonlyUnsignedAccounts`, `W = Σ writable ALT indexes`:

```
[ 0 .. S-Rs )       signer + writable        (static)
[ S-Rs .. S )       signer + readonly        (static)
[ S .. K-Ru )       writable non-signer      (static)
[ K-Ru .. K )       readonly non-signer      (static)
loaded i >= K:      writable iff (i-K) < W   (ALT)
```

**Layer 2 — demotion (`is_writable_internal` / `demote_program_id`).** Even when
the partition layer says writable, the account is READONLY at runtime if EITHER
(a) its key is in the **reserved-account-keys** set (SIMD-0105), OR (b) it is used
as a `programIdIndex` by any instruction AND the upgradeable BPF loader is NOT
present in the combined list. The verdict consumes the demoted (runtime) mode;
`deriveRoles(msg, { reservedAccountKeys })` applies it, while `deriveRoles(msg)`
returns the raw partition mode (the runtime's `None` behaviour). The
reserved set is the SIMD-0105 active set (native programs + sysvars); the
**Incinerator is explicitly NOT reserved** and stays writable.

We also sanity-check that the header counts are consistent with the key count
(see the sanitization invariants above); inconsistent headers are a decode error.

## ALT conservatism (the key safety choice)

A v0 message's `addressTableLookups` reference accounts by *index into an
on-chain Address Lookup Table*. Resolving an index to a concrete address
requires fetching the table account over RPC -- a **network** operation the core
never performs. Therefore:

- every ALT-referenced account is emitted with `addressVerified: false` and a
  synthetic `alt:<table>#wN/#rN` address — but it keeps a REAL `writable` /
  `readonly` role, because the writable-vs-readonly distinction is fully
  determined by message ordering (the writable-region `[K, K+W)` vs the
  readonly-region `[K+W, K+W+R)`) and needs no network. Only the concrete
  *address* is unknown offline, not the writability;
- the verdict layer treats the presence of *any* account with
  `addressVerified: false` as a hard bar against `SIGN` (`hasUnverifiedRoles`).

A malicious transaction cannot hide a dangerous account behind an ALT and earn a
SIGN: the unresolved reference alone caps the verdict at HOLD. And if an
**unknown program** references an ALT-sourced account, the verdict is escalated
to **REJECT** (not merely HOLD): because the account's writability cannot be
proven without resolving the table, the gate fail-closes and treats it as a
writable, value-bearing target — closing the "hide a writable target behind an
ALT to downgrade an unknown-program REJECT" attack. Resolving the table (to
produce a better deterministic pass) is a documented runtime hook in
`src/enrich.ts`, never part of the offline core.

### Synthetic ALT role ordering (canonical two-pass)

When `roles.ts` appends synthetic entries (`addressVerified: false`) for
ALT-referenced indexes, it follows Solana's canonical resolution order so a
synthetic role's index matches the real runtime account index:

```
[ static keys ]
[ ALL writable indexes, table-by-table in lookup order ]
[ ALL readonly indexes, table-by-table in lookup order ]
```

i.e. a **two-pass** layout — every table's writable entries precede *any*
table's readonly entries. (A per-table interleaving would mis-number indexes for
multi-table v0 messages.)

Note: program ids may **not** be ALT-sourced (Solana requires them in the static
key set), so a program-id index outside the static keys is a decode error.

## Discriminators: base58, Anchor vs Pinocchio

- **Base58** is used for all on-chain addresses (program ids, keys, blockhash).
  We ship a small dependency-free base58 encoder in `decode.ts`.
- **Native programs** (System, SPL Token, Token-2022, BPF Loader Upgradeable)
  identify their instruction by a leading tag:
  - SPL Token / Token-2022: a single `u8` discriminator (e.g. `SetAuthority = 6`,
    `Approve = 4`, `CloseAccount = 9`, `Transfer = 3`, `TransferChecked = 12`).
  - System / BPF Loader Upgradeable: a 4-byte little-endian `u32` **bincode**
    discriminant (bincode serializes a Rust enum tag as a 4-byte LE u32; the
    `#[repr(u8)]` on the loader enum is a red herring). System: `Assign = 1`,
    `Transfer = 2`, `AssignWithSeed = 10`, `TransferWithSeed = 11`,
    `AdvanceNonceAccount = 4`. BPF Loader Upgradeable: `Upgrade = 3`,
    `SetAuthority = 4`, `Close = 5`, `SetAuthorityChecked = 7` — all four are
    high-impact (code replacement / authority handoff / account destruction) and
    are catalogued REJECT. We read the **full `u32`** for *both* programs
    (`classify.ts` keys this off a `U32_TAG_PROGRAMS` set), so a crafted payload
    like `[3,1,0,0]` (u32 = 259) cannot masquerade as tag `3` — only `[3,0,0,0]`
    (u32 = 3) matches.
  - **Compute Budget is the odd one out**: borsh, a single `u8` tag at byte 0
    (`SetComputeUnitLimit = 2`, `SetComputeUnitPrice = 3`, …), fields at offset 1.
    It only sets execution params (cannot move funds or change ownership), so it
    is treated as benign; the u32-LE rule is NEVER applied to it. This is also why
    the program id, not the data shape, drives the decoder: bytes `02 00 00 00 …`
    are a System Transfer under System but `SetComputeUnitLimit` under Compute
    Budget.
  - **SetAuthority decode (C4/C5):** for SPL/Token-2022 `SetAuthority` (tag 6) the
    finding detail decodes `authority_type` (byte 1) and the `COption` new
    authority (byte 2 flag; 32-byte pubkey when `Some`), names the AuthorityType,
    and flags an AuthorityType 4–17 used on classic SPL Token as invalid.
  - **Durable-nonce gate (C17):** a transaction is durable-nonce-backed IFF
    instruction **index 0** is a System `AdvanceNonceAccount`. At index ≥ 1 it is
    a routine nonce advance (an INFO note), NOT the non-expiry marker. A
    durable-nonce marker at ix0 **plus** any authority/ownership change escalates
    to REJECT (the Drift signature, V3).
  - For multi-variant catalog entries (more than one accepted discriminator,
    e.g. `durable-nonce-initialize` = `{6: InitializeNonceAccount,
    7: AuthorizeNonceAccount}` and `spl-approve-delegate` =
    `{4: Approve, 13: ApproveChecked}`), the finding `detail` names the exact
    decoded tag and variant, so the operator sees which sub-instruction matched.
- **Anchor** programs identify instructions with an **8-byte** discriminator
  (`sha256("global:<ix_name>")[..8]`). **Pinocchio** programs typically use a
  **1-byte** discriminator. None of the catalogued primitives are Anchor
  instructions, so the catalog matches native single-tag discriminators; an
  Anchor/Pinocchio program that is not in the known set is treated as an
  **unknown program** (which already forbids SIGN and, if it writes to a
  value-bearing account, forces REJECT).
