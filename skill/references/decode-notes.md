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
- values above `0xFFFF`,
- non-minimal encodings (a trailing zero continuation byte).

### Trailing bytes => reject

A well-formed message consumes **all** of its bytes. If any bytes remain after
parsing, we refuse to trust the partial parse and raise a decode error (which the
verdict layer turns into REJECT). This is what catches truncation and tampering.

## Header role math

Static account roles are derived purely from the three header counts and the
canonical key ordering (signers first, writable before readonly within each
group). With `N = numStaticKeys`:

```
[ 0 .. numRequiredSignatures - numReadonlySignedAccounts )   signer + writable
[ .. numRequiredSignatures )                                 signer + readonly
[ numRequiredSignatures .. N - numReadonlyUnsignedAccounts ) writable
[ .. N )                                                     readonly
```

We also sanity-check that the header counts are consistent with the key count;
inconsistent headers are a decode error.

## ALT conservatism (the key safety choice)

A v0 message's `addressTableLookups` reference accounts by *index into an
on-chain Address Lookup Table*. Resolving an index to a concrete address
requires fetching the table account over RPC -- a **network** operation the core
never performs. Therefore:

- every ALT-referenced account is emitted with role `unverified` and
  `verified: false`;
- the verdict layer treats the presence of *any* unverified role as a hard bar
  against `SIGN`.

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

When `roles.ts` appends synthetic `unverified` entries for ALT-referenced
indexes, it follows Solana's canonical resolution order so a synthetic role's
index matches the real runtime account index:

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
  - System / BPF Loader Upgradeable: a 4-byte little-endian `u32` enum index
    (e.g. System `Transfer = 2`, `AdvanceNonceAccount = 4`; BPF `Upgrade = 3`,
    `SetAuthority = 4`). We read the **full `u32`** for *both* of these programs
    (`classify.ts` keys this off a `U32_TAG_PROGRAMS` set), so a crafted payload
    like `[3,1,0,0]` cannot masquerade as tag `3` — only `[3,0,0,0]` (u32 = 3)
    matches. Matching only `byte[0]` would have let non-zero high bytes spoof a
    danger tag; the BPF Loader path previously did exactly that and is now fixed.
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
