# Crowsi Credential Authority

This repository owns the metadata-only relationship between a pairwise service
account, credential references, registered devices, use grants, and credential
transfer state. It is not a credential vault, an identity provider, or a raw
secret transport.

## Boundary

- Owners are opaque `OpaqueOwnerRef` values produced by an injected
  `ServiceAccountOwnerMapper`. Email addresses and global user identifiers are
  rejected as owners.
- Device registration and production grant issuance consume the exact
  `DeviceIdentityAssertionV1` contract from
  `ihat-identity-assertion-contracts = 0.1.0`.
- The shared contract performs bounded closed decoding, canonical payload
  construction, signature verification, issuer/audience checks, and time checks.
  `verify_device_identity_assertion` returns Crowsi's secret-free verified
  projection only after the injected verifier confirms authoritative
  subject/service/device/session revocation epochs. Crowsi then checks the mapped
  owner, device proof-key reference, posture revision, and registered epochs.
- Credential records and projections contain metadata only. There is no secret
  field, raw-secret accessor, or credential-material serialization path.

The durable boundary is intentionally finite: an owner has at most 64
credentials, 64 devices, and 512 sessions, while one owner/credential has at
most 64 active-or-pending grants across all devices. The
authority rejects overflow before commit, and management projections contain
the complete admitted set rather than silently truncating authoritative state.

## State machines

Device grants are owner, credential revision, source device, target device,
audience, action, proof key, posture, revocation epoch, nonce, and TTL bound.
They are one-use and persist consumed, expired, and revoked states.

Transfers start with the source active and target pending. Commit changes source
to revoked and target to active in one store transaction. Failpoints prove that
an interrupted commit rolls back without dual authority. Cancellation keeps the
source active and permanently revokes the pending target.

Shared and nonexportable credentials reject wrapped material transfer. They use
provider reissue instead, and target activation requires a verified,
target-bound provider revision receipt. Unknown provider outcomes are durable,
require signed reconciliation, and prohibit blind retry.

Deployable `CredentialAuthority` provider transitions require an injected
`ProviderEvidenceVerifier` over bounded canonical receipt/outcome payloads.
No production source contains a fixed signature verifier or an identity
registration shortcut.

## Stores

`MemoryStore` and generic authority constructors are available only through the
non-release `test-support` feature. Production callers receive only the finite,
signed host and gateway entry points.

`FileAuthorityStore` is the deployable local ledger. Host-config v2 requires
separate, pre-provisioned `authority_store_directory` and
`authority_anchor_directory` paths. Both are absolute, canonical, owner `0700`
directories retained by descriptor. Data, marker, head, anchor, and lock files
must be owner `0600`, regular, single-link files. Reads use bounded
`O_NOFOLLOW|O_CLOEXEC` descriptors and verify path-to-descriptor metadata before
and after I/O.

The store retains at most three consecutive immutable, content-addressed
snapshot generations and three matching immutable anchors. A hash chain covers
the complete closed snapshot. Identical committed-head documents in both
directories name the current generation, snapshot digest, and anchor digest.
A mutation fsyncs the immutable pair, advances both heads, and only then prunes
the obsolete fourth pair. Exact recovery discards pre-head partial writes,
finishes a verified one-head advance, and finishes only an obsolete partial
prune. Unknown files, temporary files, missing retained files, and nonconsecutive
sets fail closed.

Normal `open_anchored(state, anchor)` never creates a directory, lock, marker,
or generation. The signed installer-only host `initialize-once` command calls
the crate-private initializer. Its fixed binding markers and generation-zero
contents make every completed fsync boundary exactly resumable; a different
clock, store identifier, unknown file, or partial shape is rejected.

ManagementV2 state uses per-owner content-addressed generations and a distinct
monotonic anchor directory. That directory is a separately provisioned central
authority TCB; endpoints never receive the authority store, journal, or anchor.

## Coela production adapter

`CoelaAuthorityAdapter::open_anchored` is the bounded internal composition surface. It
always uses `FileAuthorityStore` and requires injected iHAT assertion, pairwise
owner-mapping, authoritative-epoch, provider-evidence, and authoritative
step-up/target-key proof ports. A one-use,
registered-device assertion gates the secret-free device/credential management
projection. The same adapter exposes register, issue-grant, prepare/finish/
cancel transfer, record-unknown-outcome, and signed-reconciliation mutations.

The central release contains the finite
`crowsi-credential-authority-host handle-once` process and the bounded mTLS
`crowsi-credential-authority-gateway serve` process. They are installed only on
the independent authority node. Endpoint and Coela releases do not embed the
store or authority implementation.

## Verification

```text
cargo check --locked --offline --lib
cargo clippy --locked --offline --lib -- -D warnings
```

The main acceptance ledger is `tests/credential_authority.rs` (`CR-01` through
`CR-10`, `TR-01` through `TR-08`, and `E2E-01`). `tests/file_authority_store.rs` covers durable
reopen, concurrent one-winner use, tamper/rollback detection, path hardening,
and the Coela production adapter's one-use secret-free management projection.
