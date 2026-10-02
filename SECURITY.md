# Security model

## Protected assets

This authority protects credential ownership metadata, device authorization
state, credential revisions, one-use grants and nonces, transfer receipts,
provider reconciliation state, and revocation epochs. Credential values,
provider tokens, private keys, recovery material, and wrapped payload bytes are
outside this repository and must remain in custody/provider components.

No credential-secret type exists here. Public projections are bounded and
secret-free. Snapshot, `Debug`, and serialization implementations contain only
metadata and authorization state.

The signed authority store admits at most 64 credentials and 64 devices per
owner, 512 sessions per owner, and 64 active-or-pending grants for one
owner/credential across all devices. Registration, grant issuance, and transfer
prepare reject the next item before mutation. Expired grants are durably reaped
before a new grant consumes credential capacity. The same limits gate snapshot
decode, management projection, and device-revocation rotation bindings, so a
compromised device cannot become unrevokable through projection truncation or
provider-rotation fanout.

Revoking a device does not immediately free current-revision grant slots bound
to that durably revoked device. Those grants remain capacity reservations until
the exact provider rotation advances the credential revision in the same
authority transaction. Failed management transfers revoke their transient
source grant when an independent active source assignment remains, so repeated
signed not-issued/cancel outcomes do not consume those rotation reservations.
Consequently, concurrent grant/transfer issuance cannot consume rotation slots
between local cut-off and a lost-response provider reconciliation.

## Identity trust

Production registration and issuance must use the shared iHAT
`DeviceIdentityAssertionV1` decoder and verifier. Crowsi accepts only a verified
issuer/audience/time binding, then applies an injected pairwise-subject to
service-account mapping. The injected verifier must also compare all assertion
revocation epochs with their authoritative source. A caller-supplied owner or
device ID never overrides the verified binding.

Device proof-key reference, compliant posture revision, subject/service/device/
session epochs, assertion nonce, and assertion expiry are checked against the
durable registration. Epoch or posture rollback fails closed. Assertion and
target-key nonces are domain-separated and one-use.

Coela management reads use a configured management audience, a currently
registered device binding, and the same durable one-use identity nonce ledger.
The adapter never accepts a caller-provided owner for a management projection;
it derives the opaque owner through the injected pairwise mapper.

All adapter grant and transfer mutations call `OperationProofVerifier` before
the state machine sees a step-up or target-key proof. A production verifier must
consult its authoritative iHAT/PA proof source or validate its cryptographic
evidence; values carried by request DTOs are not authority on their own.

## Transfer safety

The target is pending until the transaction that revokes the source also
activates the target. Commit promotes the target grant to the target device's
current key, posture, session, and revocation epochs; source lineage remains in
the transfer record. Revoking the source afterward cannot revoke the committed
target. Transaction failure commits neither change. Provider
reissue receipts bind owner, service, provider account, credential, old/new
revision, target device, nonce, and issue time. Receipt mutation and reuse fail
closed. An unknown provider result disables retry until a signed reconciliation
for the exact provider operation and nonce is stored. Production transitions
call an injected `ProviderEvidenceVerifier`; the authority never decides
validity from a signature string or algorithm embedded in the request.

Account unlink/close revokes authority grants without requesting deletion of
custody secrets. Credential rotation revokes only grants pinned to the replaced
revision. Device revocation increments a monotonic device epoch and does not
revoke unrelated target-device grants.

## File ledger trust boundary

The file ledger rejects relative/noncanonical paths, symlinks, hard links,
FIFOs, oversized files, unknown names, temporary names, non-owner files, and
permissions other than directory `0700` and file `0600`. The state lock is
single-link, path-to-descriptor verified, and opened through the retained state
directory descriptor. Snapshot input is size-bounded and closed-schema decoded.
The state and anchor directories have independent immutable generation sets and
matching committed heads; one-sided deletion, replacement, or rollback is
rejected or forward-repaired only when the other head and immutable pair prove
the exact next revision.

There is no honest local claim that two ordinary directories provide a third
monotonic witness. An attacker who coherently restores the state directory and
the independent anchor directory to the same older complete pair can satisfy
all local hashes. In the deployed composition, the gateway's separately durable
peer-status ledger retains the newer authority revision/head and rejects that
rollback before serving traffic. A deployment that cannot rely on this witness
must put a monotonic counter or hardware-backed anchor outside the authority
host. Root/kernel compromise and provider-side credential theft also require
provider rotation and incident response.

The ManagementV2 operation journal uses a distinct, owner-provisioned
`management_anchor_directory`. Each per-owner generation is content-addressed;
its revision and complete ledger digest (active operations, consumed evidence,
and terminal tombstone index) are committed to that anchor before older
generations are pruned. The anchor must be backed by an independently managed
monotonic store or service. Copying or rolling back both the journal and anchor
under the same compromised service UID is an authority compromise, not endpoint
isolation. Managed endpoints never receive either authority directory.

## Provisioned runtime boundary

The central installer creates one persistent service: the mTLS gateway. Its
`ExecStartPre` invokes the finite host's signed-config `validate-once` command;
the gateway then invokes that digest-pinned host only for bounded requests. The
installer never stores or copies an endpoint client private key. Browser and
Coela components receive no authority signing or endpoint custody secret.

Activation readiness is deliberately limited to systemd active state, a
bounded raw TCP listener probe, and strict reopening of the independently
durable state and anchor markers. A real endpoint end-to-end test owns the mTLS,
signature, and current-peer readiness proof; the authority host cannot perform
that proof without violating endpoint key custody.

## Reporting and response

Treat any integrity, rollback, signature, unknown-field, epoch, or atomic-commit
error as fail-closed. Preserve the ledger and provider receipt metadata, revoke
the affected device or credential revision, reconcile provider state, and
reauthorize the target rather than exporting raw secret material.

## Private vulnerability reporting

Report vulnerabilities through this repository's GitHub private vulnerability reporting form. Do not put credentials, personal or customer data, or production certificate material in public issues or pull requests.
