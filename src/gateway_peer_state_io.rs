use std::path::Path;

use crate::{
    HostError,
    gateway_peer_state::{PeerDenyLedgerV1, schema},
};

pub(super) fn initialize(
    root: &Path,
    anchor: &Path,
    deployment: &str,
    epoch: u64,
) -> Result<(), HostError> {
    let state_marker = crate::gateway_state_marker::present(root, "peer-state")?;
    let anchor_marker = crate::gateway_state_marker::present(anchor, "peer-anchor")?;
    if state_marker {
        crate::gateway_state_marker::verify(root, "peer-state", deployment, epoch)?;
    }
    if anchor_marker {
        crate::gateway_state_marker::verify(anchor, "peer-anchor", deployment, epoch)?;
    }
    if !state_marker || !anchor_marker {
        initialize_ledger(root, anchor)?;
        crate::gateway_state_marker::initialize(root, "peer-state", deployment, epoch)?;
        crate::gateway_state_marker::initialize(anchor, "peer-anchor", deployment, epoch)?;
    }
    ensure(root, anchor, deployment, epoch)
}

pub(super) fn ensure(
    root: &Path,
    anchor: &Path,
    deployment: &str,
    epoch: u64,
) -> Result<(), HostError> {
    markers(root, anchor, deployment, epoch)?;
    read(root, anchor, deployment, epoch).map(|_| ())
}

pub(super) fn read(
    root: &Path,
    anchor: &Path,
    deployment: &str,
    epoch: u64,
) -> Result<PeerDenyLedgerV1, HostError> {
    markers(root, anchor, deployment, epoch)?;
    crate::gateway_peer_ledger::read(root, anchor)
}

pub(super) fn write(
    root: &Path,
    anchor: &Path,
    deployment: &str,
    epoch: u64,
    value: &PeerDenyLedgerV1,
) -> Result<(), HostError> {
    markers(root, anchor, deployment, epoch)?;
    write_ledger(root, anchor, value)
}

fn initialize_ledger(root: &Path, anchor: &Path) -> Result<(), HostError> {
    let anchors = crate::gateway_peer_anchor::read(anchor)?;
    let generations = crate::gateway_peer_ledger::generations(root)?;
    if anchors.is_none() && generations.is_empty() {
        write_ledger(root, anchor, &PeerDenyLedgerV1::empty())
    } else {
        let value = crate::gateway_peer_ledger::read(root, anchor)?;
        (value.revision == 1 && value.entries.is_empty())
            .then_some(())
            .ok_or(HostError::StateInvalid)
    }
}

fn write_ledger(root: &Path, anchor: &Path, value: &PeerDenyLedgerV1) -> Result<(), HostError> {
    validate(value, value.revision)?;
    let wire = serde_json::to_vec(value).map_err(|_| HostError::StateInvalid)?;
    let digest = crate::host_crypto::digest(&wire);
    crate::management_v2_atomic::immutable(
        root,
        &crate::gateway_peer_ledger::generation(root, &digest)?,
        &wire,
    )?;
    let retained = crate::gateway_peer_anchor::write(anchor, value.revision, &digest)?;
    for (item, path) in crate::gateway_peer_ledger::generations(root)? {
        if !retained.contains(&item) {
            crate::host_files::owner_file(&path, 2_097_152)?;
            std::fs::remove_file(path).map_err(|_| HostError::StateInvalid)?;
        }
    }
    crate::management_v2_atomic::sync(root)
}

fn markers(root: &Path, anchor: &Path, deployment: &str, epoch: u64) -> Result<(), HostError> {
    crate::gateway_state_marker::verify(root, "peer-state", deployment, epoch)?;
    crate::gateway_state_marker::verify(anchor, "peer-anchor", deployment, epoch)
}

pub(super) fn validate(value: &PeerDenyLedgerV1, revision: u64) -> Result<(), HostError> {
    let mut devices = std::collections::BTreeSet::new();
    let mut certificates = std::collections::BTreeSet::new();
    let mut request_keys = std::collections::BTreeSet::new();
    let valid = value.schema == schema()
        && value.revision == revision
        && revision > 0
        && valid_digest(&value.authority_head_sha256)
        && value.entries.len() <= 10_000
        && value.entries.iter().all(|item| {
            ((!item.registered
                && !item.revoked
                && item.device_revocation_epoch == 0
                && item.revoked_at_epoch_s == 0)
                || (item.registered
                    && item.device_revocation_epoch > 0
                    && ((!item.revoked && item.revoked_at_epoch_s == 0)
                        || (item.revoked && item.revoked_at_epoch_s > 0))))
                && valid_digest(&item.certificate_sha256)
                && valid_id(&item.device_id)
                && valid_id(&item.request_key_id)
                && devices.insert(&item.device_id)
                && certificates.insert(&item.certificate_sha256)
                && request_keys.insert(&item.request_key_id)
        });
    valid.then_some(()).ok_or(HostError::StateInvalid)
}

fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

pub(super) fn valid_digest(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|item| item.is_ascii_digit() || matches!(item, b'a'..=b'f'))
}
