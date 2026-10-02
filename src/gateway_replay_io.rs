use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
};

use crate::{
    HostError,
    gateway_replay_state::{GLOBAL_REPLAY_CAPACITY, PER_DEVICE_REPLAY_CAPACITY, ReplayLedger},
};

pub(super) fn initialize(
    root: &Path,
    anchor: &Path,
    deployment: &str,
    epoch: u64,
) -> Result<(), HostError> {
    let state = crate::gateway_state_marker::present(root, "replay-state")?;
    let anchored = crate::gateway_state_marker::present(anchor, "replay-anchor")?;
    if state {
        crate::gateway_state_marker::verify(root, "replay-state", deployment, epoch)?;
    }
    if anchored {
        crate::gateway_state_marker::verify(anchor, "replay-anchor", deployment, epoch)?;
    }
    if !state || !anchored {
        let head = crate::gateway_replay_anchor::read(anchor)?;
        let generations = generations(root)?;
        if head.is_none() && generations.is_empty() {
            write_ledger(root, anchor, &ReplayLedger::empty())?;
        } else {
            let value = read_ledger(root, anchor)?;
            if value.revision != 1 || !value.entries.is_empty() {
                return Err(HostError::StateInvalid);
            }
        }
        crate::gateway_state_marker::initialize(root, "replay-state", deployment, epoch)?;
        crate::gateway_state_marker::initialize(anchor, "replay-anchor", deployment, epoch)?;
    }
    read(root, anchor, deployment, epoch).map(|_| ())
}

pub(super) fn read(
    root: &Path,
    anchor: &Path,
    deployment: &str,
    epoch: u64,
) -> Result<ReplayLedger, HostError> {
    markers(root, anchor, deployment, epoch)?;
    read_ledger(root, anchor)
}

pub(super) fn write(
    root: &Path,
    anchor: &Path,
    deployment: &str,
    epoch: u64,
    value: &ReplayLedger,
) -> Result<(), HostError> {
    markers(root, anchor, deployment, epoch)?;
    write_ledger(root, anchor, value)
}

include!("gateway_replay_storage.rs");

fn validate(value: &ReplayLedger, revision: u64) -> Result<(), HostError> {
    let mut per_device = BTreeMap::<&str, usize>::new();
    let mut used = BTreeSet::new();
    let valid = value.schema == crate::gateway_replay_state::schema()
        && value.revision == revision
        && revision > 0
        && value.entries.len() <= GLOBAL_REPLAY_CAPACITY
        && value.entries.iter().all(|entry| {
            let count = per_device.entry(&entry.device_id).or_default();
            *count += 1;
            id(&entry.device_id)
                && bare_hex(&entry.nonce)
                && crate::gateway_replay_anchor::valid_digest(&entry.request_digest)
                && entry.consumed_at_epoch_s > 0
                && *count <= PER_DEVICE_REPLAY_CAPACITY
                && used.insert((&entry.device_id, &entry.nonce))
        });
    valid.then_some(()).ok_or(HostError::StateInvalid)
}

fn id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.trim() == value
        && !value.chars().any(char::is_control)
}
fn bare_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|v| v.is_ascii_digit() || matches!(v, b'a'..=b'f'))
}
