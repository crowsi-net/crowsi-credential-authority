use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use crate::{HostError, management_v2_record::ManagementLedgerV2};

const SCHEMA: &str = "crowsi://credential-authority/management-commit-intent/v1";

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CommitIntentV1 {
    pub(super) schema: String,
    pub(super) owner_sha256: String,
    pub(super) prior_revision: u64,
    pub(super) prior_ledger_sha256: String,
    pub(super) revision: u64,
    pub(super) ledger_sha256: String,
}

pub(super) fn begin(
    root: &Path,
    owner: &str,
    prior: &ManagementLedgerV2,
    next: &ManagementLedgerV2,
    next_digest: &str,
) -> Result<CommitIntentV1, HostError> {
    let intent = CommitIntentV1 {
        schema: SCHEMA.into(),
        owner_sha256: crate::host_crypto::digest(owner.as_bytes()),
        prior_revision: prior.revision,
        prior_ledger_sha256: ledger_digest(prior)?,
        revision: next.revision,
        ledger_sha256: next_digest.into(),
    };
    validate(&intent, owner)?;
    let wire = serde_json::to_vec(&intent).map_err(|_| HostError::StateInvalid)?;
    crate::management_v2_atomic::immutable(root, &path(root, owner), &wire)?;
    read(root, owner)?
        .filter(|value| exact(value, &intent))
        .ok_or(HostError::StateInvalid)
}

pub(super) fn read(root: &Path, owner: &str) -> Result<Option<CommitIntentV1>, HostError> {
    let path = path(root, owner);
    if !crate::management_v2_atomic::present(&path)? {
        return Ok(None);
    }
    let wire = crate::host_files::owner_file(&path, 16_384)?;
    let value: CommitIntentV1 =
        serde_json::from_slice(&wire).map_err(|_| HostError::StateInvalid)?;
    validate(&value, owner)?;
    Ok(Some(value))
}

pub(super) fn remove(root: &Path, owner: &str) -> Result<(), HostError> {
    let path = path(root, owner);
    crate::host_files::owner_file(&path, 16_384)?;
    std::fs::remove_file(path).map_err(|_| HostError::StateInvalid)?;
    crate::management_v2_atomic::sync(root)
}

pub(super) fn filename(value: &str) -> bool {
    value
        .strip_prefix("management-v5-intent-")
        .and_then(|item| item.strip_suffix(".json"))
        .is_some_and(lower_hex)
}

fn validate(value: &CommitIntentV1, owner: &str) -> Result<(), HostError> {
    let valid = value.schema == SCHEMA
        && value.owner_sha256 == crate::host_crypto::digest(owner.as_bytes())
        && value.prior_revision > 0
        && value.revision == value.prior_revision.saturating_add(1)
        && digest(&value.prior_ledger_sha256)
        && digest(&value.ledger_sha256)
        && value.prior_ledger_sha256 != value.ledger_sha256;
    valid.then_some(()).ok_or(HostError::StateInvalid)
}

fn exact(left: &CommitIntentV1, right: &CommitIntentV1) -> bool {
    left.schema == right.schema
        && left.owner_sha256 == right.owner_sha256
        && left.prior_revision == right.prior_revision
        && left.prior_ledger_sha256 == right.prior_ledger_sha256
        && left.revision == right.revision
        && left.ledger_sha256 == right.ledger_sha256
}

fn ledger_digest(value: &ManagementLedgerV2) -> Result<String, HostError> {
    serde_json::to_vec(value)
        .map(|wire| crate::host_crypto::digest(&wire))
        .map_err(|_| HostError::StateInvalid)
}

fn path(root: &Path, owner: &str) -> PathBuf {
    root.join(format!(
        "management-v5-intent-{}.json",
        crate::host_crypto::digest(owner.as_bytes()).trim_start_matches("sha256:")
    ))
}

fn digest(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(lower_hex)
}
fn lower_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|item| item.is_ascii_digit() || matches!(item, b'a'..=b'f'))
}
