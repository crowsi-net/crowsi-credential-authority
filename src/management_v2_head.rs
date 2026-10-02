use serde::{Deserialize, Serialize};
use std::{
    fs,
    path::{Path, PathBuf},
};

use crate::HostError;

const SCHEMA: &str = "crowsi://credential-authority/management-commit-head/v1";

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CommitHeadV1 {
    schema: String,
    owner_sha256: String,
    revision: u64,
    ledger_sha256: String,
}

struct Entry {
    value: CommitHeadV1,
    path: PathBuf,
}

pub(super) fn retained(
    root: &Path,
    owner: &str,
    limit: usize,
) -> Result<Vec<(u64, String)>, HostError> {
    let digest = crate::host_crypto::digest(owner.as_bytes());
    Ok(entries(root, limit)?
        .into_iter()
        .filter(|item| item.value.owner_sha256 == digest)
        .map(|item| (item.value.revision, item.value.ledger_sha256))
        .collect())
}

pub(super) fn append(
    root: &Path,
    owner: &str,
    revision: u64,
    ledger_sha256: &str,
) -> Result<(), HostError> {
    let prior = retained(root, owner, 2)?;
    if revision == 0
        || !digest(ledger_sha256)
        || prior
            .last()
            .is_some_and(|item| revision != item.0.saturating_add(1))
    {
        return Err(HostError::StateInvalid);
    }
    let value = CommitHeadV1 {
        schema: SCHEMA.into(),
        owner_sha256: crate::host_crypto::digest(owner.as_bytes()),
        revision,
        ledger_sha256: ledger_sha256.into(),
    };
    let wire = serde_json::to_vec(&value).map_err(|_| HostError::StateInvalid)?;
    crate::management_v2_atomic::immutable(root, &path(root, &value)?, &wire)?;
    let current = retained(root, owner, 3)?;
    (current.last() == Some(&(revision, ledger_sha256.into())))
        .then_some(())
        .ok_or(HostError::StateInvalid)
}

pub(super) fn prune(root: &Path, owner: &str, expected: &[String]) -> Result<(), HostError> {
    let owner_digest = crate::host_crypto::digest(owner.as_bytes());
    for item in entries(root, 3)?
        .into_iter()
        .filter(|item| item.value.owner_sha256 == owner_digest)
    {
        if !expected.contains(&item.value.ledger_sha256) {
            crate::host_files::owner_file(&item.path, 16_384)?;
            fs::remove_file(item.path).map_err(|_| HostError::StateInvalid)?;
        }
    }
    crate::management_v2_atomic::sync(root)?;
    (retained(root, owner, 2)?
        .iter()
        .map(|item| &item.1)
        .collect::<Vec<_>>()
        == expected.iter().collect::<Vec<_>>())
    .then_some(())
    .ok_or(HostError::StateInvalid)
}

pub(super) fn filename(value: &str) -> bool {
    parse_name(value).is_ok()
}

include!("management_v2_head_scan.rs");
