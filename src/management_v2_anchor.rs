use serde::{Deserialize, Serialize};
use std::{fs, path::Path};

use crate::HostError;

pub(super) const SCHEMA: &str = "crowsi://credential-authority/management-anchor/v2";

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ManagementAnchorV1 {
    pub schema: String,
    pub owner_sha256: String,
    pub revision: u64,
    pub ledger_sha256: String,
}

pub(crate) fn read(root: &Path, owner: &str) -> Result<Option<ManagementAnchorV1>, HostError> {
    let owner_digest = crate::host_crypto::digest(owner.as_bytes());
    Ok(crate::management_v2_anchor_scan::entries(root, 2)?
        .into_iter()
        .rfind(|item| item.value.owner_sha256 == owner_digest)
        .map(|item| item.value))
}

pub(crate) fn append(
    root: &Path,
    owner: &str,
    revision: u64,
    ledger_sha256: &str,
) -> Result<Vec<String>, HostError> {
    if revision == 0
        || !crate::management_v2_anchor_scan::digest(ledger_sha256)
        || read(root, owner)?.is_some_and(|value| revision != value.revision.saturating_add(1))
    {
        return Err(HostError::StateInvalid);
    }
    let value = ManagementAnchorV1 {
        schema: SCHEMA.into(),
        owner_sha256: crate::host_crypto::digest(owner.as_bytes()),
        revision,
        ledger_sha256: ledger_sha256.into(),
    };
    let wire = serde_json::to_vec(&value).map_err(|_| HostError::StateInvalid)?;
    crate::management_v2_atomic::immutable(
        root,
        &crate::management_v2_anchor_scan::path(root, &value)?,
        &wire,
    )?;
    let retained = owner_entries(root, &value.owner_sha256, 3)?;
    if retained.last() != Some(&(revision, ledger_sha256.into())) {
        return Err(HostError::StateInvalid);
    }
    Ok(retained.into_iter().map(|item| item.1).collect())
}

pub(crate) fn prune(root: &Path, owner: &str, retained: &[String]) -> Result<(), HostError> {
    let owner_digest = crate::host_crypto::digest(owner.as_bytes());
    for item in crate::management_v2_anchor_scan::entries(root, 3)?
        .into_iter()
        .filter(|item| item.value.owner_sha256 == owner_digest)
    {
        if !retained.contains(&item.value.ledger_sha256) {
            crate::host_files::owner_file(&item.path, 16_384)?;
            fs::remove_file(item.path).map_err(|_| HostError::StateInvalid)?;
        }
    }
    crate::management_v2_atomic::sync(root)?;
    let values = retained_owner(root, owner, 2)?;
    (values.iter().map(|item| &item.1).collect::<Vec<_>>() == retained.iter().collect::<Vec<_>>())
        .then_some(())
        .ok_or(HostError::StateInvalid)
}

pub(crate) fn retained_owner(
    root: &Path,
    owner: &str,
    limit: usize,
) -> Result<Vec<(u64, String)>, HostError> {
    owner_entries(root, &crate::host_crypto::digest(owner.as_bytes()), limit)
}

fn owner_entries(
    root: &Path,
    owner_digest: &str,
    limit: usize,
) -> Result<Vec<(u64, String)>, HostError> {
    Ok(crate::management_v2_anchor_scan::entries(root, limit)?
        .into_iter()
        .filter(|item| item.value.owner_sha256 == owner_digest)
        .map(|item| (item.value.revision, item.value.ledger_sha256))
        .collect())
}
