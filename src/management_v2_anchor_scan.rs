use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

use crate::{HostError, management_v2_anchor::ManagementAnchorV1};

pub(super) struct AnchorEntry {
    pub(super) value: ManagementAnchorV1,
    pub(super) path: PathBuf,
}

pub(super) fn entries(root: &Path, per_owner_limit: usize) -> Result<Vec<AnchorEntry>, HostError> {
    let mut values = Vec::new();
    for entry in std::fs::read_dir(root).map_err(|_| HostError::StateInvalid)? {
        let entry = entry.map_err(|_| HostError::StateInvalid)?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| HostError::StateInvalid)?;
        if name == crate::management_v2_marker::filename("anchor") {
            crate::host_files::owner_file(&entry.path(), 4096)?;
            continue;
        }
        let parsed = parse_name(&name)?;
        let wire = crate::host_files::owner_file(&entry.path(), 16_384)?;
        let value: ManagementAnchorV1 =
            serde_json::from_slice(&wire).map_err(|_| HostError::StateInvalid)?;
        if value.schema != crate::management_v2_anchor::SCHEMA
            || value.owner_sha256 != parsed.0
            || value.revision != parsed.1
            || value.ledger_sha256 != parsed.2
        {
            return Err(HostError::StateInvalid);
        }
        values.push(AnchorEntry {
            value,
            path: entry.path(),
        });
        if values.len() > 20_000 {
            return Err(HostError::StateInvalid);
        }
    }
    values.sort_by(|left, right| {
        (&left.value.owner_sha256, left.value.revision)
            .cmp(&(&right.value.owner_sha256, right.value.revision))
    });
    validate_sets(&values, per_owner_limit)?;
    Ok(values)
}

fn validate_sets(values: &[AnchorEntry], limit: usize) -> Result<(), HostError> {
    let mut owners = BTreeMap::<&str, Vec<&AnchorEntry>>::new();
    for value in values {
        owners
            .entry(&value.value.owner_sha256)
            .or_default()
            .push(value);
    }
    let valid = owners.values().all(|items| {
        items.len() <= limit
            && items.windows(2).all(|pair| {
                pair[1].value.revision == pair[0].value.revision.saturating_add(1)
                    && pair[1].value.ledger_sha256 != pair[0].value.ledger_sha256
            })
    });
    valid.then_some(()).ok_or(HostError::StateInvalid)
}

fn parse_name(value: &str) -> Result<(String, u64, String), HostError> {
    let body = value
        .strip_prefix("management-v5-anchor-")
        .and_then(|item| item.strip_suffix(".json"))
        .ok_or(HostError::StateInvalid)?;
    let parts = body.split('-').collect::<Vec<_>>();
    if parts.len() != 3 {
        return Err(HostError::StateInvalid);
    }
    let owner = format!("sha256:{}", parts[0]);
    let ledger = format!("sha256:{}", parts[2]);
    let revision = parts[1].parse().map_err(|_| HostError::StateInvalid)?;
    if !digest(&owner) || !digest(&ledger) || revision == 0 {
        return Err(HostError::StateInvalid);
    }
    Ok((owner, revision, ledger))
}

pub(super) fn path(root: &Path, value: &ManagementAnchorV1) -> Result<PathBuf, HostError> {
    if !digest(&value.owner_sha256) || !digest(&value.ledger_sha256) || value.revision == 0 {
        return Err(HostError::StateInvalid);
    }
    Ok(root.join(format!(
        "management-v5-anchor-{}-{:020}-{}.json",
        &value.owner_sha256[7..],
        value.revision,
        &value.ledger_sha256[7..]
    )))
}

pub(super) fn digest(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|item| item.is_ascii_digit() || matches!(item, b'a'..=b'f'))
}
