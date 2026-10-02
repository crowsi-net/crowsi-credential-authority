use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
};

use crate::HostError;

const SCHEMA: &str = "crowsi://credential-authority/gateway-replay-anchor/v1";
const PREFIX: &str = "gateway-replay-anchor-";

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ReplayAnchorV1 {
    schema: String,
    revision: u64,
    ledger_sha256: String,
}

pub(super) fn read(root: &Path) -> Result<Option<(u64, String)>, HostError> {
    Ok(entries(root)?.pop().map(|item| (item.0, item.1)))
}

pub(super) fn retained(root: &Path) -> Result<BTreeSet<String>, HostError> {
    Ok(entries(root)?.into_iter().map(|item| item.1).collect())
}

pub(super) fn write(
    root: &Path,
    revision: u64,
    digest: &str,
) -> Result<BTreeSet<String>, HostError> {
    if revision == 0
        || !valid_digest(digest)
        || read(root)?.is_some_and(|value| revision <= value.0)
    {
        return Err(HostError::StateInvalid);
    }
    let value = ReplayAnchorV1 {
        schema: SCHEMA.into(),
        revision,
        ledger_sha256: digest.into(),
    };
    let wire = serde_json::to_vec(&value).map_err(|_| HostError::StateInvalid)?;
    crate::management_v2_atomic::immutable(root, &path(root, revision, digest)?, &wire)?;
    let mut values = entries(root)?;
    let valid = values
        .last()
        .is_some_and(|item| item.0 == revision && item.1 == digest);
    if !valid {
        return Err(HostError::StateInvalid);
    }
    while values.len() > 2 {
        let old = values.remove(0);
        crate::host_files::owner_file(&old.2, 16_384)?;
        fs::remove_file(old.2).map_err(|_| HostError::StateInvalid)?;
    }
    crate::management_v2_atomic::sync(root)?;
    Ok(values.into_iter().map(|item| item.1).collect())
}

fn entries(root: &Path) -> Result<Vec<(u64, String, PathBuf)>, HostError> {
    let marker = crate::gateway_state_marker::filename("replay-anchor")?;
    let mut values = Vec::new();
    for entry in fs::read_dir(root).map_err(|_| HostError::StateInvalid)? {
        let entry = entry.map_err(|_| HostError::StateInvalid)?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| HostError::StateInvalid)?;
        if name == marker {
            continue;
        }
        let value = name
            .strip_prefix(PREFIX)
            .and_then(|item| item.strip_suffix(".json"))
            .ok_or(HostError::StateInvalid)?;
        let (revision, hex) = value.split_once('-').ok_or(HostError::StateInvalid)?;
        let revision = revision
            .parse::<u64>()
            .map_err(|_| HostError::StateInvalid)?;
        let digest = format!("sha256:{hex}");
        let wire = crate::host_files::owner_file(&entry.path(), 16_384)?;
        let anchor: ReplayAnchorV1 =
            serde_json::from_slice(&wire).map_err(|_| HostError::StateInvalid)?;
        if revision == 0
            || !valid_digest(&digest)
            || anchor.schema != SCHEMA
            || anchor.revision != revision
            || anchor.ledger_sha256 != digest
        {
            return Err(HostError::StateInvalid);
        }
        values.push((revision, digest, entry.path()));
        if values.len() > 3 {
            return Err(HostError::StateInvalid);
        }
    }
    values.sort_by_key(|item| item.0);
    let unique = values
        .iter()
        .map(|item| &item.1)
        .collect::<BTreeSet<_>>()
        .len()
        == values.len();
    let consecutive = values
        .windows(2)
        .all(|v| v[1].0 == v[0].0.saturating_add(1));
    (unique && consecutive)
        .then_some(values)
        .ok_or(HostError::StateInvalid)
}

fn path(root: &Path, revision: u64, digest: &str) -> Result<PathBuf, HostError> {
    valid_digest(digest)
        .then(|| root.join(format!("{PREFIX}{revision:020}-{}.json", &digest[7..])))
        .ok_or(HostError::StateInvalid)
}

pub(super) fn valid_digest(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|v| v.is_ascii_digit() || matches!(v, b'a'..=b'f'))
}
