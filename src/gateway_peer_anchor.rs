use serde::{Deserialize, Serialize};
use std::{fs, path::Path};

use crate::HostError;

pub(super) const SCHEMA: &str = "crowsi://credential-authority/gateway-peer-deny-anchor/v1";

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PeerAnchorV1 {
    pub(super) schema: String,
    pub(super) revision: u64,
    pub(super) ledger_sha256: String,
}

pub(super) fn read(root: &Path) -> Result<Option<PeerAnchorV1>, HostError> {
    let Some(value) = crate::gateway_peer_anchor_entries::entries(root)?.pop() else {
        return Ok(None);
    };
    Ok(Some(PeerAnchorV1 {
        schema: SCHEMA.into(),
        revision: value.revision,
        ledger_sha256: value.digest,
    }))
}

pub(super) fn retained(root: &Path) -> Result<Vec<String>, HostError> {
    Ok(crate::gateway_peer_anchor_entries::entries(root)?
        .into_iter()
        .map(|item| item.digest)
        .collect())
}

pub(super) fn write(
    root: &Path,
    revision: u64,
    ledger_sha256: &str,
) -> Result<Vec<String>, HostError> {
    if revision == 0
        || !digest(ledger_sha256)
        || read(root)?.is_some_and(|value| revision <= value.revision)
    {
        return Err(HostError::StateInvalid);
    }
    let value = PeerAnchorV1 {
        schema: SCHEMA.into(),
        revision,
        ledger_sha256: ledger_sha256.into(),
    };
    let wire = serde_json::to_vec(&value).map_err(|_| HostError::StateInvalid)?;
    crate::management_v2_atomic::immutable(root, &path(root, revision, ledger_sha256)?, &wire)?;
    let mut values = crate::gateway_peer_anchor_entries::entries(root)?;
    if values
        .last()
        .is_none_or(|item| item.revision != revision || item.digest != ledger_sha256)
    {
        return Err(HostError::StateInvalid);
    }
    while values.len() > 2 {
        let old = values.remove(0);
        crate::host_files::owner_file(&old.path, 16_384)?;
        fs::remove_file(old.path).map_err(|_| HostError::StateInvalid)?;
    }
    crate::management_v2_atomic::sync(root)?;
    Ok(values.into_iter().map(|item| item.digest).collect())
}

fn path(root: &Path, revision: u64, digest: &str) -> Result<std::path::PathBuf, HostError> {
    let hex = digest
        .strip_prefix("sha256:")
        .filter(|value| value.len() == 64)
        .ok_or(HostError::StateInvalid)?;
    Ok(root.join(format!(
        "{}{:020}-{hex}.json",
        crate::gateway_peer_anchor_entries::PREFIX,
        revision
    )))
}

pub(super) fn digest(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|item| item.is_ascii_digit() || matches!(item, b'a'..=b'f'))
}
