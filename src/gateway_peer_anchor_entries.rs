use std::{collections::BTreeSet, fs, path::PathBuf};

use crate::{HostError, gateway_peer_anchor::PeerAnchorV1};

pub(super) const PREFIX: &str = "gateway-peer-anchor-";

pub(super) struct AnchorEntry {
    pub(super) revision: u64,
    pub(super) digest: String,
    pub(super) path: PathBuf,
}

pub(super) fn entries(root: &std::path::Path) -> Result<Vec<AnchorEntry>, HostError> {
    let marker = crate::gateway_state_marker::filename("peer-anchor")?;
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
        values.push(parse(entry.path(), &name)?);
        if values.len() > 3 {
            return Err(HostError::StateInvalid);
        }
    }
    values.sort_by_key(|item| item.revision);
    let unique = values
        .iter()
        .map(|item| &item.digest)
        .collect::<BTreeSet<_>>();
    let consecutive = values
        .windows(2)
        .all(|items| items[1].revision == items[0].revision.saturating_add(1));
    if unique.len() != values.len() || !consecutive {
        return Err(HostError::StateInvalid);
    }
    Ok(values)
}

fn parse(path: PathBuf, name: &str) -> Result<AnchorEntry, HostError> {
    let value = name
        .strip_prefix(PREFIX)
        .and_then(|item| item.strip_suffix(".json"))
        .ok_or(HostError::StateInvalid)?;
    let (revision, hex) = value.split_once('-').ok_or(HostError::StateInvalid)?;
    let revision = revision
        .parse::<u64>()
        .map_err(|_| HostError::StateInvalid)?;
    let digest = format!("sha256:{hex}");
    let wire = crate::host_files::owner_file(&path, 16_384)?;
    let anchor: PeerAnchorV1 =
        serde_json::from_slice(&wire).map_err(|_| HostError::StateInvalid)?;
    let valid = revision > 0
        && crate::gateway_peer_anchor::digest(&digest)
        && anchor.schema == crate::gateway_peer_anchor::SCHEMA
        && anchor.revision == revision
        && anchor.ledger_sha256 == digest;
    valid
        .then_some(AnchorEntry {
            revision,
            digest,
            path,
        })
        .ok_or(HostError::StateInvalid)
}
