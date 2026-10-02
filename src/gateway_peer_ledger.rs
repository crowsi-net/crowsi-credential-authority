use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
};

use crate::{HostError, gateway_peer_state::PeerDenyLedgerV1};

pub(super) fn read(root: &Path, anchor: &Path) -> Result<PeerDenyLedgerV1, HostError> {
    let value = crate::gateway_peer_anchor::read(anchor)?.ok_or(HostError::StateInvalid)?;
    let anchors = crate::gateway_peer_anchor::retained(anchor)?
        .into_iter()
        .collect::<BTreeSet<_>>();
    let generations = generations(root)?
        .into_iter()
        .map(|item| item.0)
        .collect::<BTreeSet<_>>();
    if anchors != generations {
        return Err(HostError::StateInvalid);
    }
    let wire = crate::host_files::owner_file(&generation(root, &value.ledger_sha256)?, 2_097_152)?;
    let ledger = serde_json::from_slice(&wire).map_err(|_| HostError::StateInvalid)?;
    crate::gateway_peer_state_io::validate(&ledger, value.revision)?;
    Ok(ledger)
}

pub(super) fn generations(root: &Path) -> Result<Vec<(String, PathBuf)>, HostError> {
    let marker = crate::gateway_state_marker::filename("peer-state")?;
    let mut values = Vec::new();
    for entry in std::fs::read_dir(root).map_err(|_| HostError::StateInvalid)? {
        let entry = entry.map_err(|_| HostError::StateInvalid)?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| HostError::StateInvalid)?;
        if name == "gateway-peer-status.lock" || name == marker {
            continue;
        }
        let value = name
            .strip_prefix("gateway-peer-deny-")
            .and_then(|item| item.strip_suffix(".json"))
            .ok_or(HostError::StateInvalid)?;
        let digest = format!("sha256:{value}");
        if !crate::gateway_peer_state_io::valid_digest(&digest) {
            return Err(HostError::StateInvalid);
        }
        let wire = crate::host_files::owner_file(&entry.path(), 2_097_152)?;
        if crate::host_crypto::digest(&wire) != digest {
            return Err(HostError::StateInvalid);
        }
        values.push((digest, entry.path()));
        if values.len() > 3 {
            return Err(HostError::StateInvalid);
        }
    }
    Ok(values)
}

pub(super) fn generation(root: &Path, digest: &str) -> Result<PathBuf, HostError> {
    crate::gateway_peer_state_io::valid_digest(digest)
        .then(|| root.join(format!("gateway-peer-deny-{}.json", &digest[7..])))
        .ok_or(HostError::StateInvalid)
}
