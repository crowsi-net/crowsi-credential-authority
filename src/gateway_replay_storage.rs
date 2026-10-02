fn read_ledger(root: &Path, anchor: &Path) -> Result<ReplayLedger, HostError> {
    let (revision, digest) =
        crate::gateway_replay_anchor::read(anchor)?.ok_or(HostError::StateInvalid)?;
    let anchors = crate::gateway_replay_anchor::retained(anchor)?;
    let generations = generations(root)?
        .into_iter()
        .map(|v| v.0)
        .collect::<BTreeSet<_>>();
    if anchors != generations {
        return Err(HostError::StateInvalid);
    }
    let wire = crate::host_files::owner_file(&generation(root, &digest)?, 16_777_216)?;
    let value = serde_json::from_slice(&wire).map_err(|_| HostError::StateInvalid)?;
    validate(&value, revision)?;
    Ok(value)
}

fn write_ledger(root: &Path, anchor: &Path, value: &ReplayLedger) -> Result<(), HostError> {
    validate(value, value.revision)?;
    let wire = serde_json::to_vec(value).map_err(|_| HostError::StateInvalid)?;
    let digest = crate::host_crypto::digest(&wire);
    crate::management_v2_atomic::immutable(root, &generation(root, &digest)?, &wire)?;
    let retained = crate::gateway_replay_anchor::write(anchor, value.revision, &digest)?;
    for (digest, path) in generations(root)? {
        if !retained.contains(&digest) {
            crate::host_files::owner_file(&path, 16_777_216)?;
            std::fs::remove_file(path).map_err(|_| HostError::StateInvalid)?;
        }
    }
    crate::management_v2_atomic::sync(root)
}

fn generations(root: &Path) -> Result<Vec<(String, PathBuf)>, HostError> {
    let marker = crate::gateway_state_marker::filename("replay-state")?;
    let mut values = Vec::new();
    for entry in std::fs::read_dir(root).map_err(|_| HostError::StateInvalid)? {
        let entry = entry.map_err(|_| HostError::StateInvalid)?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| HostError::StateInvalid)?;
        if name == "transport-replay.lock" || name == marker {
            continue;
        }
        let hex = name
            .strip_prefix("gateway-replay-ledger-")
            .and_then(|v| v.strip_suffix(".json"))
            .ok_or(HostError::StateInvalid)?;
        let digest = format!("sha256:{hex}");
        let wire = crate::host_files::owner_file(&entry.path(), 16_777_216)?;
        if !crate::gateway_replay_anchor::valid_digest(&digest)
            || crate::host_crypto::digest(&wire) != digest
        {
            return Err(HostError::StateInvalid);
        }
        values.push((digest, entry.path()));
        if values.len() > 3 {
            return Err(HostError::StateInvalid);
        }
    }
    Ok(values)
}

fn generation(root: &Path, digest: &str) -> Result<PathBuf, HostError> {
    crate::gateway_replay_anchor::valid_digest(digest)
        .then(|| root.join(format!("gateway-replay-ledger-{}.json", &digest[7..])))
        .ok_or(HostError::StateInvalid)
}

fn markers(root: &Path, anchor: &Path, deployment: &str, epoch: u64) -> Result<(), HostError> {
    crate::gateway_state_marker::verify(root, "replay-state", deployment, epoch)?;
    crate::gateway_state_marker::verify(anchor, "replay-anchor", deployment, epoch)
}
