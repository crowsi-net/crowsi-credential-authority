fn entries(root: &Path, limit: usize) -> Result<Vec<Entry>, HostError> {
    let mut values = Vec::new();
    for entry in fs::read_dir(root).map_err(|_| HostError::StateInvalid)? {
        let entry = entry.map_err(|_| HostError::StateInvalid)?;
        let Ok(parsed) = parse_name(&entry.file_name().to_string_lossy()) else {
            continue;
        };
        let wire = crate::host_files::owner_file(&entry.path(), 16_384)?;
        let value: CommitHeadV1 =
            serde_json::from_slice(&wire).map_err(|_| HostError::StateInvalid)?;
        if value.schema != SCHEMA
            || value.owner_sha256 != parsed.0
            || value.revision != parsed.1
            || value.ledger_sha256 != parsed.2
        {
            return Err(HostError::StateInvalid);
        }
        values.push(Entry {
            value,
            path: entry.path(),
        });
    }
    values.sort_by(|left, right| {
        (&left.value.owner_sha256, left.value.revision)
            .cmp(&(&right.value.owner_sha256, right.value.revision))
    });
    let mut owners = std::collections::BTreeMap::<&str, Vec<&Entry>>::new();
    for value in &values {
        owners
            .entry(&value.value.owner_sha256)
            .or_default()
            .push(value);
    }
    let valid = owners.values().all(|group| {
        group.len() <= limit
            && group.windows(2).all(|pair| {
                pair[1].value.revision == pair[0].value.revision.saturating_add(1)
                    && pair[1].value.ledger_sha256 != pair[0].value.ledger_sha256
            })
    });
    valid.then_some(values).ok_or(HostError::StateInvalid)
}

fn parse_name(value: &str) -> Result<(String, u64, String), HostError> {
    let body = value
        .strip_prefix("management-v5-head-")
        .and_then(|item| item.strip_suffix(".json"))
        .ok_or(HostError::StateInvalid)?;
    let parts = body.split('-').collect::<Vec<_>>();
    if parts.len() != 3 || !lower_hex(parts[0]) || !lower_hex(parts[2]) {
        return Err(HostError::StateInvalid);
    }
    let revision = parts[1].parse().map_err(|_| HostError::StateInvalid)?;
    Ok((
        format!("sha256:{}", parts[0]),
        revision,
        format!("sha256:{}", parts[2]),
    ))
}

fn path(root: &Path, value: &CommitHeadV1) -> Result<PathBuf, HostError> {
    if !digest(&value.owner_sha256) || !digest(&value.ledger_sha256) || value.revision == 0 {
        return Err(HostError::StateInvalid);
    }
    Ok(root.join(format!(
        "management-v5-head-{}-{:020}-{}.json",
        &value.owner_sha256[7..],
        value.revision,
        &value.ledger_sha256[7..]
    )))
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
