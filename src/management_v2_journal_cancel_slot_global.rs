#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct GlobalHead {
    schema: String,
    owner_sha256: String,
    revision: u64,
    ledger_sha256: String,
}

fn global_unacknowledged(root: &std::path::Path) -> Result<usize, HostError> {
    let heads = latest_heads(root)?;
    let mut count = 0_usize;
    for head in heads.values() {
        let ledger = head_ledger(root, head)?;
        count = count
            .checked_add(unacknowledged_records(&ledger))
            .and_then(|item| item.checked_add(unacknowledged_tombstones(&ledger)))
            .ok_or(HostError::StateInvalid)?;
        if count >= MAX_UNACKNOWLEDGED_GLOBAL {
            return Ok(count);
        }
    }
    Ok(count)
}

fn latest_heads(
    root: &std::path::Path,
) -> Result<std::collections::BTreeMap<String, GlobalHead>, HostError> {
    let mut result = std::collections::BTreeMap::<String, GlobalHead>::new();
    for entry in std::fs::read_dir(root).map_err(|_| HostError::StateInvalid)? {
        let entry = entry.map_err(|_| HostError::StateInvalid)?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| HostError::StateInvalid)?;
        if !crate::management_v2_head::filename(&name) {
            continue;
        }
        let wire = crate::host_files::owner_file(&entry.path(), 16_384)?;
        let head: GlobalHead =
            serde_json::from_slice(&wire).map_err(|_| HostError::StateInvalid)?;
        if !head_valid(&head, &name) {
            return Err(HostError::StateInvalid);
        }
        let replace = result
            .get(&head.owner_sha256)
            .is_none_or(|current| head.revision > current.revision);
        if replace {
            result.insert(head.owner_sha256.clone(), head);
        }
    }
    Ok(result)
}

fn head_valid(value: &GlobalHead, name: &str) -> bool {
    let owner = value.owner_sha256.strip_prefix("sha256:");
    let ledger = value.ledger_sha256.strip_prefix("sha256:");
    value.schema == "crowsi://credential-authority/management-commit-head/v1"
        && value.revision > 0
        && owner.is_some_and(lower_hex)
        && ledger.is_some_and(lower_hex)
        && name
            == format!(
                "management-v5-head-{}-{:020}-{}.json",
                owner.unwrap_or_default(),
                value.revision,
                ledger.unwrap_or_default()
            )
}

fn head_ledger(root: &std::path::Path, head: &GlobalHead) -> Result<ManagementLedgerV2, HostError> {
    let path = root.join(format!(
        "management-v5-ledger-{}-{}.json",
        &head.owner_sha256[7..],
        &head.ledger_sha256[7..]
    ));
    let wire = crate::host_files::owner_file(&path, 16_777_216)?;
    if crate::host_crypto::digest(&wire) != head.ledger_sha256 {
        return Err(HostError::StateInvalid);
    }
    let ledger: ManagementLedgerV2 =
        serde_json::from_slice(&wire).map_err(|_| HostError::StateInvalid)?;
    if ledger.revision != head.revision {
        return Err(HostError::StateInvalid);
    }
    let owner = ledger
        .records
        .first()
        .map(|item| item.owner_ref.as_str())
        .or_else(|| {
            ledger
                .tombstones
                .first()
                .map(|item| item.owner_ref.as_str())
        });
    if let Some(owner) = owner {
        if crate::host_crypto::digest(owner.as_bytes()) != head.owner_sha256 {
            return Err(HostError::StateInvalid);
        }
        crate::management_v2_journal_io::validate(&ledger, owner, ledger.revision)?;
    } else {
        crate::management_v2_journal_io::validate(&ledger, &head.owner_sha256, ledger.revision)?;
    }
    Ok(ledger)
}

fn lower_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|item| item.is_ascii_digit() || matches!(item, b'a'..=b'f'))
}
