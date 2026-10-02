use std::path::{Path, PathBuf};

use crate::{HostError, management_v2_record::ManagementLedgerV2};

#[derive(Clone)]
pub(super) struct Generation {
    pub(super) revision: u64,
    pub(super) digest: String,
    pub(super) path: PathBuf,
    pub(super) ledger: ManagementLedgerV2,
}

pub(super) fn retained(
    root: &Path,
    owner: &str,
    limit: usize,
) -> Result<Vec<Generation>, HostError> {
    let prefix = format!(
        "management-v5-ledger-{}-",
        crate::host_crypto::digest(owner.as_bytes()).trim_start_matches("sha256:")
    );
    let mut values = Vec::new();
    for entry in std::fs::read_dir(root).map_err(|_| HostError::StateInvalid)? {
        let entry = entry.map_err(|_| HostError::StateInvalid)?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| HostError::StateInvalid)?;
        let Some(value) = name.strip_prefix(&prefix) else {
            continue;
        };
        let hex = value.strip_suffix(".json").ok_or(HostError::StateInvalid)?;
        let digest = format!("sha256:{hex}");
        let wire = crate::host_files::owner_file(&entry.path(), 16_777_216)?;
        if !digest_valid(&digest) || crate::host_crypto::digest(&wire) != digest {
            return Err(HostError::StateInvalid);
        }
        let ledger: ManagementLedgerV2 =
            serde_json::from_slice(&wire).map_err(|_| HostError::StateInvalid)?;
        crate::management_v2_journal_io::validate(&ledger, owner, ledger.revision)?;
        values.push(Generation {
            revision: ledger.revision,
            digest,
            path: entry.path(),
            ledger,
        });
        if values.len() > limit {
            return Err(HostError::StateInvalid);
        }
    }
    values.sort_by_key(|item| item.revision);
    let valid = values
        .windows(2)
        .all(|pair| pair[1].revision == pair[0].revision.saturating_add(1));
    valid.then_some(values).ok_or(HostError::StateInvalid)
}

pub(super) fn append(
    root: &Path,
    owner: &str,
    value: &ManagementLedgerV2,
    digest: &str,
) -> Result<(), HostError> {
    let wire = serde_json::to_vec(value).map_err(|_| HostError::StateInvalid)?;
    if crate::host_crypto::digest(&wire) != digest {
        return Err(HostError::StateInvalid);
    }
    crate::management_v2_atomic::immutable(root, &path(root, owner, digest)?, &wire)
}

pub(super) fn prune(root: &Path, owner: &str, retained: &[String]) -> Result<(), HostError> {
    for generation in self::retained(root, owner, 3)? {
        if !retained.contains(&generation.digest) {
            crate::host_files::owner_file(&generation.path, 16_777_216)?;
            std::fs::remove_file(generation.path).map_err(|_| HostError::StateInvalid)?;
        }
    }
    crate::management_v2_atomic::sync(root)?;
    (self::retained(root, owner, 2)?
        .iter()
        .map(|item| &item.digest)
        .collect::<Vec<_>>()
        == retained.iter().collect::<Vec<_>>())
    .then_some(())
    .ok_or(HostError::StateInvalid)
}

fn path(root: &Path, owner: &str, digest: &str) -> Result<PathBuf, HostError> {
    digest_valid(digest)
        .then(|| {
            root.join(format!(
                "management-v5-ledger-{}-{}.json",
                crate::host_crypto::digest(owner.as_bytes()).trim_start_matches("sha256:"),
                &digest[7..]
            ))
        })
        .ok_or(HostError::StateInvalid)
}

fn digest_valid(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|item| item.is_ascii_digit() || matches!(item, b'a'..=b'f'))
}
