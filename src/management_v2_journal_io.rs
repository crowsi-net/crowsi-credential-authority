use std::path::Path;

use crate::{
    HostError,
    management_v2_record::{self, ManagementLedgerV2},
};

pub(super) fn validate_layout(root: &Path) -> Result<(), HostError> {
    let mut count = 0_usize;
    for entry in std::fs::read_dir(root).map_err(|_| HostError::StateInvalid)? {
        let entry = entry.map_err(|_| HostError::StateInvalid)?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| HostError::StateInvalid)?;
        if name == crate::management_v2_marker::filename("state") {
            crate::host_files::owner_file(&entry.path(), 4096)?;
        } else if name == "management-v5-global.lock" || owner_lock_name(&name) {
            validate_lock_file(&entry.path())?;
        } else if crate::management_v2_head::filename(&name)
            || crate::management_v2_intent::filename(&name)
        {
            crate::host_files::owner_file(&entry.path(), 16_384)?;
        } else if ledger_name(&name) {
            let wire = crate::host_files::owner_file(&entry.path(), 16_777_216)?;
            let expected = format!(
                "sha256:{}",
                name.strip_suffix(".json")
                    .and_then(|value| value.rsplit('-').next())
                    .ok_or(HostError::StateInvalid)?
            );
            if crate::host_crypto::digest(&wire) != expected {
                return Err(HostError::StateInvalid);
            }
            let _: ManagementLedgerV2 =
                serde_json::from_slice(&wire).map_err(|_| HostError::StateInvalid)?;
        } else {
            return Err(HostError::StateInvalid);
        }
        count += 1;
        if count > 50_000 {
            return Err(HostError::StateInvalid);
        }
    }
    Ok(())
}

fn validate_lock_file(path: &Path) -> Result<(), HostError> {
    use std::os::unix::fs::MetadataExt;
    let value = std::fs::symlink_metadata(path).map_err(|_| HostError::StateInvalid)?;
    let valid = !value.file_type().is_symlink()
        && value.is_file()
        && value.nlink() == 1
        && value.uid() == nix::unistd::geteuid().as_raw()
        && value.mode() & 0o777 == 0o600;
    valid.then_some(()).ok_or(HostError::StateInvalid)
}

fn owner_lock_name(value: &str) -> bool {
    value
        .strip_prefix("management-v5-sha256:")
        .and_then(|item| item.strip_suffix(".lock"))
        .is_some_and(lower_hex)
}

fn ledger_name(value: &str) -> bool {
    let Some(body) = value
        .strip_prefix("management-v5-ledger-")
        .and_then(|item| item.strip_suffix(".json"))
    else {
        return false;
    };
    let mut parts = body.split('-');
    matches!((parts.next(), parts.next(), parts.next()), (Some(owner), Some(digest), None)
        if lower_hex(owner) && lower_hex(digest))
}

fn lower_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|item| item.is_ascii_digit() || matches!(item, b'a'..=b'f'))
}

include!("management_v2_journal_io_read_write.rs");

pub(super) fn validate(
    value: &ManagementLedgerV2,
    owner: &str,
    revision: u64,
) -> Result<(), HostError> {
    let valid = value.schema == management_v2_record::schema()
        && value.revision == revision
        && revision > 0
        && value.authority_config_generation_head > 0
        && value.records.len() <= 80
        && value.tombstones.len() <= 256
        && value.consumed_evidence.len() <= 1024
        && valid_consumed(&value.consumed_evidence)
        && value.transport_replays.len() <= 8192
        && valid_transport_replays(&value.transport_replays)
        && value.durable_responses.len() <= 512
        && crate::management_v2_receipt::valid_set(&value.durable_responses)
        && value.durable_responses.iter().all(|item| {
            item.accepted_ledger_revision <= value.revision
                && item.accepted_generation_head <= value.authority_config_generation_head
        })
        && value.records.iter().all(|item| {
            item.owner_ref == owner
                && item.authority_config_generation > 0
                && item.authority_config_generation <= value.authority_config_generation_head
                && provider_state_valid(item)
                && crate::management_v2_revocation_finalization_acceptance::record(item)
                && crate::management_v2_independent_finalization_acceptance::record(item)
        })
        && value.tombstones.iter().all(|item| {
            item.owner_ref == owner
                && item.authority_config_generation > 0
                && item.authority_config_generation <= value.authority_config_generation_head
                && crate::management_v2_revocation_finalization_acceptance::tombstone(item)
                && crate::management_v2_independent_finalization_acceptance::tombstone(item)
        })
        && crate::management_v2_journal_cancel_capacity::valid(value);
    valid.then_some(()).ok_or(HostError::StateInvalid)
}

include!("management_v2_journal_validation.rs");
