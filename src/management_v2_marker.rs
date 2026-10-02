use serde::{Deserialize, Serialize};
use std::path::Path;

use crate::HostError;

const SCHEMA: &str = "crowsi://credential-authority/management-state-marker/v2";

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct MarkerV1 {
    schema: String,
    role: String,
    authority_epoch: u64,
    reservation_key_id: String,
    reservation_public_key_hex: String,
    reservation_config_generation: u64,
}

pub(super) fn initialize(
    root: &Path,
    role: &str,
    epoch: u64,
    reservation: &crate::management_v2_journal::ReservationRootBinding,
) -> Result<(), HostError> {
    if !valid(role, epoch, reservation) {
        return Err(HostError::ConfigInvalid);
    }
    let path = path(root, role);
    if crate::management_v2_atomic::present(&path)? {
        return verify(root, role, epoch, reservation);
    }
    let value = MarkerV1 {
        schema: SCHEMA.into(),
        role: role.into(),
        authority_epoch: epoch,
        reservation_key_id: reservation.key_id.clone(),
        reservation_public_key_hex: reservation.public_key_hex.clone(),
        reservation_config_generation: reservation.config_generation,
    };
    let wire = serde_json::to_vec(&value).map_err(|_| HostError::StateInvalid)?;
    crate::management_v2_atomic::immutable(root, &path, &wire)?;
    verify(root, role, epoch, reservation)
}

pub(super) fn present(root: &Path, role: &str) -> Result<bool, HostError> {
    crate::management_v2_atomic::present(&path(root, role))
}

pub(super) fn verify(
    root: &Path,
    role: &str,
    epoch: u64,
    reservation: &crate::management_v2_journal::ReservationRootBinding,
) -> Result<(), HostError> {
    let wire = crate::host_files::owner_file(&path(root, role), 4096)?;
    let value: MarkerV1 = serde_json::from_slice(&wire).map_err(|_| HostError::StateInvalid)?;
    (value.schema == SCHEMA
        && value.role == role
        && value.authority_epoch == epoch
        && value.reservation_key_id == reservation.key_id
        && value.reservation_public_key_hex == reservation.public_key_hex
        && value.reservation_config_generation == reservation.config_generation
        && valid(role, epoch, reservation))
    .then_some(())
    .ok_or(HostError::StateInvalid)
}

fn valid(
    role: &str,
    epoch: u64,
    reservation: &crate::management_v2_journal::ReservationRootBinding,
) -> bool {
    epoch > 0
        && matches!(role, "state" | "anchor")
        && !reservation.key_id.is_empty()
        && reservation.key_id.len() <= 128
        && reservation.public_key_hex.len() == 64
        && reservation
            .public_key_hex
            .bytes()
            .all(|item| item.is_ascii_digit() || matches!(item, b'a'..=b'f'))
        && reservation.config_generation > 0
}

pub(super) fn filename(role: &str) -> String {
    format!("management-v5-{role}-initialized.json")
}

fn path(root: &Path, role: &str) -> std::path::PathBuf {
    root.join(filename(role))
}
