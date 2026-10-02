use std::{collections::BTreeSet, path::Path};

use crate::host_config_validation::{digest, id, key, opaque};
use crate::{host_config_types::HostConfigDocument, host_files};

pub(crate) fn mappings(value: &HostConfigDocument) -> bool {
    let mut tuples = BTreeSet::new();
    let mut owners = BTreeSet::new();
    let owner_valid = !value.owner_mappings.is_empty()
        && value.owner_mappings.len() <= 1_000
        && value.owner_mappings.iter().all(|item| {
            item.issuer == value.identity_issuer
                && id(&item.service_id, 128)
                && item.pairwise_subject.starts_with("psu_")
                && id(&item.pairwise_subject, 128)
                && opaque(&item.opaque_owner_ref)
                && key(&item.account_binding_sha256)
                && tuples.insert((&item.issuer, &item.service_id, &item.pairwise_subject))
                && owners.insert(&item.opaque_owner_ref)
        });
    let mut devices = BTreeSet::new();
    owner_valid
        && value.device_proof_keys.len() <= 10_000
        && value.device_proof_keys.iter().all(|item| {
            value
                .owner_mappings
                .iter()
                .any(|owner| owner.opaque_owner_ref == item.opaque_owner_ref)
                && id(&item.device_id, 128)
                && id(&item.device_proof_key_ref, 240)
                && key(&item.public_key_hex)
                && matches!(
                    item.custody.as_str(),
                    "hardware-nonexportable" | "software-nonexportable"
                )
                && id(&item.custody_revision, 128)
                && devices.insert((&item.opaque_owner_ref, &item.device_id))
        })
}

pub(crate) fn providers(value: &HostConfigDocument) -> bool {
    let mut services = BTreeSet::new();
    !value.provider_operations.is_empty()
        && value.provider_operations.len() <= 64
        && value.provider_operations.iter().all(|route| {
            id(&route.service_id, 128)
                && services.insert(&route.service_id)
                && Path::new(&route.executable).is_absolute()
                && Path::new(&route.config_path).is_absolute()
                && Path::new(&route.state_directory).is_absolute()
                && digest(&route.executable_sha256)
                && digest(&route.config_sha256)
                && id(&route.response_key_id, 128)
                && key(&route.response_public_key_hex)
                && host_files::trusted_executable(
                    Path::new(&route.executable),
                    &route.executable_sha256,
                )
                .is_ok()
                && host_files::pinned_owner_file(
                    Path::new(&route.config_path),
                    262_144,
                    &route.config_sha256,
                )
                .is_ok()
                && host_files::provider_state_directory(Path::new(&route.state_directory)).is_ok()
        })
}
