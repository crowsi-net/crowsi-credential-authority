use std::{collections::BTreeSet, path::Path};

use crate::host_config_types::{HostConfigDocument, HostRootTrust};

pub(crate) fn roles_distinct(value: &HostConfigDocument, root: &HostRootTrust) -> bool {
    let mut ids = BTreeSet::new();
    let mut keys = BTreeSet::new();
    let roles = [
        (
            &root.configuration_key_id,
            &root.configuration_public_key_hex,
        ),
        (&value.identity_key_id, &value.identity_public_key_hex),
        (
            &value.management_projection_key_id,
            &value.management_projection_public_key_hex,
        ),
        (
            &value.revocation_execution_reservation_key_id,
            &value.revocation_execution_reservation_public_key_hex,
        ),
        (
            &value.current_status_key_id,
            &value.current_status_public_key_hex,
        ),
        (
            &value.user_verification_key_id,
            &value.user_verification_public_key_hex,
        ),
        (
            &value.identity_response_key_id,
            &value.identity_response_public_key_hex,
        ),
        (&value.response_key_id, &value.response_public_key_hex),
    ];
    roles
        .into_iter()
        .all(|(id, key)| ids.insert(id) && keys.insert(key))
        && value.provider_operations.iter().all(|route| {
            ids.insert(&route.response_key_id) && keys.insert(&route.response_public_key_hex)
        })
        && value.device_proof_keys.iter().all(|device| {
            ids.insert(&device.device_proof_key_ref) && keys.insert(&device.public_key_hex)
        })
}

pub(crate) fn paths(value: &HostConfigDocument) -> bool {
    let fixed = [
        &value.authority_store_directory,
        &value.authority_anchor_directory,
        &value.operation_state_directory,
        &value.management_state_directory,
        &value.management_anchor_directory,
        &value.response_signing_key_path,
        &value.management_projection_signing_key_path,
        &value.revocation_execution_reservation_signing_key_path,
    ];
    let providers = value.provider_operations.iter().flat_map(|route| {
        [
            &route.executable,
            &route.config_path,
            &route.state_directory,
        ]
    });
    let paths = fixed.into_iter().chain(providers).collect::<Vec<_>>();
    paths.iter().all(|item| Path::new(item).is_absolute())
        && paths.iter().collect::<BTreeSet<_>>().len() == paths.len()
}
