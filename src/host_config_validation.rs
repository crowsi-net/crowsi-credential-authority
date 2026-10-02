use std::collections::BTreeSet;

use crate::{
    HostError,
    host_config_types::{HostConfigDocument, HostRootTrust},
};

pub(crate) fn validate(
    value: &HostConfigDocument,
    root: &HostRootTrust,
    now: u64,
) -> Result<(), HostError> {
    let valid = value.schema == "crowsi://credential-authority/host-config/v4"
        && root.schema == "crowsi://credential-authority/host-root-trust/v1"
        && value.deployment_role == "single-central-authority-host"
        && value.configuration_key_id == root.configuration_key_id
        && value.authority_epoch > 0
        && value.issued_at_epoch_s > 0
        && value.issued_at_epoch_s <= now
        && now < value.expires_at_epoch_s
        && value
            .expires_at_epoch_s
            .saturating_sub(value.issued_at_epoch_s)
            <= 31_536_000
        && id(&value.identity_issuer, 512)
        && id(&value.registration_audience, 128)
        && id(&value.management_audience, 128)
        && id(&value.management_projection_issuer, 256)
        && id(&value.management_projection_key_id, 128)
        && id(&value.revocation_execution_reservation_key_id, 128)
        && value.revocation_execution_reservation_config_generation > 0
        && id(&value.identity_key_id, 128)
        && id(&value.current_status_key_id, 128)
        && id(&value.user_verification_key_id, 128)
        && id(&value.identity_response_key_id, 128)
        && value.minimum_identity_config_generation > 0
        && id(&value.identity_finalization_authority_id, 128)
        && !value.revocation_approval_authority_refs.is_empty()
        && value.revocation_approval_authority_refs.len() <= 16
        && value
            .revocation_approval_authority_refs
            .iter()
            .all(|item| id(item, 128))
        && value
            .revocation_approval_authority_refs
            .iter()
            .collect::<BTreeSet<_>>()
            .len()
            == value.revocation_approval_authority_refs.len()
        && id(&value.response_key_id, 128)
        && id(&value.configuration_key_id, 128)
        && value.identity_key_id != value.current_status_key_id
        && value.identity_public_key_hex != value.current_status_public_key_hex
        && key(&value.identity_public_key_hex)
        && key(&value.management_projection_public_key_hex)
        && key(&value.revocation_execution_reservation_public_key_hex)
        && key(&value.current_status_public_key_hex)
        && key(&value.user_verification_public_key_hex)
        && key(&value.identity_response_public_key_hex)
        && key(&value.response_public_key_hex)
        && key(&root.configuration_public_key_hex)
        && crate::host_config_roles::paths(value)
        && crate::host_config_mappings::mappings(value)
        && crate::host_config_roles::roles_distinct(value, root)
        && crate::host_config_mappings::providers(value);
    if valid {
        Ok(())
    } else {
        Err(HostError::ConfigInvalid)
    }
}

pub(crate) fn id(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value.trim() == value
        && !value.chars().any(char::is_control)
}
pub(crate) fn key(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}
pub(crate) fn digest(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}
pub(crate) fn opaque(value: &str) -> bool {
    value.starts_with("psa_")
        && (24..=128).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_-".contains(&byte))
}
