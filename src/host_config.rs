use ed25519_dalek::SigningKey;
use std::path::Path;

use crate::{
    HostError,
    host_config_types::{HostConfigDocument, HostRootTrust, HostSigningKeyDocument},
    host_crypto, host_files,
};

pub(crate) struct VerifiedHostConfig {
    pub document: HostConfigDocument,
    pub response_signing_key: SigningKey,
    pub management_projection_signing_key: SigningKey,
    pub revocation_execution_reservation_signing_key: SigningKey,
}

pub(crate) fn load_pinned(
    path: &Path,
    digest: &str,
    now: u64,
) -> Result<VerifiedHostConfig, HostError> {
    let config = load_document(path, Some(digest), now)?;
    load_private(config)
}

pub(crate) fn load_document(
    path: &Path,
    digest: Option<&str>,
    now: u64,
) -> Result<HostConfigDocument, HostError> {
    let config_wire = if let Some(value) = digest {
        host_files::pinned_owner_file(path, 262_144, value)?
    } else {
        host_files::owner_file(path, 262_144)?
    };
    let root_wire = host_files::root_trust(path)?;
    let config: HostConfigDocument =
        serde_json::from_slice(&config_wire).map_err(|_| HostError::ConfigInvalid)?;
    let root: HostRootTrust =
        serde_json::from_slice(&root_wire).map_err(|_| HostError::ConfigInvalid)?;
    crate::host_config_validation::validate(&config, &root, now)?;
    let value = serde_json::to_value(&config).map_err(|_| HostError::ConfigInvalid)?;
    let payload = host_crypto::canonical("CROWSI-CREDENTIAL-AUTHORITY-HOST-CONFIG-V4", &value)?;
    if !host_crypto::verify(
        &root.configuration_public_key_hex,
        &config.signature,
        &payload,
    ) {
        return Err(HostError::ConfigInvalid);
    }
    Ok(config)
}

fn load_private(config: HostConfigDocument) -> Result<VerifiedHostConfig, HostError> {
    let key_wire = host_files::owner_file(Path::new(&config.response_signing_key_path), 16_384)?;
    let key: HostSigningKeyDocument =
        serde_json::from_slice(&key_wire).map_err(|_| HostError::ConfigInvalid)?;
    let signing = host_crypto::signing_key(&key.private_key_hex)?;
    if key.schema != "crowsi://credential-authority/host-response-key/v1"
        || key.key_id != config.response_key_id
        || hex::encode(signing.verifying_key().to_bytes()) != config.response_public_key_hex
    {
        return Err(HostError::ConfigInvalid);
    }
    let projection_key_wire = host_files::owner_file(
        Path::new(&config.management_projection_signing_key_path),
        16_384,
    )?;
    let projection_key: HostSigningKeyDocument =
        serde_json::from_slice(&projection_key_wire).map_err(|_| HostError::ConfigInvalid)?;
    let projection_signing = host_crypto::signing_key(&projection_key.private_key_hex)?;
    if projection_key.schema != "crowsi://credential-authority/management-projection-key/v2"
        || projection_key.key_id != config.management_projection_key_id
        || hex::encode(projection_signing.verifying_key().to_bytes())
            != config.management_projection_public_key_hex
    {
        return Err(HostError::ConfigInvalid);
    }
    let reservation_wire = host_files::owner_file(
        Path::new(&config.revocation_execution_reservation_signing_key_path),
        16_384,
    )?;
    let reservation_key: HostSigningKeyDocument =
        serde_json::from_slice(&reservation_wire).map_err(|_| HostError::ConfigInvalid)?;
    let reservation_signing = host_crypto::signing_key(&reservation_key.private_key_hex)?;
    if reservation_key.schema
        != "crowsi://credential-authority/revocation-execution-reservation-key/v1"
        || reservation_key.key_id != config.revocation_execution_reservation_key_id
        || hex::encode(reservation_signing.verifying_key().to_bytes())
            != config.revocation_execution_reservation_public_key_hex
    {
        return Err(HostError::ConfigInvalid);
    }
    host_files::owner_directory(Path::new(&config.authority_store_directory))?;
    host_files::owner_directory(Path::new(&config.authority_anchor_directory))?;
    host_files::owner_directory(Path::new(&config.operation_state_directory))?;
    host_files::owner_directory(Path::new(&config.management_state_directory))?;
    host_files::owner_directory(Path::new(&config.management_anchor_directory))?;
    for route in &config.provider_operations {
        host_files::provider_state_directory(Path::new(&route.state_directory))?;
    }
    Ok(VerifiedHostConfig {
        document: config,
        response_signing_key: signing,
        management_projection_signing_key: projection_signing,
        revocation_execution_reservation_signing_key: reservation_signing,
    })
}
