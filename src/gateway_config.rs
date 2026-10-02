use crowsi_authority_transport::{PeerBinding, ServerCredential};
use std::path::Path;
use zeroize::Zeroizing;

use crate::{
    HostError,
    gateway_config_validation::{decode, validate},
    gateway_contract::{GatewayConfigDocument, GatewaySigningKeyDocument},
    host_config_types::HostRootTrust,
    host_crypto, host_files,
};

pub(crate) struct VerifiedGatewayConfig {
    pub document: GatewayConfigDocument,
    pub source_digest: String,
    pub credential: ServerCredential,
    pub peers: Vec<(PeerBinding, Vec<u8>)>,
}

pub(crate) fn load(path: &Path, now: u64) -> Result<VerifiedGatewayConfig, HostError> {
    let wire = host_files::owner_file(path, 524_288)?;
    let source_digest = host_crypto::digest(&wire);
    let document = verify_document(path, &wire, now)?;
    load_private(document, source_digest)
}

pub(crate) fn load_document(
    path: &Path,
    digest: &str,
    now: u64,
) -> Result<GatewayConfigDocument, HostError> {
    let wire = host_files::pinned_owner_file(path, 524_288, digest)?;
    verify_document(path, &wire, now)
}

fn verify_document(path: &Path, wire: &[u8], now: u64) -> Result<GatewayConfigDocument, HostError> {
    let root_wire = host_files::root_trust(path)?;
    let document: GatewayConfigDocument =
        serde_json::from_slice(wire).map_err(|_| HostError::ConfigInvalid)?;
    let root: HostRootTrust =
        serde_json::from_slice(&root_wire).map_err(|_| HostError::ConfigInvalid)?;
    validate(&document, &root, now)?;
    let value = serde_json::to_value(&document).map_err(|_| HostError::ConfigInvalid)?;
    let payload = host_crypto::canonical("CROWSI-AUTHORITY-GATEWAY-CONFIG-V2", &value)?;
    if !host_crypto::verify(
        &root.configuration_public_key_hex,
        &document.signature,
        &payload,
    ) {
        return Err(HostError::ConfigInvalid);
    }
    Ok(document)
}

fn load_private(
    document: GatewayConfigDocument,
    source_digest: String,
) -> Result<VerifiedGatewayConfig, HostError> {
    let key_wire = host_files::owner_file(Path::new(&document.response_signing_key_path), 16_384)?;
    let key: GatewaySigningKeyDocument =
        serde_json::from_slice(&key_wire).map_err(|_| HostError::ConfigInvalid)?;
    let signing = host_crypto::signing_key(&key.private_key_hex)?;
    if key.schema != "crowsi://credential-authority/gateway-response-key/v1"
        || key.key_id != document.response_key_id
        || hex::encode(signing.verifying_key().to_bytes()) != document.response_public_key_hex
    {
        return Err(HostError::ConfigInvalid);
    }
    let private_key = Zeroizing::new(host_files::owner_file(
        Path::new(&document.server_private_key_path),
        65_536,
    )?);
    let credential = ServerCredential {
        certificate_der: decode(&document.server_certificate_der_hex, 262_144)?,
        private_key_der: private_key,
        client_trust_anchors_der: vec![decode(&document.client_trust_anchor_der_hex, 262_144)?],
        response_key_id: document.response_key_id.clone(),
        response_signing_key: signing,
    };
    let peers = document
        .peers
        .iter()
        .map(|item| {
            Ok((
                PeerBinding {
                    device_id: item.device_id.clone(),
                    certificate_sha256: item.certificate_sha256.clone(),
                    request_key_id: item.request_key_id.clone(),
                    request_public_key_hex: item.request_public_key_hex.clone(),
                },
                decode(&item.certificate_der_hex, 262_144)?,
            ))
        })
        .collect::<Result<_, HostError>>()?;
    host_files::owner_directory(Path::new(&document.replay_state_directory))?;
    host_files::owner_directory(Path::new(&document.replay_anchor_directory))?;
    host_files::owner_directory(Path::new(&document.peer_status_state_directory))?;
    host_files::owner_directory(Path::new(&document.peer_status_anchor_directory))?;
    Ok(VerifiedGatewayConfig {
        document,
        source_digest,
        credential,
        peers,
    })
}
