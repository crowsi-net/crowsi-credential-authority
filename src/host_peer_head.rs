use crate::{
    FileAuthorityStore, HostError,
    gateway_contract::GatewayConfigDocument,
    gateway_peer_head_types::{
        PeerStatusHeadEntryV1, PeerStatusHeadRequestV1, PeerStatusHeadV1, REQUEST_SCHEMA,
        RESPONSE_DOMAIN, RESPONSE_SCHEMA,
    },
    host_config::VerifiedHostConfig,
    host_crypto,
};

pub(super) fn handle(
    config: &VerifiedHostConfig,
    gateway: &GatewayConfigDocument,
    gateway_digest: &str,
    wire: &[u8],
    now: u64,
) -> Result<Vec<u8>, HostError> {
    if wire.is_empty() || wire.len() > 16_384 {
        return Err(HostError::RequestInvalid);
    }
    let request: PeerStatusHeadRequestV1 =
        serde_json::from_slice(wire).map_err(|_| HostError::RequestInvalid)?;
    if request.schema != REQUEST_SCHEMA
        || !request.request_id.starts_with("peerhead_")
        || request.request_id.len() != 73
        || request.deployment_id != gateway.deployment_id
        || request.gateway_config_sha256 != gateway_digest
        || request.authority_epoch != gateway.authority_epoch
    {
        return Err(HostError::RequestInvalid);
    }
    let store = FileAuthorityStore::open_anchored(
        &config.document.authority_store_directory,
        &config.document.authority_anchor_directory,
    )?;
    let snapshot = store.export_snapshot()?;
    let entries = gateway
        .peers
        .iter()
        .map(|peer| entry(config, &snapshot, peer))
        .collect::<Result<Vec<_>, HostError>>()?;
    let head_digest = crate::gateway_peer_head::head_digest(snapshot.version, &entries)?;
    let mut response = PeerStatusHeadV1 {
        schema: RESPONSE_SCHEMA.into(),
        request_id: request.request_id,
        request_digest_sha256: host_crypto::digest(wire),
        deployment_id: gateway.deployment_id.clone(),
        gateway_config_sha256: gateway_digest.into(),
        authority_epoch: gateway.authority_epoch,
        authority_revision: snapshot.version,
        entries,
        head_digest_sha256: head_digest,
        issued_at_epoch_s: now,
        expires_at_epoch_s: now.saturating_add(10),
        key_id: config.document.response_key_id.clone(),
        signature: String::new(),
    };
    let value = serde_json::to_value(&response).map_err(|_| HostError::ResponseInvalid)?;
    let canonical = host_crypto::canonical(RESPONSE_DOMAIN, &value)?;
    response.signature = host_crypto::sign(&config.response_signing_key, &canonical);
    serde_json::to_vec(&response).map_err(|_| HostError::ResponseInvalid)
}

fn entry(
    config: &VerifiedHostConfig,
    snapshot: &crate::DurableSnapshot,
    peer: &crate::gateway_contract::GatewayPeerDocument,
) -> Result<PeerStatusHeadEntryV1, HostError> {
    let key = config
        .document
        .device_proof_keys
        .iter()
        .find(|item| item.device_id == peer.device_id)
        .ok_or(HostError::ConfigInvalid)?;
    let record = snapshot
        .devices
        .iter()
        .find_map(|((owner, device), record)| {
            (owner.as_str() == key.opaque_owner_ref && device.as_str() == peer.device_id)
                .then_some(record)
        });
    Ok(PeerStatusHeadEntryV1 {
        device_id: peer.device_id.clone(),
        certificate_sha256: peer.certificate_sha256.clone(),
        request_key_id: peer.request_key_id.clone(),
        registered: record.is_some(),
        revoked: record.is_some_and(|value| value.revoked),
        device_revocation_epoch: record.map_or(0, |value| value.epoch),
    })
}
