use crate::{
    HostError,
    gateway_contract::GatewayConfigDocument,
    gateway_peer_head_types::{
        PeerStatusHeadEntryV1, PeerStatusHeadRequestV1, PeerStatusHeadV1, REQUEST_SCHEMA,
        RESPONSE_DOMAIN, RESPONSE_SCHEMA,
    },
    host_config_types::HostConfigDocument,
    host_crypto,
};

pub(super) fn request(
    config: &GatewayConfigDocument,
    config_digest: &str,
) -> Result<(PeerStatusHeadRequestV1, Vec<u8>), HostError> {
    let mut random = [0_u8; 32];
    getrandom::fill(&mut random).map_err(|_| HostError::Unavailable)?;
    let request = PeerStatusHeadRequestV1 {
        schema: REQUEST_SCHEMA.into(),
        request_id: format!("peerhead_{}", hex::encode(random)),
        deployment_id: config.deployment_id.clone(),
        gateway_config_sha256: config_digest.into(),
        authority_epoch: config.authority_epoch,
    };
    let wire = serde_json::to_vec(&request).map_err(|_| HostError::RequestInvalid)?;
    Ok((request, wire))
}

pub(super) fn verify(
    wire: &[u8],
    request: &PeerStatusHeadRequestV1,
    request_wire: &[u8],
    gateway: &GatewayConfigDocument,
    host: &HostConfigDocument,
    now: u64,
) -> Result<PeerStatusHeadV1, HostError> {
    if wire.is_empty() || wire.len() > 1_048_576 {
        return Err(HostError::ResponseInvalid);
    }
    let value: PeerStatusHeadV1 =
        serde_json::from_slice(wire).map_err(|_| HostError::ResponseInvalid)?;
    let valid = value.schema == RESPONSE_SCHEMA
        && value.request_id == request.request_id
        && value.request_digest_sha256 == host_crypto::digest(request_wire)
        && value.deployment_id == gateway.deployment_id
        && value.gateway_config_sha256 == request.gateway_config_sha256
        && value.authority_epoch == gateway.authority_epoch
        && value.issued_at_epoch_s <= now
        && now < value.expires_at_epoch_s
        && value
            .expires_at_epoch_s
            .saturating_sub(value.issued_at_epoch_s)
            <= 10
        && value.key_id == host.response_key_id
        && entries(&value.entries, gateway)
        && value.head_digest_sha256 == head_digest(value.authority_revision, &value.entries)?;
    if !valid {
        return Err(HostError::ResponseInvalid);
    }
    let json = serde_json::to_value(&value).map_err(|_| HostError::ResponseInvalid)?;
    let canonical = host_crypto::canonical(RESPONSE_DOMAIN, &json)?;
    host_crypto::verify(&host.response_public_key_hex, &value.signature, &canonical)
        .then_some(value)
        .ok_or(HostError::ResponseInvalid)
}

pub(super) fn head_digest(
    revision: u64,
    entries: &[PeerStatusHeadEntryV1],
) -> Result<String, HostError> {
    let wire = serde_json::to_vec(&serde_json::json!({
        "authority_revision":revision,"entries":entries
    }))
    .map_err(|_| HostError::ResponseInvalid)?;
    Ok(host_crypto::digest(&wire))
}

fn entries(values: &[PeerStatusHeadEntryV1], config: &GatewayConfigDocument) -> bool {
    values.len() == config.peers.len()
        && values.iter().zip(&config.peers).all(|(value, peer)| {
            value.device_id == peer.device_id
                && value.certificate_sha256 == peer.certificate_sha256
                && value.request_key_id == peer.request_key_id
                && ((!value.registered && !value.revoked && value.device_revocation_epoch == 0)
                    || (value.registered && value.device_revocation_epoch > 0))
        })
}
