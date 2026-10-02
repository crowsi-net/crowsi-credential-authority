use crate::{
    HostError,
    gateway_contract::GatewayConfigDocument,
    gateway_replay_witness_types::{
        REQUEST_SCHEMA, RESPONSE_DOMAIN, RESPONSE_SCHEMA, ReplayWitnessRequestV1,
        ReplayWitnessResponseV1,
    },
    host_config_types::HostConfigDocument,
    host_crypto,
};

pub(super) fn request(
    gateway: &GatewayConfigDocument,
    gateway_digest: &str,
    device: &str,
    nonce: &str,
    digest: &str,
    now: u64,
) -> Result<(ReplayWitnessRequestV1, Vec<u8>), HostError> {
    if !gateway.peers.iter().any(|item| item.device_id == device)
        || !bare_hex(nonce)
        || !sha256(digest)
    {
        return Err(HostError::EvidenceInvalid);
    }
    let seed = [
        device.as_bytes(),
        b"\0",
        nonce.as_bytes(),
        b"\0",
        digest.as_bytes(),
    ]
    .concat();
    let request = ReplayWitnessRequestV1 {
        schema: REQUEST_SCHEMA.into(),
        request_id: format!("replay_{}", &host_crypto::digest(&seed)[7..]),
        deployment_id: gateway.deployment_id.clone(),
        gateway_config_sha256: gateway_digest.into(),
        authority_epoch: gateway.authority_epoch,
        device_id: device.into(),
        nonce: nonce.into(),
        transport_request_digest: digest.into(),
        expires_at_epoch_s: now.saturating_add(300),
    };
    let wire = serde_json::to_vec(&request).map_err(|_| HostError::RequestInvalid)?;
    Ok((request, wire))
}

pub(super) fn verify(
    wire: &[u8],
    request: &ReplayWitnessRequestV1,
    request_wire: &[u8],
    gateway: &GatewayConfigDocument,
    host: &HostConfigDocument,
    now: u64,
) -> Result<(), HostError> {
    if wire.is_empty() || wire.len() > 65_536 {
        return Err(HostError::ResponseInvalid);
    }
    let value: ReplayWitnessResponseV1 =
        serde_json::from_slice(wire).map_err(|_| HostError::ResponseInvalid)?;
    let valid = value.schema == RESPONSE_SCHEMA
        && value.request_id == request.request_id
        && value.request_digest_sha256 == host_crypto::digest(request_wire)
        && value.deployment_id == gateway.deployment_id
        && value.gateway_config_sha256 == request.gateway_config_sha256
        && value.authority_epoch == gateway.authority_epoch
        && value.device_id == request.device_id
        && value.nonce == request.nonce
        && value.transport_request_digest == request.transport_request_digest
        && value.witness_revision > 0
        && value.issued_at_epoch_s <= now
        && now < value.expires_at_epoch_s
        && value
            .expires_at_epoch_s
            .saturating_sub(value.issued_at_epoch_s)
            <= 10
        && value.key_id == host.response_key_id;
    if !valid {
        return Err(HostError::ResponseInvalid);
    }
    let json = serde_json::to_value(&value).map_err(|_| HostError::ResponseInvalid)?;
    let canonical = host_crypto::canonical(RESPONSE_DOMAIN, &json)?;
    host_crypto::verify(&host.response_public_key_hex, &value.signature, &canonical)
        .then_some(())
        .ok_or(HostError::ResponseInvalid)
}

fn bare_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|item| item.is_ascii_digit() || matches!(item, b'a'..=b'f'))
}

fn sha256(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(bare_hex)
}
