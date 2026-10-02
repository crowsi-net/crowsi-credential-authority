use std::path::Path;

use crate::{
    HostError,
    gateway_contract::GatewayConfigDocument,
    gateway_replay_witness_types::{
        REQUEST_SCHEMA, RESPONSE_DOMAIN, RESPONSE_SCHEMA, ReplayWitnessRequestV1,
        ReplayWitnessResponseV1,
    },
    host_config::VerifiedHostConfig,
    host_crypto,
    management_v2_journal::ManagementJournalV2,
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
    let request: ReplayWitnessRequestV1 =
        serde_json::from_slice(wire).map_err(|_| HostError::RequestInvalid)?;
    let peer = gateway
        .peers
        .iter()
        .find(|item| item.device_id == request.device_id)
        .ok_or(HostError::EvidenceInvalid)?;
    let owner = config
        .document
        .device_proof_keys
        .iter()
        .find(|item| item.device_id == peer.device_id)
        .ok_or(HostError::ConfigInvalid)?;
    let expected_request_id = replay_request_id(
        &request.device_id,
        &request.nonce,
        &request.transport_request_digest,
    );
    let valid = request.schema == REQUEST_SCHEMA
        && matches!(expected_request_id, Ok(ref value) if value == &request.request_id)
        && request.deployment_id == gateway.deployment_id
        && request.gateway_config_sha256 == gateway_digest
        && request.authority_epoch == gateway.authority_epoch
        && bare_hex(&request.nonce)
        && sha256(&request.transport_request_digest)
        && now < request.expires_at_epoch_s
        && request.expires_at_epoch_s.saturating_sub(now) <= 300;
    if !valid {
        return Err(HostError::RequestInvalid);
    }
    let journal = ManagementJournalV2::open(
        Path::new(&config.document.management_state_directory),
        Path::new(&config.document.management_anchor_directory),
        config.document.authority_epoch,
        crate::management_v2_journal::ReservationRootBinding::from_config(&config.document),
    )?;
    let revision = journal.consume_transport_replay(
        &owner.opaque_owner_ref,
        &request.device_id,
        &request.nonce,
        request.expires_at_epoch_s,
        now,
    )?;
    let mut response = ReplayWitnessResponseV1 {
        schema: RESPONSE_SCHEMA.into(),
        request_id: request.request_id,
        request_digest_sha256: host_crypto::digest(wire),
        deployment_id: gateway.deployment_id.clone(),
        gateway_config_sha256: gateway_digest.into(),
        authority_epoch: gateway.authority_epoch,
        device_id: request.device_id,
        nonce: request.nonce,
        transport_request_digest: request.transport_request_digest,
        witness_revision: revision,
        issued_at_epoch_s: now,
        expires_at_epoch_s: now.saturating_add(10),
        key_id: config.document.response_key_id.clone(),
        signature: String::new(),
    };
    let json = serde_json::to_value(&response).map_err(|_| HostError::ResponseInvalid)?;
    let canonical = host_crypto::canonical(RESPONSE_DOMAIN, &json)?;
    response.signature = host_crypto::sign(&config.response_signing_key, &canonical);
    serde_json::to_vec(&response).map_err(|_| HostError::ResponseInvalid)
}

fn replay_request_id(device: &str, nonce: &str, digest: &str) -> Result<String, HostError> {
    let valid = !device.is_empty()
        && device.len() <= 128
        && device.trim() == device
        && !device.chars().any(char::is_control)
        && bare_hex(nonce)
        && sha256(digest);
    valid
        .then(|| {
            let seed = [
                device.as_bytes(),
                b"\0",
                nonce.as_bytes(),
                b"\0",
                digest.as_bytes(),
            ]
            .concat();
            format!("replay_{}", &host_crypto::digest(&seed)[7..])
        })
        .ok_or(HostError::RequestInvalid)
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
