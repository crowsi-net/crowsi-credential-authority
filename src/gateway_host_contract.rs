use crowsi_authority_transport::{PeerBinding, SignedRequest};
use serde::{Deserialize, Serialize};

use crate::HostError;

const SCHEMA: &str = "crowsi://credential-authority/gateway-host-request/v1";
const MAX_WIRE: usize = 540_000;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct GatewayHostRequestV1 {
    schema: String,
    command: String,
    peer: GatewayHostPeerV1,
    payload_hex: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct GatewayHostPeerV1 {
    device_id: String,
    certificate_sha256: String,
    request_key_id: String,
    request_public_key_hex: String,
}

pub(crate) fn encode(value: &SignedRequest) -> Result<Vec<u8>, HostError> {
    validate(value)?;
    let document = GatewayHostRequestV1 {
        schema: SCHEMA.into(),
        command: value.command.clone(),
        peer: GatewayHostPeerV1 {
            device_id: value.peer.device_id.clone(),
            certificate_sha256: value.peer.certificate_sha256.clone(),
            request_key_id: value.peer.request_key_id.clone(),
            request_public_key_hex: value.peer.request_public_key_hex.clone(),
        },
        payload_hex: hex::encode(&value.payload),
    };
    let wire = serde_json::to_vec(&document).map_err(|_| HostError::RequestInvalid)?;
    (wire.len() <= MAX_WIRE)
        .then_some(wire)
        .ok_or(HostError::RequestInvalid)
}

pub(crate) fn decode(wire: &[u8]) -> Result<SignedRequest, HostError> {
    if wire.is_empty() || wire.len() > MAX_WIRE {
        return Err(HostError::RequestInvalid);
    }
    let value: GatewayHostRequestV1 =
        serde_json::from_slice(wire).map_err(|_| HostError::RequestInvalid)?;
    let request = SignedRequest {
        peer: PeerBinding {
            device_id: value.peer.device_id,
            certificate_sha256: value.peer.certificate_sha256,
            request_key_id: value.peer.request_key_id,
            request_public_key_hex: value.peer.request_public_key_hex,
        },
        command: value.command,
        payload: hex::decode(value.payload_hex).map_err(|_| HostError::RequestInvalid)?,
    };
    if value.schema != SCHEMA {
        return Err(HostError::RequestInvalid);
    }
    validate(&request)?;
    Ok(request)
}

fn validate(value: &SignedRequest) -> Result<(), HostError> {
    let valid = command(&value.command)
        && id(&value.peer.device_id)
        && digest(&value.peer.certificate_sha256)
        && id(&value.peer.request_key_id)
        && lower_hex(&value.peer.request_public_key_hex, 64)
        && !value.payload.is_empty()
        && value.payload.len() <= 262_144;
    valid.then_some(()).ok_or(HostError::RequestInvalid)
}

fn command(value: &str) -> bool {
    matches!(
        value,
        "snapshot"
            | "source-options"
            | "source-approve"
            | "pending"
            | "target-options"
            | "target-approve"
            | "approval-options"
            | "approve-revocation"
            | "cancel"
            | "reconcile"
            | "revocation-finalize"
            | "independent-revocation-pre-final"
            | "revocation-execution-reserve"
            | "revocation-execution-cancel"
            | "revocation-execution-cancel-finalize"
            | "revocation-execution-cancel-cleanup-complete"
            | "independent-revocation-finalize"
            | "lookup-prepared"
    )
}

fn id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

fn digest(value: &str) -> bool {
    value
        .strip_prefix("sha256:")
        .is_some_and(|item| lower_hex(item, 64))
}

fn lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
