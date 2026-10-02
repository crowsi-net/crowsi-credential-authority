use crowsi_authority_transport::{PeerBinding, SignedRequest};
use crowsi_credential_authority_contracts::{
    ActorRequirementV2, ENDPOINT_MANAGEMENT_ENVELOPE_SCHEMA, EndpointManagementEnvelopeV2,
    EndpointManagementEvidenceV2, MANAGEMENT_PROJECTION_SCHEMA, MANAGEMENT_REQUEST_SCHEMA,
    ManagementCommandV2, ManagementOperationKind, ManagementOperationScopeV2,
    ManagementOperationState, ManagementOperationV2, ManagementProjectionBodyV2,
    ManagementProjectionV2, ManagementRequestV2, RequiredActorRole,
    canonical_management_projection, management_command_digest,
};
use ed25519_dalek::Signer;
use ihat_identity_assertion_contracts::IdentityEvidenceMetadata;

use crate::{
    gateway_contract::GatewayPeerDocument,
    gateway_peer_response_identity::{exchange as identity_exchange, identity, key, public},
};

pub(super) const NOW: u64 = 10_000;
pub(super) const DEVICE_A: &str = "device-a";
pub(super) const DEVICE_C: &str = "device-c";

pub(super) fn exchange() -> (SignedRequest, Vec<u8>) {
    let identity = identity();
    let identity_exchange = identity_exchange(&identity);
    let browser_request = ManagementRequestV2 {
        schema: MANAGEMENT_REQUEST_SCHEMA.into(),
        request_id: "peer-deny-reconcile".into(),
        command: ManagementCommandV2::Snapshot {
            service_id: "service-a".into(),
        },
    };
    let envelope = EndpointManagementEnvelopeV2 {
        schema: ENDPOINT_MANAGEMENT_ENVELOPE_SCHEMA.into(),
        browser_request: browser_request.clone(),
        evidence: EndpointManagementEvidenceV2::Passive { identity_exchange },
    };
    let request = SignedRequest {
        peer: PeerBinding {
            device_id: DEVICE_C.into(),
            certificate_sha256: digest('c'),
            request_key_id: "request-c".into(),
            request_public_key_hex: public(12),
        },
        command: "snapshot".into(),
        payload: serde_json::to_vec(&envelope).expect("envelope"),
    };
    (request, projection(&browser_request, &identity))
}

fn projection(request: &ManagementRequestV2, identity: &IdentityEvidenceMetadata) -> Vec<u8> {
    let assertion = &identity.assertion;
    let epochs = &assertion.revocation_epochs;
    let mut value = ManagementProjectionV2 {
        schema: MANAGEMENT_PROJECTION_SCHEMA.into(),
        projection_id: "projection-peer-deny".into(),
        request_id: request.request_id.clone(),
        command_digest_sha256: management_command_digest(request).expect("digest"),
        issuer: "projection-issuer".into(),
        audience: assertion.audience.clone(),
        service_id: assertion.service_id.clone(),
        pairwise_subject: assertion.pairwise_subject.clone(),
        opaque_account_ref: "psa_owner_0000000000000001".into(),
        current_device_ref: assertion.device_id.clone(),
        current_session_ref: assertion.session_ref.clone(),
        subject_revocation_epoch: epochs.subject,
        service_revocation_epoch: epochs.service,
        device_revocation_epoch: epochs.device,
        session_revocation_epoch: epochs.session,
        device_posture_state: assertion.device_posture.state.clone(),
        device_posture_revision: assertion.device_posture.revision,
        device_proof_key_ref: assertion.device_proof_key_ref.clone(),
        snapshot_revision: 2,
        issued_at_epoch_s: NOW,
        expires_at_epoch_s: NOW + 30,
        body: ManagementProjectionBodyV2::Operation {
            operation: completed(),
        },
        key_id: "projection-key".into(),
        signature: String::new(),
    };
    value.signature = hex::encode(
        key(7)
            .sign(&canonical_management_projection(&value).expect("projection canonical"))
            .to_bytes(),
    );
    serde_json::to_vec(&value).expect("projection")
}

fn completed() -> ManagementOperationV2 {
    ManagementOperationV2 {
        operation_id: "revoke-device-a".into(),
        kind: ManagementOperationKind::DeviceRevocation,
        intent_digest_sha256: "ab".repeat(32),
        state: ManagementOperationState::Completed,
        state_revision: 8,
        created_at_epoch_s: NOW - 10,
        expires_at_epoch_s: NOW + 300,
        source_device_ref: DEVICE_C.into(),
        scope: ManagementOperationScopeV2::DeviceRevocation {
            target_device_ref: DEVICE_A.into(),
            expected_device_revocation_epoch: 7,
            revokes_session_refs: vec!["session-a".into()],
            rotates_credential_refs: vec![],
            preserves_device_refs: vec![DEVICE_C.into()],
        },
        actor: ActorRequirementV2 {
            role: RequiredActorRole::NoActor,
            required_actor_device_ref: None,
            required_approval_authority_ref: None,
            excluded_actor_device_refs: vec![],
        },
        webauthn_options: None,
        reason: None,
        reconcile_digest: None,
    }
}

pub(super) fn peers() -> Vec<GatewayPeerDocument> {
    vec![peer(DEVICE_A, 'a', 11), peer(DEVICE_C, 'c', 12)]
}
fn peer(device: &str, cert: char, public_key: u8) -> GatewayPeerDocument {
    GatewayPeerDocument {
        device_id: device.into(),
        certificate_der_hex: "00".into(),
        certificate_sha256: digest(cert),
        request_key_id: format!("request-{cert}"),
        request_public_key_hex: public(public_key),
    }
}
fn digest(value: char) -> String {
    format!("sha256:{}", value.to_string().repeat(64))
}
