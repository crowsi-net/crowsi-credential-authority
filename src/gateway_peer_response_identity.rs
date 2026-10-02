use ed25519_dalek::{Signer, SigningKey};
use ihat_identity_assertion_contracts::{
    AUTHORITY_REQUEST_SCHEMA, AUTHORITY_RESPONSE_SCHEMA, AuthorityCommand, AuthorityEvidence,
    AuthorityRequestV1, AuthorityResponseV1, AuthorityResult, CurrentDeviceStatusV1,
    DeviceIdentityAssertionV1, DevicePostureV1, IdentityEvidenceMetadata,
    IssueCurrentDeviceIdentityEvidenceCommand, ResponseOutcome, RevocationEpochsV1,
    SIGNED_EVIDENCE_SCHEMA, SignedEvidenceV1, VerificationRole, canonical_assertion_payload,
    canonical_current_status_payload, canonical_response, command_digest,
};

use crate::gateway_peer_response_fixture::{DEVICE_C, NOW};

pub(super) fn identity() -> IdentityEvidenceMetadata {
    let mut assertion = DeviceIdentityAssertionV1 {
        schema: "ihat://identity/device-identity-assertion/v1".into(),
        issuer: "ihat-authority".into(),
        audience: "management-audience".into(),
        service_id: "service-a".into(),
        pairwise_subject: "psu_pairwise-a".into(),
        device_id: DEVICE_C.into(),
        device_proof_key_ref: "device-proof-c".into(),
        session_ref: format!("sref_{}", "c".repeat(64)),
        device_posture: DevicePostureV1 {
            state: "compliant".into(),
            revision: 5,
        },
        revocation_epochs: RevocationEpochsV1 {
            subject: 1,
            service: 2,
            device: 3,
            session: 4,
        },
        issued_at_epoch_s: NOW - 1,
        expires_at_epoch_s: NOW + 29,
        nonce: "identity-nonce-c".into(),
        key_id: "identity-key".into(),
        signature: String::new(),
    };
    assertion.signature = hex::encode(
        key(2)
            .sign(&canonical_assertion_payload(&assertion))
            .to_bytes(),
    );
    let mut status = CurrentDeviceStatusV1 {
        schema: "ihat://identity/current-device-status/v1".into(),
        issuer: assertion.issuer.clone(),
        audience: assertion.audience.clone(),
        service_id: assertion.service_id.clone(),
        pairwise_subject: assertion.pairwise_subject.clone(),
        device_id: assertion.device_id.clone(),
        device_proof_key_ref: assertion.device_proof_key_ref.clone(),
        session_ref: assertion.session_ref.clone(),
        device_posture: assertion.device_posture.clone(),
        revocation_epochs: assertion.revocation_epochs.clone(),
        issued_at_epoch_s: assertion.issued_at_epoch_s,
        expires_at_epoch_s: assertion.expires_at_epoch_s,
        nonce: assertion.nonce.clone(),
        key_id: "status-key".into(),
        signature: String::new(),
    };
    status.signature = hex::encode(
        key(3)
            .sign(&canonical_current_status_payload(&status))
            .to_bytes(),
    );
    IdentityEvidenceMetadata {
        assertion,
        current_status: status,
    }
}

pub(super) fn exchange(
    identity: &IdentityEvidenceMetadata,
) -> crowsi_credential_authority_contracts::SignedAuthorityExchangeV1 {
    let proof_id = "session-sender-c";
    let mut request = AuthorityRequestV1 {
        schema: AUTHORITY_REQUEST_SCHEMA.into(),
        request_id: "current-identity-c".into(),
        command: AuthorityCommand::IssueCurrentDeviceIdentityEvidence(
            IssueCurrentDeviceIdentityEvidenceCommand {
                service_id: identity.assertion.service_id.clone(),
                pairwise_subject: identity.assertion.pairwise_subject.clone(),
                device_id: identity.assertion.device_id.clone(),
                audience: identity.assertion.audience.clone(),
                identity_nonce: identity.assertion.nonce.clone(),
                ttl_seconds: 30,
                session_sender_key_fingerprint: "55".repeat(32),
                session_sender_proof_id: proof_id.into(),
            },
        ),
        evidence: vec![AuthorityEvidence::Signed(SignedEvidenceV1 {
            schema: SIGNED_EVIDENCE_SCHEMA.into(),
            role: VerificationRole::SessionSender,
            proof_id: proof_id.into(),
            key_id: "device-proof-c".into(),
            issued_at_epoch_s: NOW - 1,
            expires_at_epoch_s: NOW + 29,
            binding_sha256: String::new(),
            signature: "55".repeat(64),
        })],
    };
    let digest = command_digest(&request).expect("digest");
    let AuthorityEvidence::Signed(sender) = &mut request.evidence[0] else {
        unreachable!()
    };
    sender.binding_sha256.clone_from(&digest);
    let mut response = AuthorityResponseV1 {
        schema: AUTHORITY_RESPONSE_SCHEMA.into(),
        request_id: request.request_id.clone(),
        command_type: request.command.type_name().into(),
        command_digest: digest,
        config_generation: 2,
        issued_at_epoch_s: NOW - 1,
        expires_at_epoch_s: NOW + 29,
        outcome: ResponseOutcome::Committed {
            result: AuthorityResult::IdentityEvidence(identity.clone()),
        },
        key_id: "identity-response-key".into(),
        signature: String::new(),
    };
    response.signature = hex::encode(
        key(5)
            .sign(&canonical_response(&response).expect("response canonical"))
            .to_bytes(),
    );
    crowsi_credential_authority_contracts::SignedAuthorityExchangeV1 { request, response }
}

pub(super) fn key(value: u8) -> SigningKey {
    SigningKey::from_bytes(&[value; 32])
}
pub(super) fn public(value: u8) -> String {
    hex::encode(key(value).verifying_key().to_bytes())
}
