use ed25519_dalek::Signer;
use ihat_identity_assertion_contracts::{
    AUTHORITY_REQUEST_SCHEMA, AUTHORITY_RESPONSE_SCHEMA, AuthorityCommand, AuthorityEvidence,
    AuthorityRequestV1, AuthorityResponseV1, AuthorityResult, CurrentDeviceStatusV1,
    DeviceIdentityAssertionV1, DevicePostureV1, IdentityEvidenceMetadata,
    IssueCurrentDeviceIdentityEvidenceCommand, ResponseOutcome, RevocationEpochsV1,
    SIGNED_EVIDENCE_SCHEMA, SignedEvidenceV1, VerificationRole, canonical_assertion_payload,
    canonical_current_status_payload, canonical_response, command_digest,
};

use crate::fixture::{Fixture, key};

pub(crate) const ISSUER: &str = "ihat-authority";
pub(crate) const SERVICE: &str = "service-a";
pub(crate) const PAIRWISE: &str = "psu_pairwise-service-a";
pub(crate) const OWNER: &str = "psa_owner_0000000000000001";
pub(crate) const DEVICE_A: &str = "device-a";
pub(crate) const DEVICE_B: &str = "device-b";
pub(crate) const REGISTRATION_AUDIENCE: &str = "crowsi://identity/register";
pub(crate) const MANAGEMENT_AUDIENCE: &str = "crowsi://management";

pub(crate) fn assertion(
    fixture: &Fixture,
    device: &str,
    audience: &str,
) -> DeviceIdentityAssertionV1 {
    let suffix = if device == DEVICE_A { 'a' } else { 'b' };
    let mut value = DeviceIdentityAssertionV1 {
        schema: "ihat://identity/device-identity-assertion/v1".into(),
        issuer: ISSUER.into(),
        audience: audience.into(),
        service_id: SERVICE.into(),
        pairwise_subject: PAIRWISE.into(),
        device_id: device.into(),
        device_proof_key_ref: format!("device-proof-{suffix}"),
        session_ref: format!("sref_{}", suffix.to_string().repeat(64)),
        device_posture: DevicePostureV1 {
            state: "compliant".into(),
            revision: 11,
        },
        revocation_epochs: RevocationEpochsV1 {
            subject: 5,
            service: 3,
            device: 7,
            session: 9,
        },
        issued_at_epoch_s: fixture.now - 1,
        expires_at_epoch_s: fixture.now + 29,
        nonce: format!("nonce-{device}-{audience}"),
        key_id: "identity-key".into(),
        signature: String::new(),
    };
    value.signature = hex::encode(key(2).sign(&canonical_assertion_payload(&value)).to_bytes());
    value
}

pub(crate) fn evidence(fixture: &Fixture) -> IdentityEvidenceMetadata {
    let assertion = assertion(fixture, DEVICE_A, MANAGEMENT_AUDIENCE);
    let mut current_status = CurrentDeviceStatusV1 {
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
    current_status.signature = hex::encode(
        key(3)
            .sign(&canonical_current_status_payload(&current_status))
            .to_bytes(),
    );
    IdentityEvidenceMetadata {
        assertion,
        current_status,
    }
}

pub(crate) fn evidence_exchange(
    fixture: &Fixture,
) -> crowsi_credential_authority_contracts::SignedAuthorityExchangeV1 {
    let identity = evidence(fixture);
    let proof_id = "session-sender-device-a";
    let mut request = AuthorityRequestV1 {
        schema: AUTHORITY_REQUEST_SCHEMA.into(),
        request_id: "current-identity-device-a".into(),
        command: AuthorityCommand::IssueCurrentDeviceIdentityEvidence(
            IssueCurrentDeviceIdentityEvidenceCommand {
                service_id: SERVICE.into(),
                pairwise_subject: PAIRWISE.into(),
                device_id: DEVICE_A.into(),
                audience: MANAGEMENT_AUDIENCE.into(),
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
            key_id: "device-proof-a".into(),
            issued_at_epoch_s: fixture.now - 1,
            expires_at_epoch_s: fixture.now + 29,
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
        issued_at_epoch_s: fixture.now - 1,
        expires_at_epoch_s: fixture.now + 29,
        outcome: ResponseOutcome::Committed {
            result: AuthorityResult::IdentityEvidence(identity),
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
