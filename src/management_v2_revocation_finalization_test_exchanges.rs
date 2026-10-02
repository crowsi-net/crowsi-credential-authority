use ed25519_dalek::Signer;
use ihat_identity_assertion_contracts::{
    AUTHORITY_REQUEST_SCHEMA, AUTHORITY_RESPONSE_SCHEMA, AuthenticatorKindDto, AuthorityCommand,
    AuthorityEvidence, AuthorityRequestV1, AuthorityResponseV1, AuthorityResult,
    BeginDeviceRevocationCommand, DeviceRevocationMetadata, FRESH_UV_SCHEMA, FinishFreshUvCommand,
    FreshAuthenticationDto, FreshUvV1, ResponseOutcome, RevocationCeremonyMetadata,
    RevocationCeremonyStateDto, RevokeDeviceByRefCommand, SIGNED_EVIDENCE_SCHEMA, SignedEvidenceV1,
    VerificationRole, canonical_response, command_digest,
};

fn begin_exchange(
    prepared: &crowsi_credential_authority_contracts::EndpointPreparedOperationV2,
    identity: &ihat_identity_assertion_contracts::IdentityEvidenceMetadata,
) -> crowsi_credential_authority_contracts::SignedAuthorityExchangeV1 {
    let fresh = fresh(prepared, identity);
    let command = AuthorityCommand::BeginDeviceRevocation(BeginDeviceRevocationCommand {
        command_id: crowsi_credential_authority_contracts::revocation_begin_command_id(prepared)
            .expect("begin id"),
        finalize_command_id: prepared.operation_id.clone(),
        service_id: identity.assertion.service_id.clone(),
        pairwise_subject: prepared.pairwise_subject.clone(),
        source_device_id: DEVICE.into(),
        source_session_ref: prepared.source_session_ref.clone(),
        target_device_id: DEVICE.into(),
        expected_device_epoch: 1,
        identity_nonce: fresh.identity_nonce.clone(),
        sender_proof_id: "begin-sender-proof".into(),
        authentication: authentication(&fresh),
    });
    let sender = SignedEvidenceV1 {
        schema: SIGNED_EVIDENCE_SCHEMA.into(),
        role: VerificationRole::SessionSender,
        proof_id: "begin-sender-proof".into(),
        key_id: "begin-sender-key".into(),
        issued_at_epoch_s: NOW - 1,
        expires_at_epoch_s: NOW + 100,
        binding_sha256: String::new(),
        signature: "22".repeat(64),
    };
    signed_exchange(
        "begin-request",
        command,
        vec![
            AuthorityEvidence::FreshUv(fresh),
            AuthorityEvidence::Signed(sender),
        ],
        AuthorityResult::RevocationBegun(RevocationCeremonyMetadata {
            attempt_id: "revocation-attempt".into(),
            finalize_command_id: prepared.operation_id.clone(),
            target_digest: "33".repeat(32),
            expires_at_epoch_s: NOW + 200,
            independent_approval_required: false,
            state: RevocationCeremonyStateDto::ReadyToFinalize,
            approval_nonce: None,
        }),
        NOW,
    )
}

fn finish_exchange(
    begin: &crowsi_credential_authority_contracts::SignedAuthorityExchangeV1,
) -> crowsi_credential_authority_contracts::SignedAuthorityExchangeV1 {
    let AuthorityEvidence::FreshUv(document) = &begin.request.evidence[0] else {
        unreachable!()
    };
    signed_exchange(
        "finish-request",
        AuthorityCommand::FinishFreshUserVerification(FinishFreshUvCommand {
            command_id: "finish-source-uv".into(),
            attempt_id: document.attempt_id.clone(),
            credential_id: document.credential_id.clone(),
            client_data_json_base64url: "e30".into(),
            authenticator_data_base64url: "AA".into(),
            signature_der_base64url: "MA".into(),
        }),
        Vec::new(),
        AuthorityResult::FreshUvFinished {
            document: document.clone(),
        },
        NOW,
    )
}

fn final_exchange(
    prepared: &crowsi_credential_authority_contracts::EndpointPreparedOperationV2,
) -> crowsi_credential_authority_contracts::SignedAuthorityExchangeV1 {
    signed_exchange(
        "final-request",
        AuthorityCommand::RevokeDeviceByRef(RevokeDeviceByRefCommand {
            command_id: prepared.operation_id.clone(),
            service_id: "service-a".into(),
            pairwise_subject: prepared.pairwise_subject.clone(),
            target_device_id: DEVICE.into(),
            expected_device_epoch: 1,
            authority_id: "runtime-revocation-key".into(),
        }),
        Vec::new(),
        AuthorityResult::DeviceRevocation(DeviceRevocationMetadata {
            target_digest: "33".repeat(32),
            previous_device_epoch: 1,
            current_device_epoch: 2,
            revoked_session_count: 1,
            audit_sequence: 9,
        }),
        NOW + 1,
    )
}

include!("management_v2_revocation_finalization_test_exchange_support.rs");
