use ihat_identity_assertion_contracts::{
    AuthenticatorKindDto, AuthorityCommand, AuthorityEvidence, BeginDeviceRevocationCommand,
    FreshAuthenticationDto, VerificationRole, command_digest,
};

#[test]
fn distinct_one_use_sender_proofs_with_same_session_key_are_accepted() {
    let current = crate::management_v2_journal_test_environment::identity_exchange("device-a");
    let begin = begin(&current, "begin-sender-proof", "proof-device-a");
    assert!(
        crate::management_v2_evidence_ceremony::source_sender(&current, "proof-device-a", &begin)
            .is_ok()
    );
}

#[test]
fn reused_proof_different_key_or_source_session_is_rejected() {
    let current = crate::management_v2_journal_test_environment::identity_exchange("device-a");
    let current_proof = sender(&current).proof_id.clone();
    assert!(
        crate::management_v2_evidence_ceremony::source_sender(
            &current,
            "proof-device-a",
            &begin(&current, &current_proof, "proof-device-a")
        )
        .is_err()
    );
    assert!(
        crate::management_v2_evidence_ceremony::source_sender(
            &current,
            "proof-device-a",
            &begin(&current, "begin-sender-proof", "different-key")
        )
        .is_err()
    );
    let mut wrong_session = begin(&current, "begin-sender-proof", "proof-device-a");
    let AuthorityCommand::BeginDeviceRevocation(command) = &mut wrong_session.request.command
    else {
        unreachable!()
    };
    command.source_session_ref = format!("sref_{}", "f".repeat(64));
    rebind(&mut wrong_session);
    assert!(
        crate::management_v2_evidence_ceremony::source_sender(
            &current,
            "proof-device-a",
            &wrong_session
        )
        .is_err()
    );
}

fn begin(
    current: &crowsi_credential_authority_contracts::SignedAuthorityExchangeV1,
    proof_id: &str,
    key_id: &str,
) -> crowsi_credential_authority_contracts::SignedAuthorityExchangeV1 {
    let identity = crowsi_credential_authority_contracts::identity_evidence_from_exchange(current)
        .expect("current identity");
    let mut value = current.clone();
    value.request.request_id = "begin-device-revocation".into();
    value.request.command = AuthorityCommand::BeginDeviceRevocation(BeginDeviceRevocationCommand {
        command_id: "begin-command".into(),
        finalize_command_id: "final-command".into(),
        service_id: identity.assertion.service_id.clone(),
        pairwise_subject: identity.assertion.pairwise_subject.clone(),
        source_device_id: identity.assertion.device_id.clone(),
        source_session_ref: identity.assertion.session_ref.clone(),
        target_device_id: "device-b".into(),
        expected_device_epoch: 3,
        identity_nonce: identity.assertion.nonce.clone(),
        sender_proof_id: proof_id.into(),
        authentication: authentication(identity),
    });
    let proof = sender_mut(&mut value);
    proof.proof_id = proof_id.into();
    proof.key_id = key_id.into();
    rebind(&mut value);
    value
}

fn authentication(
    identity: &ihat_identity_assertion_contracts::IdentityEvidenceMetadata,
) -> FreshAuthenticationDto {
    FreshAuthenticationDto {
        proof_id: "fresh-proof".into(),
        authenticator_id: "authenticator-a".into(),
        authenticator_key_fingerprint: "11".repeat(32),
        kind: AuthenticatorKindDto::DeviceBoundPasskey,
        user_verified: true,
        issued_at_epoch_s: 9_999,
        expires_at_epoch_s: 10_120,
        service_id: identity.assertion.service_id.clone(),
        pairwise_subject: identity.assertion.pairwise_subject.clone(),
        session_ref: identity.assertion.session_ref.clone(),
        operation_digest_sha256: format!("sha256:{}", "22".repeat(32)),
        subject_epoch: identity.assertion.revocation_epochs.subject,
        service_epoch: identity.assertion.revocation_epochs.service,
        device_epoch: identity.assertion.revocation_epochs.device,
        session_epoch: identity.assertion.revocation_epochs.session,
    }
}

fn rebind(value: &mut crowsi_credential_authority_contracts::SignedAuthorityExchangeV1) {
    let digest = command_digest(&value.request).expect("request digest");
    sender_mut(value).binding_sha256 = digest;
}

fn sender(
    value: &crowsi_credential_authority_contracts::SignedAuthorityExchangeV1,
) -> &ihat_identity_assertion_contracts::SignedEvidenceV1 {
    value
        .request
        .evidence
        .iter()
        .find_map(|item| match item {
            AuthorityEvidence::Signed(value) if value.role == VerificationRole::SessionSender => {
                Some(value)
            }
            _ => None,
        })
        .expect("session sender")
}

fn sender_mut(
    value: &mut crowsi_credential_authority_contracts::SignedAuthorityExchangeV1,
) -> &mut ihat_identity_assertion_contracts::SignedEvidenceV1 {
    value
        .request
        .evidence
        .iter_mut()
        .find_map(|item| match item {
            AuthorityEvidence::Signed(value) if value.role == VerificationRole::SessionSender => {
                Some(value)
            }
            _ => None,
        })
        .expect("session sender")
}
