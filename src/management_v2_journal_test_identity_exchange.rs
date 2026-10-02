pub(crate) fn identity_exchange(
    device: &str,
) -> crowsi_credential_authority_contracts::SignedAuthorityExchangeV1 {
    let identity = identity(device);
    let proof_id = format!("session-sender-{device}");
    let mut request = AuthorityRequestV1 {
        schema: AUTHORITY_REQUEST_SCHEMA.into(),
        request_id: format!("current-identity-{device}"),
        command: AuthorityCommand::IssueCurrentDeviceIdentityEvidence(
            IssueCurrentDeviceIdentityEvidenceCommand {
                service_id: identity.assertion.service_id.clone(),
                pairwise_subject: identity.assertion.pairwise_subject.clone(),
                device_id: device.into(),
                audience: identity.assertion.audience.clone(),
                identity_nonce: identity.assertion.nonce.clone(),
                ttl_seconds: 30,
                session_sender_key_fingerprint: "55".repeat(32),
                session_sender_proof_id: proof_id.clone(),
            },
        ),
        evidence: vec![AuthorityEvidence::Signed(SignedEvidenceV1 {
            schema: SIGNED_EVIDENCE_SCHEMA.into(),
            role: VerificationRole::SessionSender,
            proof_id,
            key_id: format!("proof-{device}"),
            issued_at_epoch_s: NOW - 1,
            expires_at_epoch_s: NOW + 30,
            binding_sha256: String::new(),
            signature: "55".repeat(64),
        })],
    };
    let digest = command_digest(&request).expect("digest");
    let AuthorityEvidence::Signed(sender) = &mut request.evidence[0] else {
        unreachable!()
    };
    sender.binding_sha256.clone_from(&digest);
    crowsi_credential_authority_contracts::SignedAuthorityExchangeV1 {
        request,
        response: AuthorityResponseV1 {
            schema: AUTHORITY_RESPONSE_SCHEMA.into(),
            request_id: format!("current-identity-{device}"),
            command_type: "issue_current_device_identity_evidence".into(),
            command_digest: digest,
            config_generation: 1,
            issued_at_epoch_s: NOW - 1,
            expires_at_epoch_s: NOW + 29,
            outcome: ResponseOutcome::Committed {
                result: AuthorityResult::IdentityEvidence(identity),
            },
            key_id: "identity-response-key".into(),
            signature: "66".repeat(64),
        },
    }
}

pub(crate) fn sref(value: char) -> String {
    format!("sref_{}", value.to_string().repeat(64))
}
