fn bind_response(
    response: &mut crowsi_credential_authority_contracts::ManagementProjectionV2,
    envelope: &EndpointManagementEnvelopeV2,
) {
    let EndpointManagementEvidenceV2::Cancel {
        identity_exchange,
        prepared,
    } = &envelope.evidence
    else {
        unreachable!()
    };
    let identity = identity_evidence_from_exchange(identity_exchange).expect("identity");
    let assertion = &identity.assertion;
    let epochs = &assertion.revocation_epochs;
    response
        .request_id
        .clone_from(&envelope.browser_request.request_id);
    response.command_digest_sha256 =
        management_command_digest(&envelope.browser_request).expect("command digest");
    response.issuer = "projection-issuer".into();
    response.audience = "management-audience".into();
    response.service_id.clone_from(&assertion.service_id);
    response
        .pairwise_subject
        .clone_from(&assertion.pairwise_subject);
    response
        .opaque_account_ref
        .clone_from(&prepared.opaque_owner_ref);
    response.current_device_ref.clone_from(&assertion.device_id);
    response
        .current_session_ref
        .clone_from(&assertion.session_ref);
    response.subject_revocation_epoch = epochs.subject;
    response.service_revocation_epoch = epochs.service;
    response.device_revocation_epoch = epochs.device;
    response.session_revocation_epoch = epochs.session;
    response
        .device_posture_state
        .clone_from(&assertion.device_posture.state);
    response.device_posture_revision = assertion.device_posture.revision;
    response
        .device_proof_key_ref
        .clone_from(&assertion.device_proof_key_ref);
    response.issued_at_epoch_s = NOW;
    response.expires_at_epoch_s = NOW + 30;
    response.key_id = "projection-key".into();
    response.signature = hex::encode(
        crate::gateway_peer_response_identity::key(7)
            .sign(&canonical_management_projection(response).expect("canonical"))
            .to_bytes(),
    );
}
