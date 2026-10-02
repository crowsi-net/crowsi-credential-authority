use ed25519_dalek::Signer;
use ihat_identity_assertion_contracts::{
    AUTHORITY_RESPONSE_SCHEMA, AuthorityResponseV1, AuthorityResult,
    PendingCancellationAcknowledgedMetadata, PendingRevocationCancelledMetadata, ResponseOutcome,
    canonical_response, command_digest,
};

fn cancelled_exchange(
    cancellation: &crowsi_credential_authority_contracts::EndpointRevocationExecutionCancellationV1,
    issued_at: u64,
) -> crowsi_credential_authority_contracts::SignedAuthorityExchangeV1 {
    let request = crowsi_credential_authority_contracts::attach_revocation_execution_cancellation(
        &cancellation.cancel_pending_request,
        cancellation,
    )
    .expect("attach cancellation root token");
    let ihat_identity_assertion_contracts::AuthorityCommand::CancelPendingRevocation(command) =
        &request.command
    else {
        unreachable!()
    };
    let mut response = AuthorityResponseV1 {
        schema: AUTHORITY_RESPONSE_SCHEMA.into(),
        request_id: request.request_id.clone(),
        command_type: request.command.type_name().into(),
        command_digest: command_digest(&request).expect("command digest"),
        config_generation: 2,
        issued_at_epoch_s: issued_at,
        expires_at_epoch_s: issued_at + 30,
        outcome: ResponseOutcome::Committed {
            result: AuthorityResult::PendingRevocationCancelled(
                PendingRevocationCancelledMetadata {
                    attempt_id: command.attempt_id.clone(),
                    finalize_command_id: command.finalize_command_id.clone(),
                    target_digest_sha256: command.target_digest_sha256.clone(),
                    cancellation_id: cancellation.cancellation_id.clone(),
                },
            ),
        },
        key_id: "identity-response-key".into(),
        signature: String::new(),
    };
    response.signature = hex::encode(
        crate::gateway_peer_response_identity::key(5)
            .sign(&canonical_response(&response).expect("canonical response"))
            .to_bytes(),
    );
    crowsi_credential_authority_contracts::SignedAuthorityExchangeV1 { request, response }
}

fn acknowledged_exchange(
    cleanup: &crowsi_credential_authority_contracts::EndpointRevocationExecutionCancellationCleanupV1,
    issued_at: u64,
    key_id: &str,
    key: u8,
    config_generation: u64,
) -> crowsi_credential_authority_contracts::SignedAuthorityExchangeV1 {
    let request = crowsi_credential_authority_contracts::attach_revocation_cancellation_cleanup(
        &cleanup.acknowledge_request,
        cleanup,
    )
    .expect("attach cleanup root token");
    let mut response = AuthorityResponseV1 {
        schema: AUTHORITY_RESPONSE_SCHEMA.into(),
        request_id: request.request_id.clone(),
        command_type: request.command.type_name().into(),
        command_digest: command_digest(&request).expect("command digest"),
        config_generation,
        issued_at_epoch_s: issued_at,
        expires_at_epoch_s: issued_at + 30,
        outcome: ResponseOutcome::Committed {
            result: AuthorityResult::PendingCancellationAcknowledged(
                PendingCancellationAcknowledgedMetadata {
                    cancellation_id: cleanup.cancellation_id.clone(),
                    cleanup_id: cleanup.cleanup_id.clone(),
                },
            ),
        },
        key_id: key_id.into(),
        signature: String::new(),
    };
    response.signature = hex::encode(
        crate::gateway_peer_response_identity::key(key)
            .sign(&canonical_response(&response).expect("canonical response"))
            .to_bytes(),
    );
    crowsi_credential_authority_contracts::SignedAuthorityExchangeV1 { request, response }
}
