fn reserve_and_finalize(
    fixture: &crate::management_v2_journal_test_environment::Fixture,
    value: &RevocationCase,
) -> crowsi_credential_authority_contracts::EndpointRevocationFinalizeRequestV1 {
    use crowsi_credential_authority_contracts::{
        ENDPOINT_REVOCATION_FINALIZE_REQUEST_SCHEMA, EndpointRevocationFinalizeRequestV1,
        attach_revocation_execution_reservation,
    };

    let config = test_config();
    let (_, reservation) = fixture
        .journal()
        .accept_execution_reservation(&value.reserve, DEVICE, &config, &[], NOW + 1)
        .expect("durable irreversible reservation");
    let mut final_exchange = value.final_exchange.clone();
    final_exchange.request =
        attach_revocation_execution_reservation(&value.reserve.final_revoke_request, &reservation)
            .expect("attach exact root token");
    EndpointRevocationFinalizeRequestV1 {
        schema: ENDPOINT_REVOCATION_FINALIZE_REQUEST_SCHEMA.into(),
        request_id: "internal-finalize".into(),
        operation_id: value.reserve.operation_id.clone(),
        expected_state_revision: reservation.reserved_state_revision,
        pre_final_state_revision: reservation.pre_final_state_revision,
        reconcile_digest: value.reserve.reconcile_digest.clone(),
        source_approve_request: value.reserve.original_request.clone(),
        prepared: value.reserve.prepared.clone(),
        pre_final_request_sha256: value.reserve.pre_final_acceptance_request_sha256.clone(),
        accepted_identity_exchange: value.reserve.accepted_identity_exchange.clone(),
        execution_reservation_id: reservation.reservation_id.clone(),
        execution_reservation_token: reservation.token,
        final_revoke_exchange: final_exchange,
    }
}

fn test_config() -> crate::host_config::VerifiedHostConfig {
    crate::host_config::VerifiedHostConfig {
        document: crate::gateway_peer_response_config::trust(),
        response_signing_key: crate::gateway_peer_response_identity::key(6),
        management_projection_signing_key: crate::gateway_peer_response_identity::key(7),
        revocation_execution_reservation_signing_key: crate::gateway_peer_response_identity::key(
            12,
        ),
    }
}
