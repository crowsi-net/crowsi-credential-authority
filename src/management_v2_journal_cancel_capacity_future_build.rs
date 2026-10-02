use super::{HostError, VerifiedHostConfig};
use crowsi_credential_authority_contracts::{
    ENDPOINT_REVOCATION_EXECUTION_CANCEL_REQUEST_SCHEMA, EndpointManagementEnvelopeV2,
    EndpointPreparedOperationV2, EndpointRevocationExecutionCancelRequestV1, ManagementOperationV2,
    SignedAuthorityExchangeV1,
};

const CAPACITY_TIME: u64 = u64::MAX - 240;

pub(super) fn initial_self(
    value: &crate::management_v2_record::RevocationFinalizationAcceptanceV1,
    prepared: &EndpointPreparedOperationV2,
    operation: &ManagementOperationV2,
    config: &VerifiedHostConfig,
    envelope: &EndpointManagementEnvelopeV2,
) -> Result<crate::management_v2_record::RevocationFinalizationAcceptanceV1, HostError> {
    let request = cancel_request(
        prepared,
        operation,
        &value.source_approve_request_sha256,
        &value.begin_exchange,
        envelope,
    );
    let mut result = value.clone();
    result.execution_cancellation = Some(full_cancellation(config, &request, operation)?);
    Ok(terminal_self(result))
}

pub(super) fn initial_independent(
    value: &crate::management_v2_record::IndependentRevocationFinalizationAcceptanceV1,
    prepared: &EndpointPreparedOperationV2,
    operation: &ManagementOperationV2,
    config: &VerifiedHostConfig,
    envelope: &EndpointManagementEnvelopeV2,
) -> Result<crate::management_v2_record::IndependentRevocationFinalizationAcceptanceV1, HostError> {
    let request = cancel_request(
        prepared,
        operation,
        &value.pre_final_request_sha256,
        &value.begin_exchange,
        envelope,
    );
    let mut result = value.clone();
    result.execution_cancellation = Some(full_cancellation(config, &request, operation)?);
    Ok(terminal_independent(result))
}

fn cancel_request(
    prepared: &EndpointPreparedOperationV2,
    operation: &ManagementOperationV2,
    pre_final_digest: &str,
    begin_exchange: &SignedAuthorityExchangeV1,
    cancel_envelope: &EndpointManagementEnvelopeV2,
) -> EndpointRevocationExecutionCancelRequestV1 {
    EndpointRevocationExecutionCancelRequestV1 {
        schema: ENDPOINT_REVOCATION_EXECUTION_CANCEL_REQUEST_SCHEMA.into(),
        request_id: maximum_id(3),
        operation_id: operation.operation_id.clone(),
        expected_cancelled_state_revision: operation.state_revision,
        pre_final_acceptance_request_sha256: pre_final_digest.into(),
        cancel_envelope: cancel_envelope.clone(),
        prepared: prepared.clone(),
        begin_exchange: begin_exchange.clone(),
    }
}

fn maximum_config(value: &VerifiedHostConfig) -> VerifiedHostConfig {
    let mut document = value.document.clone();
    document.management_projection_issuer = maximum_escaped(256);
    document.management_audience = maximum_escaped(128);
    document.management_projection_key_id = maximum_id(0);
    document.revocation_execution_reservation_key_id = maximum_id(1);
    document.identity_response_key_id = maximum_id(2);
    document.revocation_execution_reservation_config_generation = u64::MAX;
    document.minimum_identity_config_generation = u64::MAX;
    VerifiedHostConfig {
        document,
        response_signing_key: value.response_signing_key.clone(),
        management_projection_signing_key: value.management_projection_signing_key.clone(),
        revocation_execution_reservation_signing_key: value
            .revocation_execution_reservation_signing_key
            .clone(),
    }
}

fn maximum_id(marker: usize) -> String {
    let mut value = vec![b'\\'; 128];
    value[marker] = b'"';
    value.into_iter().map(char::from).collect()
}

fn maximum_escaped(bytes: usize) -> String {
    "\\".repeat(bytes)
}

fn terminal_self(
    mut value: crate::management_v2_record::RevocationFinalizationAcceptanceV1,
) -> crate::management_v2_record::RevocationFinalizationAcceptanceV1 {
    value.cancellation_slot_reserved = false;
    value.cancellation_cleanup_completed = true;
    value.cancellation_cleanup_delivery_completed = true;
    value.cancellation_recovery_reservation_bytes = 0;
    value
}

fn terminal_independent(
    mut value: crate::management_v2_record::IndependentRevocationFinalizationAcceptanceV1,
) -> crate::management_v2_record::IndependentRevocationFinalizationAcceptanceV1 {
    value.cancellation_slot_reserved = false;
    value.cancellation_cleanup_completed = true;
    value.cancellation_cleanup_delivery_completed = true;
    value.cancellation_recovery_reservation_bytes = 0;
    value
}
