use crowsi_credential_authority_contracts::{
    ENDPOINT_REVOCATION_EXECUTION_CANCEL_CLEANUP_COMPLETE_REQUEST_SCHEMA,
    ENDPOINT_REVOCATION_EXECUTION_CANCEL_FINALIZE_REQUEST_SCHEMA,
    EndpointRevocationExecutionCancelCleanupCompleteRequestV1,
    EndpointRevocationExecutionCancelFinalizeRequestV1,
};

pub(super) fn after_cancellation_self(
    value: &crate::management_v2_record::RevocationFinalizationAcceptanceV1,
    prepared: &EndpointPreparedOperationV2,
    operation: &ManagementOperationV2,
    config: &VerifiedHostConfig,
) -> Result<crate::management_v2_record::RevocationFinalizationAcceptanceV1, HostError> {
    let mut result = value.clone();
    result.execution_cancellation = Some(complete_existing(
        value.execution_cancellation.as_ref(),
        prepared,
        operation,
        config,
    )?);
    Ok(terminal_self(result))
}

pub(super) fn after_cancellation_independent(
    value: &crate::management_v2_record::IndependentRevocationFinalizationAcceptanceV1,
    prepared: &EndpointPreparedOperationV2,
    operation: &ManagementOperationV2,
    config: &VerifiedHostConfig,
) -> Result<crate::management_v2_record::IndependentRevocationFinalizationAcceptanceV1, HostError> {
    let mut result = value.clone();
    result.execution_cancellation = Some(complete_existing(
        value.execution_cancellation.as_ref(),
        prepared,
        operation,
        config,
    )?);
    Ok(terminal_independent(result))
}

pub(super) fn after_cleanup_self(
    value: &crate::management_v2_record::RevocationFinalizationAcceptanceV1,
    prepared: &EndpointPreparedOperationV2,
    operation: &ManagementOperationV2,
    config: &VerifiedHostConfig,
) -> Result<crate::management_v2_record::RevocationFinalizationAcceptanceV1, HostError> {
    let mut result = value.clone();
    result.execution_cancellation = Some(complete_delivery(
        value.execution_cancellation.as_ref(),
        prepared,
        operation,
        config,
    )?);
    Ok(terminal_self(result))
}

pub(super) fn after_cleanup_independent(
    value: &crate::management_v2_record::IndependentRevocationFinalizationAcceptanceV1,
    prepared: &EndpointPreparedOperationV2,
    operation: &ManagementOperationV2,
    config: &VerifiedHostConfig,
) -> Result<crate::management_v2_record::IndependentRevocationFinalizationAcceptanceV1, HostError> {
    let mut result = value.clone();
    result.execution_cancellation = Some(complete_delivery(
        value.execution_cancellation.as_ref(),
        prepared,
        operation,
        config,
    )?);
    Ok(terminal_independent(result))
}

fn full_cancellation(
    config: &VerifiedHostConfig,
    request: &crowsi_credential_authority_contracts::EndpointRevocationExecutionCancelRequestV1,
    operation: &ManagementOperationV2,
) -> Result<crate::management_v2_record::RevocationExecutionCancellationAcceptanceV1, HostError> {
    let max = maximum_config(config);
    let cancellation = crate::management_v2_execution_cancellation_build::build(
        &max,
        request,
        operation.clone(),
        u64::MAX,
        CAPACITY_TIME,
    )?;
    let value = cancellation_acceptance(&max, request, cancellation);
    complete_existing(Some(&value), &request.prepared, operation, config)
}

fn complete_existing(
    value: Option<&crate::management_v2_record::RevocationExecutionCancellationAcceptanceV1>,
    prepared: &EndpointPreparedOperationV2,
    operation: &ManagementOperationV2,
    config: &VerifiedHostConfig,
) -> Result<crate::management_v2_record::RevocationExecutionCancellationAcceptanceV1, HostError> {
    let mut result = value.cloned().ok_or(HostError::StateInvalid)?;
    let cancellation = result.cancellation.as_ref();
    let exchange = maximum_cancel_exchange(
        cancellation,
        &result.cancellation_request.begin_exchange.response.key_id,
    )?;
    let request = EndpointRevocationExecutionCancelFinalizeRequestV1 {
        schema: ENDPOINT_REVOCATION_EXECUTION_CANCEL_FINALIZE_REQUEST_SCHEMA.into(),
        request_id: maximum_id(4),
        operation_id: operation.operation_id.clone(),
        cancellation_request: Box::new(result.cancellation_request.as_ref().clone()),
        cancellation: Box::new(cancellation.clone()),
        cancel_pending_exchange: exchange.clone(),
    };
    let max = maximum_config(config);
    let cleanup = crate::management_v2_execution_cancellation_cleanup_build::build(
        &max,
        &request,
        operation.clone(),
        u64::MAX,
        CAPACITY_TIME,
    )?;
    set_cleanup(&mut result, request, cleanup, exchange, &max);
    complete_delivery(Some(&result), prepared, operation, config)
}

include!("management_v2_journal_cancel_capacity_future_delivery.rs");
