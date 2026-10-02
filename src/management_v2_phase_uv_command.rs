fn command(value: &ManagementCommandV2) -> Result<(&str, u64), HostError> {
    match value {
        ManagementCommandV2::TargetOptions {
            operation_id,
            expected_state_revision,
        }
        | ManagementCommandV2::ApprovalOptions {
            operation_id,
            expected_state_revision,
        } => Ok((operation_id, *expected_state_revision)),
        _ => Err(HostError::RequestInvalid),
    }
}

fn actor_phase(
    value: &ManagementCommandV2,
) -> Result<
    (
        ManagementOperationState,
        crowsi_credential_authority_contracts::EndpointPreparedLookupPhaseV1,
    ),
    HostError,
> {
    match value {
        ManagementCommandV2::TargetOptions { .. } => Ok((
            ManagementOperationState::AwaitingTarget,
            crowsi_credential_authority_contracts::EndpointPreparedLookupPhaseV1::Target,
        )),
        ManagementCommandV2::ApprovalOptions { .. } => Ok((
            ManagementOperationState::AwaitingIndependentApproval,
            crowsi_credential_authority_contracts::EndpointPreparedLookupPhaseV1::Approval,
        )),
        _ => Err(HostError::RequestInvalid),
    }
}
