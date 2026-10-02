fn binding(
    command: &crowsi_credential_authority_contracts::ManagementCommandV2,
    prepared: &crowsi_credential_authority_contracts::EndpointPreparedOperationV2,
    operation: &crowsi_credential_authority_contracts::ManagementOperationV2,
) -> bool {
    operation_prepared(operation, prepared) && transition(command, prepared, operation)
}

fn transition(
    command: &crowsi_credential_authority_contracts::ManagementCommandV2,
    prepared: &crowsi_credential_authority_contracts::EndpointPreparedOperationV2,
    operation: &crowsi_credential_authority_contracts::ManagementOperationV2,
) -> bool {
    use crowsi_credential_authority_contracts::{
        ManagementCommandV2 as C, ManagementOperationState as S,
    };
    match command {
        C::SourceOptions { intent } => {
            intent == &prepared.intent
                && operation.state == S::AwaitingSourceUv
                && operation.state_revision == 1
        }
        C::SourceApprove {
            expected_state_revision,
            ..
        } => {
            expected_state_revision.checked_add(1) == Some(operation.state_revision)
                && source_approved(prepared, operation.state)
        }
        C::TargetOptions {
            expected_state_revision,
            ..
        } => transition_to(operation, *expected_state_revision, S::AwaitingTargetUv),
        C::ApprovalOptions {
            expected_state_revision,
            ..
        } => transition_to(operation, *expected_state_revision, S::AwaitingApprovalUv),
        C::TargetApprove {
            expected_state_revision,
            ..
        }
        | C::ApproveRevocation {
            expected_state_revision,
            ..
        }
        | C::Reconcile {
            expected_state_revision,
            ..
        } => transition_to(operation, *expected_state_revision, S::Unknown),
        C::Snapshot { .. } | C::PendingList { .. } | C::Cancel { .. } => false,
    }
}

fn source_approved(
    prepared: &crowsi_credential_authority_contracts::EndpointPreparedOperationV2,
    state: crowsi_credential_authority_contracts::ManagementOperationState,
) -> bool {
    use crowsi_credential_authority_contracts::{
        ManagementIntentV2 as I, ManagementOperationState as S,
    };
    match &prepared.intent {
        I::DeviceTransfer { .. } => state == S::AwaitingTarget,
        I::DeviceRevocation { .. } | I::SessionRevocation { .. } => {
            prepared
                .revocation
                .as_ref()
                .is_some_and(|value| value.target_device_ref != prepared.source_device_ref)
                && state == S::AwaitingIndependentApproval
        }
    }
}

fn transition_to(
    operation: &crowsi_credential_authority_contracts::ManagementOperationV2,
    previous: u64,
    state: crowsi_credential_authority_contracts::ManagementOperationState,
) -> bool {
    previous.checked_add(1) == Some(operation.state_revision) && operation.state == state
}

include!("gateway_peer_response_mutation_operation.rs");
