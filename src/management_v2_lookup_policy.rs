use crowsi_credential_authority_contracts::{
    EndpointPreparedLookupPhaseV1 as Phase, ManagementOperationState as S, RequiredActorRole as R,
};

use crate::management_v2_record::ManagementRecordV2;

pub(crate) fn allowed(
    phase: Phase,
    record: &ManagementRecordV2,
    actor: &str,
    session: &str,
) -> bool {
    match phase {
        Phase::Target => {
            record.operation.state == S::AwaitingTarget
                && record.operation.actor.role == R::TargetDevice
                && record.operation.actor.required_actor_device_ref.as_deref() == Some(actor)
                && transfer_target(record).is_some_and(|target| target == actor)
        }
        Phase::Approval => approval(record, actor),
        Phase::Cancel => {
            matches!(
                record.operation.state,
                S::AwaitingSourceUv
                    | S::AwaitingTarget
                    | S::AwaitingTargetUv
                    | S::AwaitingIndependentApproval
                    | S::AwaitingApprovalUv
                    | S::AwaitingRevocationFinal
            ) && actor == record.prepared.source_device_ref
                && (record.operation.state != S::AwaitingRevocationFinal
                    || session == record.prepared.source_session_ref)
        }
        Phase::Reconcile => {
            record.operation.state == S::Unknown
                && record.operation.actor.role == R::ReconcileOnly
                && reconcile(record, actor)
        }
    }
}

fn approval(record: &ManagementRecordV2, actor: &str) -> bool {
    record.operation.state == S::AwaitingIndependentApproval
        && record.operation.actor.role == R::IndependentApproval
        && record
            .prepared
            .revocation
            .as_ref()
            .is_some_and(|requirements| {
                actor != record.prepared.source_device_ref
                    && actor != requirements.target_device_ref
                    && record
                        .operation
                        .actor
                        .required_actor_device_ref
                        .as_deref()
                        .map_or_else(
                            || {
                                record.operation.actor.required_approval_authority_ref
                                    == requirements.required_approval_authority_ref
                            },
                            |required| required == actor,
                        )
            })
}

fn transfer_target(record: &ManagementRecordV2) -> Option<&str> {
    match &record.prepared.intent {
        crowsi_credential_authority_contracts::ManagementIntentV2::DeviceTransfer {
            target_device_ref,
            ..
        } => Some(target_device_ref),
        _ => None,
    }
}

fn reconcile(record: &ManagementRecordV2, actor: &str) -> bool {
    if matches!(
        record.prepared.intent,
        crowsi_credential_authority_contracts::ManagementIntentV2::DeviceTransfer { .. }
    ) {
        true
    } else {
        record.prepared.revocation.as_ref().is_some_and(|value| {
            actor != record.prepared.source_device_ref && actor != value.target_device_ref
        })
    }
}
