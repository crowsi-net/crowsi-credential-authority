use crowsi_credential_authority_contracts::{
    EndpointManagementEnvelopeV2, EndpointManagementEvidenceV2, EndpointPreparedOperationV2,
    ManagementCommandV2, ManagementOperationV2, ManagementProjectionV2, SignedAuthorityExchangeV1,
};

use crate::{
    HostError,
    management_v2_journal::ManagementJournalV2,
    management_v2_record::{DurableResponseV1, ManagementLedgerV2},
};

pub(crate) struct MutationRecovery {
    pub(crate) owner_ref: String,
    pub(crate) accepted_snapshot_revision: u64,
    pub(crate) current_snapshot_revision: u64,
    pub(crate) accepted_generation_head: u64,
    pub(crate) current_generation_head: u64,
    pub(crate) identity_exchange: SignedAuthorityExchangeV1,
    pub(crate) original_response: ManagementProjectionV2,
}

impl ManagementJournalV2 {
    pub(crate) fn mutation_recovery_view(
        &self,
        envelope: &EndpointManagementEnvelopeV2,
        peer: &str,
        now: u64,
    ) -> Result<Option<MutationRecovery>, HostError> {
        if !crate::management_v2_command::historic_mutation(&envelope.browser_request.command) {
            return Ok(None);
        }
        let (identity_exchange, prepared) = evidence(&envelope.evidence)?;
        let operation_id = operation_id(&envelope.browser_request.command, prepared)?;
        let owner = prepared.opaque_owner_ref.clone();
        let request_digest = crate::management_v2_journal_policy::envelope_digest(envelope)?;
        let identity_digest =
            crate::management_v2_journal_policy::exchange_digest(identity_exchange)?;
        self.locked(&owner, || {
            let ledger =
                crate::management_v2_journal_io::read(&self.root, &self.anchor_root, &owner)?;
            recover(
                &ledger,
                envelope,
                identity_exchange,
                prepared,
                operation_id,
                peer,
                &request_digest,
                &identity_digest,
                now,
            )
        })
    }
}

fn evidence(
    value: &EndpointManagementEvidenceV2,
) -> Result<(&SignedAuthorityExchangeV1, &EndpointPreparedOperationV2), HostError> {
    match value {
        EndpointManagementEvidenceV2::SourceOptions {
            identity_exchange,
            prepared,
            ..
        }
        | EndpointManagementEvidenceV2::SourceApprove {
            identity_exchange,
            prepared,
            ..
        }
        | EndpointManagementEvidenceV2::ActorOptions {
            identity_exchange,
            prepared,
            ..
        }
        | EndpointManagementEvidenceV2::TargetApprove {
            identity_exchange,
            prepared,
            ..
        }
        | EndpointManagementEvidenceV2::IndependentApprove {
            identity_exchange,
            prepared,
            ..
        }
        | EndpointManagementEvidenceV2::Reconcile {
            identity_exchange,
            prepared,
            ..
        } => Ok((identity_exchange, prepared)),
        EndpointManagementEvidenceV2::Passive { .. }
        | EndpointManagementEvidenceV2::Cancel { .. } => Err(HostError::RequestInvalid),
    }
}

fn operation_id<'a>(
    command: &'a ManagementCommandV2,
    prepared: &'a EndpointPreparedOperationV2,
) -> Result<&'a str, HostError> {
    let operation = match command {
        ManagementCommandV2::SourceOptions { .. } => &prepared.operation_id,
        ManagementCommandV2::SourceApprove { operation_id, .. }
        | ManagementCommandV2::TargetOptions { operation_id, .. }
        | ManagementCommandV2::TargetApprove { operation_id, .. }
        | ManagementCommandV2::ApprovalOptions { operation_id, .. }
        | ManagementCommandV2::ApproveRevocation { operation_id, .. }
        | ManagementCommandV2::Reconcile { operation_id, .. } => operation_id,
        _ => return Err(HostError::RequestInvalid),
    };
    (operation == &prepared.operation_id)
        .then_some(operation.as_str())
        .ok_or(HostError::StateInvalid)
}

include!("management_v2_journal_mutation_recovery_validation.rs");
