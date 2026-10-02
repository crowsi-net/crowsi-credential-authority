use crate::{
    HostError, management_v2_handler::ManagementV2Handler,
    management_v2_provider_acceptance::ProviderEvidenceAcceptanceV1,
    management_v2_record::ManagementRecordV2,
};

impl ManagementV2Handler {
    pub(crate) fn start_revocation(
        &self,
        mut record: ManagementRecordV2,
    ) -> Result<ManagementRecordV2, HostError> {
        let saga = record
            .revocation_saga
            .as_ref()
            .ok_or(HostError::StateInvalid)?;
        if saga.started {
            return Ok(record);
        }
        let prior = record.operation.state_revision;
        let saga = record
            .revocation_saga
            .as_mut()
            .ok_or(HostError::StateInvalid)?;
        saga.started = true;
        record.operation.state_revision = next(prior)?;
        self.journal.replace(prior, record)
    }

    pub(crate) fn persist_rotation_acceptance(
        &self,
        mut record: ManagementRecordV2,
        index: usize,
        acceptance: ProviderEvidenceAcceptanceV1,
    ) -> Result<ManagementRecordV2, HostError> {
        let prior = record.operation.state_revision;
        let rotation = record
            .revocation_saga
            .as_mut()
            .and_then(|saga| saga.rotations.get_mut(index))
            .ok_or(HostError::StateInvalid)?;
        if rotation.authority_applied {
            return Err(HostError::StateInvalid);
        }
        if let Some(prior_acceptance) = rotation.provider_acceptance.take() {
            archive(rotation, prior_acceptance)?;
        }
        rotation.provider_acceptance = Some(acceptance);
        rotation.provider_reconcile_request_id = None;
        record.operation.state_revision = next(prior)?;
        self.journal.replace(prior, record)
    }

    pub(crate) fn mark_rotation_attempted(
        &self,
        mut record: ManagementRecordV2,
        index: usize,
    ) -> Result<ManagementRecordV2, HostError> {
        let prior = record.operation.state_revision;
        let rotation = record
            .revocation_saga
            .as_mut()
            .and_then(|saga| saga.rotations.get_mut(index))
            .ok_or(HostError::StateInvalid)?;
        if rotation.attempted {
            return Err(HostError::StateInvalid);
        }
        rotation.attempted = true;
        record.operation.state_revision = next(prior)?;
        self.journal.replace(prior, record)
    }

    pub(crate) fn begin_rotation_reconciliation(
        &self,
        mut record: ManagementRecordV2,
        index: usize,
    ) -> Result<ManagementRecordV2, HostError> {
        let prior = record.operation.state_revision;
        let operation_id = record.operation.operation_id.clone();
        let rotation = record
            .revocation_saga
            .as_mut()
            .and_then(|saga| saga.rotations.get_mut(index))
            .ok_or(HostError::StateInvalid)?;
        if rotation.provider_reconcile_request_id.is_some() {
            return Ok(record);
        }
        rotation.reconcile_sequence = next(rotation.reconcile_sequence)?;
        rotation.provider_reconcile_request_id =
            Some(crate::management_v2_revocation_plan::reconcile_request(
                &operation_id,
                &rotation.credential_ref,
                rotation.attempt_number,
                rotation.reconcile_sequence,
            ));
        record.operation.state_revision = next(prior)?;
        self.journal.replace(prior, record)
    }
}

include!("management_v2_revocation_rotation_terminal.rs");

fn archive(
    rotation: &mut crate::management_v2_record::RevocationRotationV2,
    acceptance: ProviderEvidenceAcceptanceV1,
) -> Result<(), HostError> {
    crate::management_v2_provider_progress::append(
        "rotation",
        &mut rotation.prior_acceptances,
        &mut rotation.prior_acceptance_count,
        &mut rotation.prior_acceptance_digest_sha256,
        acceptance,
    )
}

fn next(value: u64) -> Result<u64, HostError> {
    value.checked_add(1).ok_or(HostError::StateInvalid)
}
