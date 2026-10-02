use crowsi_credential_authority_contracts::{ManagementIntentV2, ManagementOperationState};
use ihat_identity_assertion_contracts::{AuthorityResult, ResponseOutcome};

use crate::{
    DeviceId, HostError, management_v2_handler::ManagementV2Handler,
    management_v2_record::ManagementRecordV2,
};

impl ManagementV2Handler {
    pub(crate) fn execute_revocation(
        &self,
        mut record: ManagementRecordV2,
        evidence: &[crate::management_v2_journal_update::EvidenceUse<'_>],
        now: u64,
    ) -> Result<ManagementRecordV2, HostError> {
        if record.operation.state != ManagementOperationState::Unknown {
            return Err(HostError::StateInvalid);
        }
        record = self.apply_local_revocation(record, now)?;
        let (advanced, complete) = self.advance_revocation_rotations(record, now)?;
        record = advanced;
        if !complete {
            return Ok(record);
        }
        let prior = record.operation.state_revision;
        crate::management_v2_revocation_state::completed(&mut record)?;
        self.journal.replace_consuming(prior, record, evidence, now)
    }

    fn apply_local_revocation(
        &self,
        mut record: ManagementRecordV2,
        now: u64,
    ) -> Result<ManagementRecordV2, HostError> {
        if record
            .revocation_saga
            .as_ref()
            .is_some_and(|value| value.local_revocation_applied)
        {
            return Ok(record);
        }
        let final_exchange = if let Some(value) = &record.independent_revocation_finalization {
            value
                .final_revoke_exchange
                .as_ref()
                .ok_or(HostError::EvidenceInvalid)?
                .clone()
        } else if let Some(value) = &record.independent_revocation_ceremony {
            value.final_revoke.clone()
        } else if let Some(value) = &record.revocation_finalization {
            value
                .final_revoke_exchange
                .as_ref()
                .ok_or(HostError::EvidenceInvalid)?
                .clone()
        } else {
            record
                .source_revocation_ceremony
                .as_ref()
                .and_then(|item| item.final_revoke.as_ref())
                .ok_or(HostError::EvidenceInvalid)?
                .clone()
        };
        let mut host = crate::management_v2_host_adapter::open(&self.core, &record, now)?;
        match &record.prepared.intent {
            ManagementIntentV2::DeviceRevocation {
                target_device_ref,
                expected_device_revocation_epoch,
                ..
            } => {
                let ResponseOutcome::Committed {
                    result: AuthorityResult::DeviceRevocation(identity),
                } = &final_exchange.response.outcome
                else {
                    return Err(HostError::EvidenceInvalid);
                };
                if identity.previous_device_epoch != *expected_device_revocation_epoch
                    || identity.current_device_epoch
                        != expected_device_revocation_epoch.saturating_add(1)
                {
                    return Err(HostError::EvidenceInvalid);
                }
                let target = DeviceId::parse(target_device_ref.clone())?;
                let receipt = host.adapter.apply_host_device_revocation(
                    &record.operation.operation_id,
                    &host.owner,
                    &target,
                    *expected_device_revocation_epoch,
                    identity.current_device_epoch,
                )?;
                let applied = receipt.previous_epoch() == identity.previous_device_epoch
                    && receipt.current_epoch() == identity.current_device_epoch;
                if !applied {
                    return Err(HostError::StateInvalid);
                }
                record
                    .revocation_saga
                    .as_mut()
                    .ok_or(HostError::StateInvalid)?
                    .local_revocation_applied = true;
            }
            ManagementIntentV2::SessionRevocation {
                target_session_ref,
                expected_session_revocation_epoch,
                ..
            } => {
                let ResponseOutcome::Committed {
                    result: AuthorityResult::Revocation(identity),
                } = &final_exchange.response.outcome
                else {
                    return Err(HostError::EvidenceInvalid);
                };
                if identity.previous_epoch != *expected_session_revocation_epoch
                    || identity.current_epoch != expected_session_revocation_epoch.saturating_add(1)
                {
                    return Err(HostError::EvidenceInvalid);
                }
                let receipt = host.adapter.apply_host_session_revocation(
                    &record.operation.operation_id,
                    &host.owner,
                    target_session_ref,
                    *expected_session_revocation_epoch,
                    identity.current_epoch,
                )?;
                let applied = receipt == (identity.previous_epoch, identity.current_epoch);
                if !applied {
                    return Err(HostError::StateInvalid);
                }
                record
                    .revocation_saga
                    .as_mut()
                    .ok_or(HostError::StateInvalid)?
                    .local_revocation_applied = true;
            }
            ManagementIntentV2::DeviceTransfer { .. } => return Err(HostError::OperationInvalid),
        }
        let prior = record.operation.state_revision;
        record.operation.state_revision = prior.checked_add(1).ok_or(HostError::StateInvalid)?;
        self.journal.replace(prior, record)
    }
}
