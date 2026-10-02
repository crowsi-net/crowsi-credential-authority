use crowsi_credential_authority_contracts::{
    EndpointRevocationFinalizeRequestV1, ManagementOperationState,
};

use crate::{
    HostError,
    management_v2_journal::ManagementJournalV2,
    management_v2_record::{ManagementRecordV2, ManagementTombstoneV2},
};

pub(crate) enum FinalizationEntry {
    Record(Box<ManagementRecordV2>),
    Tombstone(Box<ManagementTombstoneV2>),
}

impl ManagementJournalV2 {
    pub(crate) fn accept_revocation_final(
        &self,
        request: &EndpointRevocationFinalizeRequestV1,
        peer_device: &str,
    ) -> Result<FinalizationEntry, HostError> {
        let owner = &request.prepared.opaque_owner_ref;
        self.locked(owner, || {
            let mut ledger =
                crate::management_v2_journal_io::read(&self.root, &self.anchor_root, owner)?;
            if let Some(record) = ledger
                .records
                .iter_mut()
                .find(|item| item.operation.operation_id == request.operation_id)
            {
                let changed = accept(
                    record,
                    request,
                    peer_device,
                    ledger.authority_config_generation_head,
                )?;
                let result = record.clone();
                if changed {
                    ledger.authority_config_generation_head = ledger
                        .authority_config_generation_head
                        .max(result.authority_config_generation);
                    ledger.revision = crate::management_v2_journal_policy::next(ledger.revision)?;
                    crate::management_v2_journal_io::write(
                        &self.root,
                        &self.anchor_root,
                        owner,
                        &ledger,
                    )?;
                }
                return Ok(FinalizationEntry::Record(Box::new(result)));
            }
            let tombstone = ledger
                .tombstones
                .iter()
                .find(|item| item.operation.operation_id == request.operation_id)
                .ok_or(HostError::StateInvalid)?;
            exact_tombstone(tombstone, request, peer_device)?;
            Ok(FinalizationEntry::Tombstone(Box::new(tombstone.clone())))
        })
    }

    pub(crate) fn finalization_view(
        &self,
        request: &EndpointRevocationFinalizeRequestV1,
        peer_device: &str,
    ) -> Result<(u64, FinalizationEntry), HostError> {
        let owner = &request.prepared.opaque_owner_ref;
        self.locked(owner, || {
            let ledger =
                crate::management_v2_journal_io::read(&self.root, &self.anchor_root, owner)?;
            if let Some(record) = ledger
                .records
                .iter()
                .find(|item| item.operation.operation_id == request.operation_id)
            {
                exact_record(record, request, peer_device)?;
                return Ok((
                    ledger.revision,
                    FinalizationEntry::Record(Box::new(record.clone())),
                ));
            }
            let tombstone = ledger
                .tombstones
                .iter()
                .find(|item| item.operation.operation_id == request.operation_id)
                .ok_or(HostError::StateInvalid)?;
            exact_tombstone(tombstone, request, peer_device)?;
            Ok((
                ledger.revision,
                FinalizationEntry::Tombstone(Box::new(tombstone.clone())),
            ))
        })
    }
}

fn accept(
    value: &mut ManagementRecordV2,
    request: &EndpointRevocationFinalizeRequestV1,
    peer: &str,
    generation_head: u64,
) -> Result<bool, HostError> {
    exact_base(value, request, peer)?;
    let acceptance = value
        .revocation_finalization
        .as_mut()
        .ok_or(HostError::StateInvalid)?;
    let request_digest = request_digest(request)?;
    if let (Some(stored_request), Some(stored_value), Some(stored_final)) = (
        &acceptance.finalize_request_sha256,
        &acceptance.finalize_request,
        &acceptance.final_revoke_exchange,
    ) {
        return (stored_request == &request_digest
            && stored_value.as_ref() == request
            && stored_final == &request.final_revoke_exchange
            && matches!(
                value.operation.state,
                ManagementOperationState::Unknown | ManagementOperationState::Completed
            ))
        .then_some(false)
        .ok_or(HostError::StateInvalid);
    }
    if value.operation.state != ManagementOperationState::RevocationExecutionReserved
        || value.operation.state_revision != request.expected_state_revision
        || value.operation.reconcile_digest.as_deref() != Some(&request.reconcile_digest)
        || acceptance.pre_final_state_revision != request.pre_final_state_revision
    {
        return Err(HostError::StateInvalid);
    }
    verify_new(acceptance, request)?;
    acceptance.finalize_request_sha256 = Some(request_digest);
    acceptance.finalize_request = Some(Box::new(request.clone()));
    acceptance.final_revoke_exchange = Some(request.final_revoke_exchange.clone());
    value.authority_config_generation = value
        .authority_config_generation
        .max(request.final_revoke_exchange.response.config_generation)
        .max(generation_head);
    value.operation.state_revision =
        crate::management_v2_journal_policy::next(value.operation.state_revision)?;
    value.operation.state = ManagementOperationState::Unknown;
    value.operation.reason =
        Some(crowsi_credential_authority_contracts::ManagementReasonCode::ProviderOutcomeUnknown);
    value.operation.actor = crate::management_v2_state::reconcile_actor();
    value.operation.webauthn_options = None;
    Ok(true)
}

include!("management_v2_journal_finalization_validation.rs");
