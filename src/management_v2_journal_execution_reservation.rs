use crowsi_credential_authority_contracts::{
    EndpointRevocationExecutionReservationV1, EndpointRevocationExecutionReserveRequestV1,
    ManagementOperationState,
};

use crate::{
    HostError, host_config::VerifiedHostConfig, management_v2_journal::ManagementJournalV2,
    management_v2_journal_update::EvidenceUse,
    management_v2_record::RevocationExecutionReservationAcceptanceV1,
};

impl ManagementJournalV2 {
    pub(crate) fn accept_execution_reservation(
        &self,
        request: &EndpointRevocationExecutionReserveRequestV1,
        peer: &str,
        config: &VerifiedHostConfig,
        evidence: &[EvidenceUse<'_>],
        now: u64,
    ) -> Result<(u64, EndpointRevocationExecutionReservationV1), HostError> {
        let owner = &request.prepared.opaque_owner_ref;
        self.locked(owner, || {
            let mut ledger =
                crate::management_v2_journal_io::read(&self.root, &self.anchor_root, owner)?;
            let index = ledger
                .records
                .iter()
                .position(|item| item.operation.operation_id == request.operation_id)
                .ok_or(HostError::StateInvalid)?;
            pre_final_exact(&ledger.records[index], request, peer)?;
            let next_revision = crate::management_v2_journal_policy::next(ledger.revision)?;
            let mut operation = ledger.records[index].operation.clone();
            operation.state = ManagementOperationState::RevocationExecutionReserved;
            operation.state_revision =
                crate::management_v2_journal_policy::next(operation.state_revision)?;
            operation.actor = crate::management_v2_state::reconcile_actor();
            operation.webauthn_options = None;
            operation.reason = None;
            let reservation = crate::management_v2_execution_reservation_build::build(
                config,
                request,
                operation.clone(),
                next_revision,
                now,
            )?;
            let acceptance = stored(config, request, &reservation, now)?;
            let record = &mut ledger.records[index];
            record.operation = operation;
            record.authority_config_generation = record.authority_config_generation.max(
                request
                    .reservation_identity_exchange
                    .response
                    .config_generation,
            );
            store(record, request, acceptance)?;
            let record_generation = record.authority_config_generation;
            if !crate::management_v2_operation_conflict::available_replacement(
                &ledger,
                &ledger.records[index],
            ) {
                return Err(HostError::StateInvalid);
            }
            crate::management_v2_evidence_use::consume(&mut ledger, evidence, now)?;
            ledger.authority_config_generation_head = ledger
                .authority_config_generation_head
                .max(record_generation);
            ledger.revision = next_revision;
            crate::management_v2_journal_io::write(&self.root, &self.anchor_root, owner, &ledger)?;
            Ok((next_revision, reservation))
        })
    }

    pub(crate) fn execution_reservation_view(
        &self,
        request: &EndpointRevocationExecutionReserveRequestV1,
        peer: &str,
    ) -> Result<Option<(u64, EndpointRevocationExecutionReservationV1)>, HostError> {
        let owner = &request.prepared.opaque_owner_ref;
        self.locked(owner, || {
            let ledger =
                crate::management_v2_journal_io::read(&self.root, &self.anchor_root, owner)?;
            let record = ledger
                .records
                .iter()
                .find_map(|item| reservation_from_record(item, request, peer));
            let tombstone = ledger
                .tombstones
                .iter()
                .find_map(|item| reservation_from_tombstone(item, request, peer));
            Ok(record.or(tombstone).map(|value| (ledger.revision, value)))
        })
    }
}

include!("management_v2_journal_execution_reservation_support.rs");
