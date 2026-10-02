use crowsi_credential_authority_contracts::{
    EndpointRevocationExecutionCancelRequestV1, EndpointRevocationExecutionCancellationV1,
};

use crate::{
    HostError, host_config::VerifiedHostConfig, management_v2_journal::ManagementJournalV2,
};

impl ManagementJournalV2 {
    pub(crate) fn accept_execution_cancellation(
        &self,
        request: &EndpointRevocationExecutionCancelRequestV1,
        peer: &str,
        config: &VerifiedHostConfig,
        now: u64,
    ) -> Result<(u64, EndpointRevocationExecutionCancellationV1), HostError> {
        let owner = &request.prepared.opaque_owner_ref;
        self.locked(owner, || {
            let mut ledger =
                crate::management_v2_journal_io::read(&self.root, &self.anchor_root, owner)?;
            let location = location(&ledger, request)?;
            exact(&ledger, location, request, peer)?;
            if let Some(stored) = stored(&ledger, location, request)? {
                return Ok((ledger.revision, stored));
            }
            let prior_high_water =
                crate::management_v2_journal_cancel_capacity::high_water(&ledger)?;
            let next = crate::management_v2_journal_policy::next(ledger.revision)?;
            let operation = operation(&ledger, location).clone();
            let cancellation = crate::management_v2_execution_cancellation_build::build(
                config, request, operation, next, now,
            )?;
            let acceptance = acceptance(config, request, &cancellation, now)?;
            store(&mut ledger, location, request, acceptance)?;
            ledger.revision = next;
            crate::management_v2_journal_cancel_capacity::actualize_cancellation(
                &mut ledger,
                &request.operation_id,
                config,
                prior_high_water,
            )?;
            crate::management_v2_journal_io::write(&self.root, &self.anchor_root, owner, &ledger)?;
            Ok((next, cancellation))
        })
    }
}

#[derive(Clone, Copy)]
enum Location {
    Record(usize),
    Tombstone(usize),
}

fn location(
    value: &crate::management_v2_record::ManagementLedgerV2,
    request: &EndpointRevocationExecutionCancelRequestV1,
) -> Result<Location, HostError> {
    if let Some(index) = value
        .records
        .iter()
        .position(|item| item.operation.operation_id == request.operation_id)
    {
        return Ok(Location::Record(index));
    }
    value
        .tombstones
        .iter()
        .position(|item| item.operation.operation_id == request.operation_id)
        .map(Location::Tombstone)
        .ok_or(HostError::StateInvalid)
}

fn operation(
    value: &crate::management_v2_record::ManagementLedgerV2,
    location: Location,
) -> &crowsi_credential_authority_contracts::ManagementOperationV2 {
    match location {
        Location::Record(index) => &value.records[index].operation,
        Location::Tombstone(index) => &value.tombstones[index].operation,
    }
}

include!("management_v2_journal_execution_cancellation_validation.rs");
include!("management_v2_journal_execution_cancellation_store.rs");
