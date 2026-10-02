use crowsi_credential_authority_contracts::EndpointManagementEnvelopeV2;

use crate::{
    HostError,
    host_config::VerifiedHostConfig,
    management_v2_record::{ManagementLedgerV2, ManagementRecordV2},
};

const MAX_LEDGER_BYTES: u64 = 16_777_216;
include!("management_v2_journal_cancel_capacity_limit.rs");

pub(crate) fn needs_initial(value: &ManagementRecordV2) -> bool {
    value
        .revocation_finalization
        .as_ref()
        .is_some_and(|item| item.cancellation_slot_reserved)
        || value
            .independent_revocation_finalization
            .as_ref()
            .is_some_and(|item| item.cancellation_slot_reserved)
}

pub(crate) fn reserve_initial(
    record: &mut ManagementRecordV2,
    config: &VerifiedHostConfig,
    envelope: &EndpointManagementEnvelopeV2,
    ledger_revision: u64,
) -> Result<(), HostError> {
    let prepared = record.prepared.clone();
    let operation = record.operation.clone();
    if let Some(value) = &mut record.revocation_finalization {
        let future = future::initial_self(value, &prepared, &operation, config, envelope)?;
        return reserve_self(value, future, revision_growth(ledger_revision)?);
    }
    let value = record
        .independent_revocation_finalization
        .as_mut()
        .ok_or(HostError::StateInvalid)?;
    let future = future::initial_independent(value, &prepared, &operation, config, envelope)?;
    reserve_independent(value, future, revision_growth(ledger_revision)?)
}

pub(crate) fn high_water(value: &ManagementLedgerV2) -> Result<u64, HostError> {
    let serialized = serialized_len(value)?;
    let outstanding = outstanding(value)?;
    serialized
        .checked_add(outstanding)
        .filter(|item| *item <= maximum_ledger_bytes())
        .ok_or(HostError::StateInvalid)
}

pub(crate) fn valid(value: &ManagementLedgerV2) -> bool {
    phases_valid(value) && high_water(value).is_ok()
}

pub(crate) fn actualize_cancellation(
    value: &mut ManagementLedgerV2,
    operation_id: &str,
    config: &VerifiedHostConfig,
    prior_high_water: u64,
) -> Result<(), HostError> {
    let (prepared, operation) = context(value, operation_id)?;
    let revision_growth = revision_growth(value.revision)?;
    let acceptance = acceptance_mut(value, operation_id)?;
    match acceptance {
        AcceptanceMut::Source(item) => {
            let future = future::after_cancellation_self(item, &prepared, &operation, config)?;
            reserve_self(item, future, revision_growth)?;
        }
        AcceptanceMut::Independent(item) => {
            let future =
                future::after_cancellation_independent(item, &prepared, &operation, config)?;
            reserve_independent(item, future, revision_growth)?;
        }
    }
    bounded_advance(value, prior_high_water)
}

pub(crate) fn actualize_cleanup(
    value: &mut ManagementLedgerV2,
    operation_id: &str,
    config: &VerifiedHostConfig,
    prior_high_water: u64,
) -> Result<(), HostError> {
    let (prepared, operation) = context(value, operation_id)?;
    let revision_growth = revision_growth(value.revision)?;
    let acceptance = acceptance_mut(value, operation_id)?;
    match acceptance {
        AcceptanceMut::Source(item) => {
            let future = future::after_cleanup_self(item, &prepared, &operation, config)?;
            reserve_self(item, future, revision_growth)?;
        }
        AcceptanceMut::Independent(item) => {
            let future = future::after_cleanup_independent(item, &prepared, &operation, config)?;
            reserve_independent(item, future, revision_growth)?;
        }
    }
    bounded_advance(value, prior_high_water)
}

pub(crate) fn release(
    value: &mut ManagementLedgerV2,
    operation_id: &str,
    prior_high_water: u64,
) -> Result<(), HostError> {
    match acceptance_mut(value, operation_id)? {
        AcceptanceMut::Source(item) => item.cancellation_recovery_reservation_bytes = 0,
        AcceptanceMut::Independent(item) => item.cancellation_recovery_reservation_bytes = 0,
    }
    bounded_advance(value, prior_high_water)
}

fn bounded_advance(value: &ManagementLedgerV2, prior: u64) -> Result<(), HostError> {
    (high_water(value)? <= prior)
        .then_some(())
        .ok_or(HostError::StateInvalid)
}

fn revision_growth(current: u64) -> Result<u64, HostError> {
    serialized_len(&u64::MAX)?
        .checked_sub(serialized_len(&current)?)
        .ok_or(HostError::StateInvalid)
}

include!("management_v2_journal_cancel_capacity_access.rs");
include!("management_v2_journal_cancel_capacity_future.rs");
