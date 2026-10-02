use crowsi_credential_authority_contracts::ManagementOperationState as State;

use crate::{
    HostError,
    management_v2_record::{ManagementLedgerV2, ManagementRecordV2, ManagementTombstoneV2},
};

const MAX_UNACKNOWLEDGED_PER_OWNER: usize = 4;
const MAX_UNACKNOWLEDGED_GLOBAL: usize = 256;

pub(crate) fn reserve(
    root: &std::path::Path,
    ledger: &ManagementLedgerV2,
    current: &ManagementRecordV2,
    next: &mut ManagementRecordV2,
) -> Result<(), HostError> {
    if current.operation.state != State::AwaitingRevocationFinal
        || next.operation.state != State::Cancelled
    {
        return Ok(());
    }
    if unacknowledged_records(ledger) + unacknowledged_tombstones(ledger)
        >= MAX_UNACKNOWLEDGED_PER_OWNER
        || global_unacknowledged(root)? >= MAX_UNACKNOWLEDGED_GLOBAL
    {
        return Err(HostError::StateInvalid);
    }
    let mut acceptance = acceptance_mut(next).ok_or(HostError::StateInvalid)?;
    if !acceptance.can_reserve() {
        return Err(HostError::StateInvalid);
    }
    acceptance.set_slot();
    Ok(())
}

include!("management_v2_journal_cancel_slot_global.rs");

fn unacknowledged_records(value: &ManagementLedgerV2) -> usize {
    value
        .records
        .iter()
        .filter(|item| unacknowledged_record(item))
        .count()
}

fn unacknowledged_tombstones(value: &ManagementLedgerV2) -> usize {
    value
        .tombstones
        .iter()
        .filter(|item| unacknowledged_tombstone(item))
        .count()
}

pub(crate) fn unacknowledged_record(value: &ManagementRecordV2) -> bool {
    value
        .revocation_finalization
        .as_deref()
        .is_some_and(slot_self)
        || value
            .independent_revocation_finalization
            .as_deref()
            .is_some_and(slot_independent)
}

pub(crate) fn unacknowledged_tombstone(value: &ManagementTombstoneV2) -> bool {
    value
        .revocation_finalization
        .as_deref()
        .is_some_and(slot_self)
        || value
            .independent_revocation_finalization
            .as_deref()
            .is_some_and(slot_independent)
}

fn slot_self(value: &crate::management_v2_record::RevocationFinalizationAcceptanceV1) -> bool {
    value.cancellation_slot_reserved && !value.cancellation_cleanup_delivery_completed
}

fn slot_independent(
    value: &crate::management_v2_record::IndependentRevocationFinalizationAcceptanceV1,
) -> bool {
    value.cancellation_slot_reserved && !value.cancellation_cleanup_delivery_completed
}

struct AcceptanceMut<'a> {
    self_value: Option<&'a mut crate::management_v2_record::RevocationFinalizationAcceptanceV1>,
    independent:
        Option<&'a mut crate::management_v2_record::IndependentRevocationFinalizationAcceptanceV1>,
}

impl AcceptanceMut<'_> {
    fn can_reserve(&self) -> bool {
        self.self_value
            .as_deref()
            .is_some_and(reservable_self)
            || self
                .independent
                .as_deref()
                .is_some_and(reservable_independent)
    }

    fn set_slot(&mut self) {
        if let Some(value) = &mut self.self_value {
            value.cancellation_slot_reserved = true;
        }
        if let Some(value) = &mut self.independent {
            value.cancellation_slot_reserved = true;
        }
    }
}

fn reservable_self(
    value: &crate::management_v2_record::RevocationFinalizationAcceptanceV1,
) -> bool {
    value.execution_reservation.is_none()
        && !value.cancellation_slot_reserved
        && !value.cancellation_cleanup_completed
        && !value.cancellation_cleanup_delivery_completed
}

fn reservable_independent(
    value: &crate::management_v2_record::IndependentRevocationFinalizationAcceptanceV1,
) -> bool {
    value.execution_reservation.is_none()
        && !value.cancellation_slot_reserved
        && !value.cancellation_cleanup_completed
        && !value.cancellation_cleanup_delivery_completed
}

fn acceptance_mut(value: &mut ManagementRecordV2) -> Option<AcceptanceMut<'_>> {
    if let Some(item) = &mut value.revocation_finalization {
        return Some(AcceptanceMut {
            self_value: Some(item),
            independent: None,
        });
    }
    value
        .independent_revocation_finalization
        .as_mut()
        .map(|item| AcceptanceMut {
            self_value: None,
            independent: Some(item),
        })
}
