fn reserve_self(
    value: &mut crate::management_v2_record::RevocationFinalizationAcceptanceV1,
    mut future: crate::management_v2_record::RevocationFinalizationAcceptanceV1,
    revision_growth: u64,
) -> Result<(), HostError> {
    value.cancellation_recovery_reservation_bytes = 0;
    future.cancellation_recovery_reservation_bytes = 0;
    value.cancellation_recovery_reservation_bytes = serialized_len(&future)?
        .checked_sub(serialized_len(value)?)
        .and_then(|item| item.checked_add(revision_growth))
        .ok_or(HostError::StateInvalid)?;
    (value.cancellation_recovery_reservation_bytes > 0)
        .then_some(())
        .ok_or(HostError::StateInvalid)
}

fn reserve_independent(
    value: &mut crate::management_v2_record::IndependentRevocationFinalizationAcceptanceV1,
    mut future: crate::management_v2_record::IndependentRevocationFinalizationAcceptanceV1,
    revision_growth: u64,
) -> Result<(), HostError> {
    value.cancellation_recovery_reservation_bytes = 0;
    future.cancellation_recovery_reservation_bytes = 0;
    value.cancellation_recovery_reservation_bytes = serialized_len(&future)?
        .checked_sub(serialized_len(value)?)
        .and_then(|item| item.checked_add(revision_growth))
        .ok_or(HostError::StateInvalid)?;
    (value.cancellation_recovery_reservation_bytes > 0)
        .then_some(())
        .ok_or(HostError::StateInvalid)
}

mod future {
    include!("management_v2_journal_cancel_capacity_future_build.rs");
    include!("management_v2_journal_cancel_capacity_future_phases.rs");
    include!("management_v2_journal_cancel_capacity_future_exchange.rs");
}
