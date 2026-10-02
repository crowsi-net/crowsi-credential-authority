fn acceptances(
    value: &crate::management_v2_record::ManagementLedgerV2,
    location: Location,
) -> (
    Option<&crate::management_v2_record::RevocationFinalizationAcceptanceV1>,
    Option<&crate::management_v2_record::IndependentRevocationFinalizationAcceptanceV1>,
) {
    match location {
        Location::Record(index) => (
            value.records[index].revocation_finalization.as_deref(),
            value.records[index]
                .independent_revocation_finalization
                .as_deref(),
        ),
        Location::Tombstone(index) => (
            value.tombstones[index].revocation_finalization.as_deref(),
            value.tombstones[index]
                .independent_revocation_finalization
                .as_deref(),
        ),
    }
}

fn slot_self(value: &crate::management_v2_record::RevocationFinalizationAcceptanceV1) -> bool {
    value.cancellation_slot_reserved
        && !value.cancellation_cleanup_completed
        && value.execution_reservation.is_none()
        && value.finalize_request.is_none()
        && value.final_revoke_exchange.is_none()
}

fn slot_independent(
    value: &crate::management_v2_record::IndependentRevocationFinalizationAcceptanceV1,
) -> bool {
    value.cancellation_slot_reserved
        && !value.cancellation_cleanup_completed
        && value.execution_reservation.is_none()
        && value.finalize_request.is_none()
        && value.final_revoke_exchange.is_none()
}
