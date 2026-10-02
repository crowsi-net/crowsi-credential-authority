fn phases_valid(value: &ManagementLedgerV2) -> bool {
    value.records.iter().all(record_phase_valid)
        && value.tombstones.iter().all(tombstone_phase_valid)
}

fn record_phase_valid(value: &ManagementRecordV2) -> bool {
    value
        .revocation_finalization
        .as_deref()
        .is_none_or(self_phase_valid)
        && value
            .independent_revocation_finalization
            .as_deref()
            .is_none_or(independent_phase_valid)
}

fn tombstone_phase_valid(value: &crate::management_v2_record::ManagementTombstoneV2) -> bool {
    value
        .revocation_finalization
        .as_deref()
        .is_none_or(self_phase_valid)
        && value
            .independent_revocation_finalization
            .as_deref()
            .is_none_or(independent_phase_valid)
}

fn self_phase_valid(
    value: &crate::management_v2_record::RevocationFinalizationAcceptanceV1,
) -> bool {
    reservation_phase(
        value.cancellation_slot_reserved,
        value.cancellation_cleanup_delivery_completed,
        value.cancellation_recovery_reservation_bytes,
    )
}

fn independent_phase_valid(
    value: &crate::management_v2_record::IndependentRevocationFinalizationAcceptanceV1,
) -> bool {
    reservation_phase(
        value.cancellation_slot_reserved,
        value.cancellation_cleanup_delivery_completed,
        value.cancellation_recovery_reservation_bytes,
    )
}

fn reservation_phase(slot: bool, delivered: bool, bytes: u64) -> bool {
    if delivered {
        !slot && bytes == 0
    } else if slot {
        bytes > 0
    } else {
        bytes == 0
    }
}
