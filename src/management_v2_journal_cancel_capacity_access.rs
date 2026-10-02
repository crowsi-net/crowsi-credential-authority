enum AcceptanceMut<'a> {
    Source(&'a mut crate::management_v2_record::RevocationFinalizationAcceptanceV1),
    Independent(&'a mut crate::management_v2_record::IndependentRevocationFinalizationAcceptanceV1),
}

fn context(
    value: &ManagementLedgerV2,
    operation_id: &str,
) -> Result<
    (
        crowsi_credential_authority_contracts::EndpointPreparedOperationV2,
        crowsi_credential_authority_contracts::ManagementOperationV2,
    ),
    HostError,
> {
    if let Some(item) = value
        .records
        .iter()
        .find(|item| item.operation.operation_id == operation_id)
    {
        return Ok((item.prepared.clone(), item.operation.clone()));
    }
    value
        .tombstones
        .iter()
        .find(|item| item.operation.operation_id == operation_id)
        .map(|item| (item.prepared.clone(), item.operation.clone()))
        .ok_or(HostError::StateInvalid)
}

fn acceptance_mut<'a>(
    value: &'a mut ManagementLedgerV2,
    operation_id: &str,
) -> Result<AcceptanceMut<'a>, HostError> {
    if let Some(item) = value
        .records
        .iter_mut()
        .find(|item| item.operation.operation_id == operation_id)
    {
        return acceptance_record(item);
    }
    let item = value
        .tombstones
        .iter_mut()
        .find(|item| item.operation.operation_id == operation_id)
        .ok_or(HostError::StateInvalid)?;
    if let Some(value) = item.revocation_finalization.as_deref_mut() {
        return Ok(AcceptanceMut::Source(value));
    }
    item.independent_revocation_finalization
        .as_deref_mut()
        .map(AcceptanceMut::Independent)
        .ok_or(HostError::StateInvalid)
}

fn acceptance_record(value: &mut ManagementRecordV2) -> Result<AcceptanceMut<'_>, HostError> {
    if let Some(item) = value.revocation_finalization.as_deref_mut() {
        return Ok(AcceptanceMut::Source(item));
    }
    value
        .independent_revocation_finalization
        .as_deref_mut()
        .map(AcceptanceMut::Independent)
        .ok_or(HostError::StateInvalid)
}

fn outstanding(value: &ManagementLedgerV2) -> Result<u64, HostError> {
    value
        .records
        .iter()
        .map(record_reservation)
        .chain(value.tombstones.iter().map(tombstone_reservation))
        .try_fold(0_u64, |sum, item| {
            sum.checked_add(item).ok_or(HostError::StateInvalid)
        })
}

fn record_reservation(value: &ManagementRecordV2) -> u64 {
    value
        .revocation_finalization
        .as_ref()
        .map_or(0, |item| item.cancellation_recovery_reservation_bytes)
        .saturating_add(
            value
                .independent_revocation_finalization
                .as_ref()
                .map_or(0, |item| item.cancellation_recovery_reservation_bytes),
        )
}

fn tombstone_reservation(value: &crate::management_v2_record::ManagementTombstoneV2) -> u64 {
    value
        .revocation_finalization
        .as_ref()
        .map_or(0, |item| item.cancellation_recovery_reservation_bytes)
        .saturating_add(
            value
                .independent_revocation_finalization
                .as_ref()
                .map_or(0, |item| item.cancellation_recovery_reservation_bytes),
        )
}

fn serialized_len<T: serde::Serialize>(value: &T) -> Result<u64, HostError> {
    u64::try_from(
        serde_json::to_vec(value)
            .map_err(|_| HostError::StateInvalid)?
            .len(),
    )
    .map_err(|_| HostError::StateInvalid)
}

include!("management_v2_journal_cancel_capacity_phase.rs");
