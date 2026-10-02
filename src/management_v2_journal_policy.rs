use crate::{
    HostError,
    management_v2_journal_update::EvidenceUse,
    management_v2_record::{ManagementLedgerV2, ManagementRecordV2, ManagementTombstoneV2},
};

pub(crate) fn exact(
    existing: &ManagementRecordV2,
    supplied: &ManagementRecordV2,
) -> Result<ManagementRecordV2, HostError> {
    (existing.owner_ref == supplied.owner_ref
        && existing.service_id == supplied.service_id
        && existing.pairwise_subject == supplied.pairwise_subject
        && existing.authority_config_generation == supplied.authority_config_generation
        && existing.prepared == supplied.prepared
        && existing.source_identity_exchange == supplied.source_identity_exchange
        && existing.source_options_exchange == supplied.source_options_exchange)
        .then(|| existing.clone())
        .ok_or(HostError::StateInvalid)
}

#[cfg(all(test, feature = "test-support"))]
pub(crate) fn exact_tombstone(
    existing: &ManagementTombstoneV2,
    supplied: &ManagementRecordV2,
) -> Result<ManagementRecordV2, HostError> {
    if existing.owner_ref != supplied.owner_ref
        || existing.service_id != supplied.service_id
        || existing.pairwise_subject != supplied.pairwise_subject
        || existing.authority_config_generation != supplied.authority_config_generation
        || existing.prepared != supplied.prepared
        || existing.source_identity_exchange_sha256
            != exchange_digest(&supplied.source_identity_exchange)?
        || existing.source_options_exchange_sha256
            != exchange_digest(&supplied.source_options_exchange)?
    {
        return Err(HostError::StateInvalid);
    }
    let mut replay = supplied.clone();
    replay.operation = existing.operation.clone();
    Ok(replay)
}

pub(crate) fn next(value: u64) -> Result<u64, HostError> {
    value.checked_add(1).ok_or(HostError::StateInvalid)
}

pub(crate) fn active(value: &ManagementLedgerV2) -> usize {
    value
        .records
        .iter()
        .filter(|item| !crate::management_v2_quota::terminal(item))
        .count()
}

pub(crate) fn owner_limit(record: &ManagementRecordV2) -> usize {
    if matches!(
        record.prepared.intent,
        crowsi_credential_authority_contracts::ManagementIntentV2::DeviceTransfer { .. }
    ) {
        48
    } else {
        64
    }
}

pub(crate) fn compact(ledger: &mut ManagementLedgerV2, now: u64) -> Result<(), HostError> {
    ledger
        .durable_responses
        .retain(|item| now < item.retain_until_epoch_s);
    retain_tombstones(ledger, now);
    while ledger.records.len() >= 80 {
        let index = ledger
            .records
            .iter()
            .enumerate()
            .filter(|(_, item)| crate::management_v2_quota::terminal(item))
            .min_by_key(|(_, item)| item.operation.created_at_epoch_s)
            .map(|(index, _)| index)
            .ok_or(HostError::StateInvalid)?;
        let value = ledger.records.remove(index);
        let transfer = matches!(
            value.prepared.intent,
            crowsi_credential_authority_contracts::ManagementIntentV2::DeviceTransfer { .. }
        );
        if source_tombstones(ledger, &value.prepared.source_device_ref) >= 128
            || (transfer && transfer_tombstones(ledger) >= 192)
            || ledger.tombstones.len() >= 256
        {
            return Err(HostError::StateInvalid);
        }
        ledger
            .tombstones
            .push(ManagementTombstoneV2::from_record(&value)?);
    }
    Ok(())
}

pub(crate) fn evidence_digest(value: &EvidenceUse<'_>) -> Result<String, HostError> {
    if value.kind.is_empty()
        || value.kind.len() > 64
        || value.id.is_empty()
        || value.id.len() > 256
        || !digest_valid(value.binding)
    {
        return Err(HostError::EvidenceInvalid);
    }
    Ok(crate::host_crypto::digest(
        format!("CROWSI-MANAGEMENT-SEMANTIC-EVIDENCE-V4\0{}", value.id).as_bytes(),
    ))
}

pub(crate) fn envelope_digest(
    value: &crowsi_credential_authority_contracts::EndpointManagementEnvelopeV2,
) -> Result<String, HostError> {
    let digest =
        crowsi_credential_authority_contracts::endpoint_management_phase_envelope_digest(value)
            .map_err(|_| HostError::EvidenceInvalid)?;
    Ok(format!("sha256:{digest}"))
}

pub(crate) fn exchange_digest(
    value: &crowsi_credential_authority_contracts::SignedAuthorityExchangeV1,
) -> Result<String, HostError> {
    let wire = serde_json::to_vec(value).map_err(|_| HostError::EvidenceInvalid)?;
    let mut framed = b"CROWSI-MANAGEMENT-IDENTITY-EXCHANGE-V1\0".to_vec();
    framed.extend_from_slice(&wire);
    Ok(crate::host_crypto::digest(&framed))
}

include!("management_v2_journal_policy_support.rs");
include!("management_v2_journal_policy_tombstones.rs");
