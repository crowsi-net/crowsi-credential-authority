use crate::{
    HostError,
    management_v2_journal::ManagementJournalV2,
    management_v2_journal_update::EvidenceUse,
    management_v2_record::{
        DurableResponseReceiptV1 as Receipt, DurableResponseV1 as Response, ManagementRecordV2,
    },
};

include!("management_v2_journal_receipt_read.rs");
include!("management_v2_journal_receipt_mutation.rs");

fn prepare_insert(
    ledger: &mut crate::management_v2_record::ManagementLedgerV2,
    record: &ManagementRecordV2,
    now: u64,
) -> Result<(), HostError> {
    if ledger
        .records
        .iter()
        .any(|value| value.operation.operation_id == record.operation.operation_id)
        || ledger
            .tombstones
            .iter()
            .any(|value| value.operation.operation_id == record.operation.operation_id)
        || record.authority_config_generation < ledger.authority_config_generation_head
    {
        return Err(HostError::StateInvalid);
    }
    crate::management_v2_journal_policy::compact(ledger, now)?;
    if !crate::management_v2_operation_conflict::available(ledger, record) {
        return Err(HostError::StateInvalid);
    }
    let transfer = matches!(
        record.prepared.intent,
        crowsi_credential_authority_contracts::ManagementIntentV2::DeviceTransfer { .. }
    );
    if (transfer && ledger.records.len() >= 72)
        || ledger.records.len() >= 80
        || crate::management_v2_quota::source(
            ledger,
            &record.owner_ref,
            &record.prepared.source_device_ref,
        ) >= 16
        || crate::management_v2_journal_policy::active(ledger)
            >= crate::management_v2_journal_policy::owner_limit(record)
    {
        return Err(HostError::StateInvalid);
    }
    Ok(())
}

fn exact(
    ledger: &crate::management_v2_record::ManagementLedgerV2,
    request: &str,
    identity: &str,
    identity_generation: u64,
    now: u64,
) -> Result<Option<Vec<u8>>, HostError> {
    let Some(value) = ledger
        .durable_responses
        .iter()
        .find(|value| value.request_digest_sha256 == request)
    else {
        return Ok(None);
    };
    if value.identity_exchange_sha256 != identity
        || identity_generation < ledger.authority_config_generation_head
        || now >= value.retain_until_epoch_s
        || !response_live(value, now)
        || (value.read_only && value.accepted_ledger_revision != ledger.revision)
    {
        return Err(HostError::StateInvalid);
    }
    crate::management_v2_receipt::wire(value).map(Some)
}

fn response_live(value: &Receipt, now: u64) -> bool {
    match &value.response {
        Response::Projection(value) => now < value.expires_at_epoch_s,
        Response::PreparedLookup(value) => now < value.expires_at_epoch_s,
    }
}

fn append(
    values: &mut Vec<Receipt>,
    value: Receipt,
    terminal: &std::collections::BTreeSet<String>,
    now: u64,
) -> Result<(), HostError> {
    values.retain(|item| now < item.retain_until_epoch_s);
    if values
        .iter()
        .any(|item| item.request_digest_sha256 == value.request_digest_sha256)
    {
        return Err(HostError::StateInvalid);
    }
    if !value.read_only
        && let (Some(operation_id), Some(phase)) =
            (value.operation_id.as_deref(), value.phase.as_deref())
    {
        values.retain(|item| {
            item.read_only
                || item.operation_id.as_deref() != Some(operation_id)
                || item.phase.as_deref() != Some(phase)
        });
    }
    make_room(values, &value, terminal);
    values.push(value);
    if values.len() > 512 || !crate::management_v2_receipt::valid_set(values) {
        return Err(HostError::StateInvalid);
    }
    Ok(())
}

pub(crate) fn terminal_operations(
    ledger: &crate::management_v2_record::ManagementLedgerV2,
) -> std::collections::BTreeSet<String> {
    ledger
        .records
        .iter()
        .filter(|item| {
            crate::management_v2_quota::terminal(item)
                && !crate::management_v2_journal_cancel_slot::unacknowledged_record(item)
        })
        .map(|item| item.operation.operation_id.clone())
        .chain(
            ledger
                .tombstones
                .iter()
                .filter(|item| {
                    !crate::management_v2_journal_cancel_slot::unacknowledged_tombstone(item)
                })
                .map(|item| item.operation.operation_id.clone()),
        )
        .collect()
}

include!("management_v2_journal_receipt_retention.rs");
include!("management_v2_journal_receipt_validation.rs");
