use crate::management_v2_record::{ManagementLedgerV2, ManagementRecordV2};

pub(crate) fn terminal(value: &ManagementRecordV2) -> bool {
    use crowsi_credential_authority_contracts::ManagementOperationState as S;
    matches!(
        value.operation.state,
        S::Completed | S::Rejected | S::Cancelled | S::Expired
    )
}

pub(crate) fn source(value: &ManagementLedgerV2, owner: &str, source: &str) -> usize {
    value
        .records
        .iter()
        .filter(|item| {
            item.owner_ref == owner && item.prepared.source_device_ref == source && !terminal(item)
        })
        .count()
}
