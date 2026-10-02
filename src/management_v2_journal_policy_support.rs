fn source_tombstones(value: &ManagementLedgerV2, source: &str) -> usize {
    value
        .tombstones
        .iter()
        .filter(|item| item.prepared.source_device_ref == source)
        .count()
}

fn transfer_tombstones(value: &ManagementLedgerV2) -> usize {
    value
        .tombstones
        .iter()
        .filter(|item| {
            matches!(
                item.prepared.intent,
                crowsi_credential_authority_contracts::ManagementIntentV2::DeviceTransfer { .. }
            )
        })
        .count()
}

fn digest_valid(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|item| item.is_ascii_digit() || matches!(item, b'a'..=b'f'))
}
