fn retain_tombstones(ledger: &mut ManagementLedgerV2, now: u64) {
    let protected = ledger
        .durable_responses
        .iter()
        .filter(|item| !item.read_only)
        .filter_map(|item| item.operation_id.as_deref())
        .collect::<std::collections::BTreeSet<_>>();
    ledger.tombstones.retain(|item| {
        crate::management_v2_journal_cancel_slot::unacknowledged_tombstone(item)
            || protected.contains(item.operation.operation_id.as_str())
            || now <= item.prepared.expires_at_epoch_s.saturating_add(300)
    });
}
