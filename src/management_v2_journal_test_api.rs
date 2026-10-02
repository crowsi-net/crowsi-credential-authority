impl ManagementJournalV2 {
    pub(crate) fn insert(
        &self,
        record: ManagementRecordV2,
        now: u64,
    ) -> Result<ManagementRecordV2, HostError> {
        self.insert_consuming(record, &[], now)
    }

    pub(crate) fn insert_consuming(
        &self,
        record: ManagementRecordV2,
        evidence: &[crate::management_v2_journal_update::EvidenceUse<'_>],
        now: u64,
    ) -> Result<ManagementRecordV2, HostError> {
        let owner = record.owner_ref.clone();
        self.locked(&owner, || {
            let mut ledger =
                crate::management_v2_journal_io::read(&self.root, &self.anchor_root, &owner)?;
            if let Some(value) = ledger
                .records
                .iter()
                .find(|item| item.operation.operation_id == record.operation.operation_id)
            {
                return crate::management_v2_journal_policy::exact(value, &record);
            }
            if let Some(value) = ledger
                .tombstones
                .iter()
                .find(|item| item.operation.operation_id == record.operation.operation_id)
            {
                return crate::management_v2_journal_policy::exact_tombstone(value, &record);
            }
            if record.authority_config_generation < ledger.authority_config_generation_head {
                return Err(HostError::EvidenceInvalid);
            }
            crate::management_v2_journal_policy::compact(&mut ledger, now)?;
            let transfer = matches!(
                record.prepared.intent,
                crowsi_credential_authority_contracts::ManagementIntentV2::DeviceTransfer { .. }
            );
            if (transfer && ledger.records.len() >= 72) || ledger.records.len() >= 80 {
                return Err(HostError::StateInvalid);
            }
            if crate::management_v2_quota::source(
                &ledger,
                &owner,
                &record.prepared.source_device_ref,
            ) >= 16
                || crate::management_v2_journal_policy::active(&ledger)
                    >= crate::management_v2_journal_policy::owner_limit(&record)
            {
                return Err(HostError::StateInvalid);
            }
            crate::management_v2_evidence_use::consume(&mut ledger, evidence, now)?;
            ledger.authority_config_generation_head = ledger
                .authority_config_generation_head
                .max(record.authority_config_generation);
            ledger.revision = crate::management_v2_journal_policy::next(ledger.revision)?;
            ledger.records.push(record.clone());
            crate::management_v2_journal_io::write(&self.root, &self.anchor_root, &owner, &ledger)?;
            Ok(record)
        })
    }
}
