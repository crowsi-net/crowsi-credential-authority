use crate::{
    HostError, management_v2_journal::ManagementJournalV2, management_v2_record::ManagementRecordV2,
};

pub(crate) struct EvidenceUse<'a> {
    pub kind: &'a str,
    pub id: &'a str,
    pub binding: &'a str,
    pub expires_at_epoch_s: u64,
}

impl ManagementJournalV2 {
    pub(crate) fn replace(
        &self,
        expected: u64,
        mut record: ManagementRecordV2,
    ) -> Result<ManagementRecordV2, HostError> {
        record.authority_config_generation = record
            .authority_config_generation
            .max(self.generation_head(&record.owner_ref)?);
        self.replace_consuming(expected, record, &[], 0)
    }

    pub(crate) fn replace_consuming(
        &self,
        expected: u64,
        record: ManagementRecordV2,
        evidence: &[EvidenceUse<'_>],
        now: u64,
    ) -> Result<ManagementRecordV2, HostError> {
        let owner = record.owner_ref.clone();
        self.locked(&owner, || {
            let mut ledger =
                crate::management_v2_journal_io::read(&self.root, &self.anchor_root, &owner)?;
            if record.authority_config_generation < ledger.authority_config_generation_head {
                return Err(HostError::EvidenceInvalid);
            }
            let current = ledger
                .records
                .iter_mut()
                .find(|item| item.operation.operation_id == record.operation.operation_id)
                .ok_or(HostError::StateInvalid)?;
            if current.operation.state_revision != expected
                || current.prepared != record.prepared
                || record.operation.state_revision.checked_sub(expected) != Some(1)
            {
                return Err(HostError::StateInvalid);
            }
            *current = record.clone();
            crate::management_v2_evidence_use::consume(&mut ledger, evidence, now)?;
            ledger.authority_config_generation_head = ledger
                .authority_config_generation_head
                .max(record.authority_config_generation);
            ledger.revision = crate::management_v2_journal_policy::next(ledger.revision)?;
            crate::management_v2_journal_io::write(&self.root, &self.anchor_root, &owner, &ledger)?;
            Ok(record)
        })
    }
}
