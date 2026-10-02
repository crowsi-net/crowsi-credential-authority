use crate::{
    HostError, management_v2_journal::ManagementJournalV2,
    management_v2_journal_update::EvidenceUse, management_v2_record::ManagementRecordV2,
};

impl ManagementJournalV2 {
    pub(crate) fn accept_independent_pre_final(
        &self,
        expected: u64,
        mut record: ManagementRecordV2,
        evidence: &[EvidenceUse<'_>],
        now: u64,
    ) -> Result<(u64, ManagementRecordV2), HostError> {
        let owner = record.owner_ref.clone();
        self.locked(&owner, || {
            let mut ledger =
                crate::management_v2_journal_io::read(&self.root, &self.anchor_root, &owner)?;
            if record.authority_config_generation < ledger.authority_config_generation_head {
                return Err(HostError::EvidenceInvalid);
            }
            let next = crate::management_v2_journal_policy::next(ledger.revision)?;
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
            record
                .independent_revocation_finalization
                .as_mut()
                .ok_or(HostError::StateInvalid)?
                .pre_final_snapshot_revision = next;
            *current = record.clone();
            crate::management_v2_evidence_use::consume(&mut ledger, evidence, now)?;
            ledger.authority_config_generation_head = ledger
                .authority_config_generation_head
                .max(record.authority_config_generation);
            ledger.revision = next;
            crate::management_v2_journal_io::write(&self.root, &self.anchor_root, &owner, &ledger)?;
            Ok((next, record))
        })
    }

    pub(crate) fn independent_pre_final_view(
        &self,
        request: &crowsi_credential_authority_contracts::EndpointIndependentRevocationPreFinalRequestV1,
        peer: &str,
    ) -> Result<Option<(u64, ManagementRecordV2)>, HostError> {
        let owner = &request.prepared.opaque_owner_ref;
        self.locked(owner, || {
            let ledger =
                crate::management_v2_journal_io::read(&self.root, &self.anchor_root, owner)?;
            let value = ledger.records.iter().find(|item| {
                item.operation.operation_id == request.operation_id
                    && crate::management_v2_independent_finalization_acceptance::pre_final_exact(
                        item, request, peer,
                    )
            });
            Ok(value.map(|item| (ledger.revision, item.clone())))
        })
    }
}
