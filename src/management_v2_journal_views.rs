impl ManagementJournalV2 {
    pub(crate) fn view(&self, owner: &str) -> Result<(u64, Vec<ManagementRecordV2>), HostError> {
        self.locked(owner, || {
            let value =
                crate::management_v2_journal_io::read(&self.root, &self.anchor_root, owner)?;
            Ok((value.revision, value.records))
        })
    }

    pub(crate) fn current_view(
        &self,
        owner: &str,
        identity_config_generation: u64,
    ) -> Result<(u64, Vec<ManagementRecordV2>), HostError> {
        self.locked(owner, || {
            let value =
                crate::management_v2_journal_io::read(&self.root, &self.anchor_root, owner)?;
            if identity_config_generation < value.authority_config_generation_head {
                return Err(HostError::EvidenceInvalid);
            }
            Ok((value.revision, value.records))
        })
    }

    pub(crate) fn record(&self, owner: &str, id: &str) -> Result<ManagementRecordV2, HostError> {
        self.locked(owner, || {
            let ledger =
                crate::management_v2_journal_io::read(&self.root, &self.anchor_root, owner)?;
            ledger
                .records
                .into_iter()
                .find(|item| item.operation.operation_id == id)
                .ok_or(HostError::StateInvalid)
        })
    }

    pub(crate) fn generation_head(&self, owner: &str) -> Result<u64, HostError> {
        self.locked(owner, || {
            let ledger =
                crate::management_v2_journal_io::read(&self.root, &self.anchor_root, owner)?;
            Ok(ledger.authority_config_generation_head)
        })
    }
}
