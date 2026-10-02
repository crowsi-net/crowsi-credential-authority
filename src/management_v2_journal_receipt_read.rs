impl ManagementJournalV2 {
    pub(crate) fn exact_response(
        &self,
        owner: &str,
        request_digest: &str,
        identity_digest: &str,
        identity_generation: u64,
        now: u64,
    ) -> Result<Option<Vec<u8>>, HostError> {
        self.locked(owner, || {
            let ledger =
                crate::management_v2_journal_io::read(&self.root, &self.anchor_root, owner)?;
            exact(
                &ledger,
                request_digest,
                identity_digest,
                identity_generation,
                now,
            )
        })
    }

    pub(crate) fn commit_read_response(
        &self,
        owner: &str,
        expected_revision: u64,
        identity_generation: u64,
        evidence: &[EvidenceUse<'_>],
        mut receipt: Receipt,
        now: u64,
    ) -> Result<Vec<u8>, HostError> {
        self.locked(owner, || {
            let mut ledger =
                crate::management_v2_journal_io::read(&self.root, &self.anchor_root, owner)?;
            if let Some(value) = exact(
                &ledger,
                &receipt.request_digest_sha256,
                &receipt.identity_exchange_sha256,
                identity_generation,
                now,
            )? {
                return Ok(value);
            }
            if !receipt.read_only
                || ledger.revision != expected_revision
                || identity_generation < ledger.authority_config_generation_head
            {
                return Err(HostError::StateInvalid);
            }
            let next = crate::management_v2_journal_policy::next(ledger.revision)?;
            response_revision(&receipt, next)?;
            crate::management_v2_evidence_use::consume(&mut ledger, evidence, now)?;
            ledger.authority_config_generation_head = ledger
                .authority_config_generation_head
                .max(identity_generation);
            ledger.revision = next;
            receipt.accepted_ledger_revision = next;
            receipt.accepted_generation_head = ledger.authority_config_generation_head;
            let request_digest = receipt.request_digest_sha256.clone();
            let identity_digest = receipt.identity_exchange_sha256.clone();
            let terminal = terminal_operations(&ledger);
            append(&mut ledger.durable_responses, receipt, &terminal, now)?;
            crate::management_v2_journal_io::write(&self.root, &self.anchor_root, owner, &ledger)?;
            exact(
                &ledger,
                &request_digest,
                &identity_digest,
                identity_generation,
                now,
            )?
            .ok_or(HostError::StateInvalid)
        })
    }
}
