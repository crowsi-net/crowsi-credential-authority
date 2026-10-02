impl ManagementJournalV2 {
    pub(crate) fn insert_consuming_response(
        &self,
        record: ManagementRecordV2,
        evidence: &[EvidenceUse<'_>],
        mut receipt: Receipt,
        now: u64,
    ) -> Result<(ManagementRecordV2, Vec<u8>), HostError> {
        let owner = record.owner_ref.clone();
        self.locked(&owner, || {
            let mut ledger =
                crate::management_v2_journal_io::read(&self.root, &self.anchor_root, &owner)?;
            if let Some(value) = exact(
                &ledger,
                &receipt.request_digest_sha256,
                &receipt.identity_exchange_sha256,
                record.authority_config_generation,
                now,
            )? {
                let current = ledger
                    .records
                    .iter()
                    .find(|item| item.operation.operation_id == record.operation.operation_id)
                    .cloned()
                    .ok_or(HostError::StateInvalid)?;
                crate::management_v2_journal_policy::exact(&current, &record)?;
                return Ok((current, value));
            }
            prepare_insert(&mut ledger, &record, now)?;
            crate::management_v2_evidence_use::consume(&mut ledger, evidence, now)?;
            ledger.authority_config_generation_head = ledger
                .authority_config_generation_head
                .max(record.authority_config_generation);
            ledger.revision = crate::management_v2_journal_policy::next(ledger.revision)?;
            mutation_response(&receipt, &record, ledger.revision)?;
            receipt.accepted_ledger_revision = ledger.revision;
            receipt.accepted_generation_head = ledger.authority_config_generation_head;
            let terminal = terminal_operations(&ledger);
            append(&mut ledger.durable_responses, receipt, &terminal, now)?;
            ledger.records.push(record.clone());
            crate::management_v2_journal_io::write(&self.root, &self.anchor_root, &owner, &ledger)?;
            let wire = crate::management_v2_receipt::wire(
                ledger
                    .durable_responses
                    .last()
                    .ok_or(HostError::StateInvalid)?,
            )?;
            Ok((record, wire))
        })
    }

    pub(crate) fn replace_consuming_response(
        &self,
        expected: u64,
        mut record: ManagementRecordV2,
        evidence: &[EvidenceUse<'_>],
        mut receipt: Receipt,
        now: u64,
        cancellation_capacity: Option<(
            &crate::host_config::VerifiedHostConfig,
            &crowsi_credential_authority_contracts::EndpointManagementEnvelopeV2,
        )>,
    ) -> Result<(ManagementRecordV2, Vec<u8>), HostError> {
        let owner = record.owner_ref.clone();
        self.locked(&owner, || {
            let mut ledger =
                crate::management_v2_journal_io::read(&self.root, &self.anchor_root, &owner)?;
            if let Some(value) = exact(
                &ledger,
                &receipt.request_digest_sha256,
                &receipt.identity_exchange_sha256,
                record.authority_config_generation,
                now,
            )? {
                let current = ledger
                    .records
                    .iter()
                    .find(|item| item.operation.operation_id == record.operation.operation_id)
                    .cloned()
                    .ok_or(HostError::StateInvalid)?;
                return Ok((current, value));
            }
            if record.authority_config_generation < ledger.authority_config_generation_head {
                return Err(HostError::EvidenceInvalid);
            }
            let index = ledger
                .records
                .iter()
                .position(|item| item.operation.operation_id == record.operation.operation_id)
                .ok_or(HostError::StateInvalid)?;
            let current = &ledger.records[index];
            if current.operation.state_revision != expected
                || current.prepared != record.prepared
                || record.operation.state_revision.checked_sub(expected) != Some(1)
            {
                return Err(HostError::StateInvalid);
            }
            crate::management_v2_journal_cancel_slot::reserve(
                &self.root,
                &ledger,
                current,
                &mut record,
            )?;
            if let Some((config, envelope)) = cancellation_capacity
                && crate::management_v2_journal_cancel_capacity::needs_initial(&record)
            {
                crate::management_v2_journal_cancel_capacity::reserve_initial(
                    &mut record,
                    config,
                    envelope,
                    crate::management_v2_journal_policy::next(ledger.revision)?,
                )?;
            }
            ledger.records[index] = record.clone();
            crate::management_v2_evidence_use::consume(&mut ledger, evidence, now)?;
            ledger.authority_config_generation_head = ledger
                .authority_config_generation_head
                .max(record.authority_config_generation);
            ledger.revision = crate::management_v2_journal_policy::next(ledger.revision)?;
            mutation_response(&receipt, &record, ledger.revision)?;
            receipt.accepted_ledger_revision = ledger.revision;
            receipt.accepted_generation_head = ledger.authority_config_generation_head;
            let terminal = terminal_operations(&ledger);
            append(&mut ledger.durable_responses, receipt, &terminal, now)?;
            crate::management_v2_journal_io::write(&self.root, &self.anchor_root, &owner, &ledger)?;
            let wire = crate::management_v2_receipt::wire(
                ledger
                    .durable_responses
                    .last()
                    .ok_or(HostError::StateInvalid)?,
            )?;
            Ok((record, wire))
        })
    }
}
