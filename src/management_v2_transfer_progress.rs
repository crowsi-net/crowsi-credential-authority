impl ManagementV2Handler {
    pub(crate) fn persist_transfer_acceptance(
        &self,
        mut record: ManagementRecordV2,
        acceptance: crate::management_v2_provider_acceptance::ProviderEvidenceAcceptanceV1,
    ) -> Result<ManagementRecordV2, HostError> {
        if record.transfer_provider_acceptance.as_ref() == Some(&acceptance) {
            return Ok(record);
        }
        if let Some(prior_acceptance) = record.transfer_provider_acceptance.take() {
            crate::management_v2_provider_progress::append(
                "transfer",
                &mut record.transfer_provider_history,
                &mut record.transfer_provider_history_count,
                &mut record.transfer_provider_history_digest_sha256,
                prior_acceptance,
            )?;
        }
        let prior = record.operation.state_revision;
        record.transfer_provider_acceptance = Some(acceptance);
        let context = record
            .transfer_context
            .as_mut()
            .ok_or(HostError::StateInvalid)?;
        context.provider_reconcile_request_id = None;
        crate::management_v2_transfer_state::bump(&mut record)?;
        self.journal.replace(prior, record)
    }

    pub(crate) fn begin_transfer_reconciliation(
        &self,
        mut record: ManagementRecordV2,
    ) -> Result<ManagementRecordV2, HostError> {
        let context = record
            .transfer_context
            .as_mut()
            .ok_or(HostError::StateInvalid)?;
        if context.provider_reconcile_request_id.is_some() {
            return Ok(record);
        }
        context.reconcile_sequence = context
            .reconcile_sequence
            .checked_add(1)
            .ok_or(HostError::StateInvalid)?;
        context.provider_reconcile_request_id = Some(
            crate::management_v2_provider_progress::transfer_reconcile_request(
                &record.operation.operation_id,
                context.reconcile_sequence,
            ),
        );
        let prior = record.operation.state_revision;
        crate::management_v2_transfer_state::bump(&mut record)?;
        self.journal.replace(prior, record)
    }

    pub(crate) fn persist_transfer_context(
        &self,
        mut record: ManagementRecordV2,
        context: crate::management_v2_transfer_context::TransferContextV2,
    ) -> Result<ManagementRecordV2, HostError> {
        if record.transfer_context.as_ref() == Some(&context) {
            return Ok(record);
        }
        if record.transfer_context.is_some() {
            return Err(HostError::StateInvalid);
        }
        let prior = record.operation.state_revision;
        record.provider_transfer_id = Some(context.transfer_id.clone());
        record.transfer_context = Some(context);
        crate::management_v2_transfer_state::bump(&mut record)?;
        self.journal.replace(prior, record)
    }

    pub(crate) fn apply_transfer_receipt(
        &self,
        mut record: ManagementRecordV2,
        now: u64,
    ) -> Result<ManagementRecordV2, HostError> {
        let context = record
            .transfer_context
            .clone()
            .ok_or(HostError::StateInvalid)?;
        let acceptance = record
            .transfer_provider_acceptance
            .as_ref()
            .filter(|item| item.document.kind == "reissue-receipt")
            .ok_or(HostError::StateInvalid)?;
        let owner = crate::OpaqueOwnerRef::parse(context.owner_ref.clone())?;
        let credential = CredentialId::parse(context.credential_ref.clone())?;
        let target = DeviceId::parse(context.target_device_ref.clone())?;
        let receipt = crate::management_v2_provider_acceptance::historic_receipt(
            acceptance,
            &owner,
            &credential,
            &target,
            &context.provider_nonce,
            now,
        )?;
        let mut mutation = crate::management_v2_adapter::mutation_with_provider_key(
            &self.core,
            &record,
            now,
            &acceptance.response_public_key_hex,
        )?;
        let authorization = record
            .source_approval_acceptance_sha256
            .as_deref()
            .ok_or(HostError::EvidenceInvalid)?;
        mutation.adapter.finish_management_transfer(
            TransferAcceptance::new(
                crate::TransferId::parse(context.transfer_id)?,
                mutation.owner,
                target,
                mutation.target,
            )
            .with_provider_receipt(receipt),
            authorization,
        )?;
        let prior = record.operation.state_revision;
        crate::management_v2_transfer_state::complete(&mut record)?;
        self.journal.replace(prior, record)
    }
}
