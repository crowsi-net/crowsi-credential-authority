impl ManagementV2Handler {
    pub(crate) fn reconcile_v2(
        &self,
        envelope: &EndpointManagementEnvelopeV2,
        verified: &VerifiedManagementIdentity<'_>,
        prepared: &EndpointPreparedOperationV2,
        now: u64,
    ) -> Result<Vec<u8>, HostError> {
        let (id, revision) = command(&envelope.browser_request.command)?;
        let mut record = self.journal.record(&verified.owner.opaque_owner_ref, id)?;
        let ManagementCommandV2::Reconcile {
            reconcile_digest, ..
        } = &envelope.browser_request.command
        else {
            return Err(HostError::RequestInvalid);
        };
        if record.prepared != *prepared
            || record.operation.state_revision != revision
            || record.operation.reconcile_digest.as_deref() != Some(reconcile_digest)
            || record.operation.state != ManagementOperationState::Unknown
            || !crate::management_v2_lookup_policy::allowed(
                crowsi_credential_authority_contracts::EndpointPreparedLookupPhaseV1::Reconcile,
                &record,
                &verified.identity.assertion.device_id,
                &verified.identity.assertion.session_ref,
            )
        {
            return Err(HostError::StateInvalid);
        }
        record.authority_config_generation = crate::management_v2_config_generation::record(
            &self.journal,
            &record,
            &[verified.identity_exchange],
        )?;
        let phase_binding = crate::management_v2_journal_policy::envelope_digest(envelope)?;
        let identity_digest =
            crate::management_v2_journal_policy::exchange_digest(verified.identity_exchange)?;
        let use_status = identity_uses(verified, &identity_digest, &phase_binding);
        record.operation.state_revision = next(revision)?;
        let (ledger_revision, _) = self.journal.view(&verified.owner.opaque_owner_ref)?;
        let receipt = crate::management_v2_receipt::projection(
            &self.core.config,
            envelope,
            verified,
            ManagementProjectionBodyV2::Operation {
                operation: record.operation.clone(),
            },
            crate::management_v2_journal_policy::next(ledger_revision)?,
            now,
            now.saturating_add(30),
            false,
        )?;
        let (record, response) = self.journal.replace_consuming_response(
            revision,
            record,
            &use_status,
            receipt,
            now,
            None,
        )?;
        if matches!(
            record.prepared.intent,
            crowsi_credential_authority_contracts::ManagementIntentV2::DeviceTransfer { .. }
        ) {
            let _ = self.reconcile_transfer(record, &[], now)?;
        } else {
            let _ = self.execute_revocation(record, &[], now)?;
        }
        Ok(response)
    }
}
