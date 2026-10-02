impl ManagementV2Handler {
    pub(crate) fn mark_rotation_applied(
        &self,
        mut record: ManagementRecordV2,
        index: usize,
    ) -> Result<ManagementRecordV2, HostError> {
        let prior = record.operation.state_revision;
        let rotation = record
            .revocation_saga
            .as_mut()
            .and_then(|saga| saga.rotations.get_mut(index))
            .ok_or(HostError::StateInvalid)?;
        if rotation
            .provider_acceptance
            .as_ref()
            .is_none_or(|item| item.document.kind != "reissue-receipt")
        {
            return Err(HostError::StateInvalid);
        }
        rotation.authority_applied = true;
        record.operation.state_revision = next(prior)?;
        self.journal.replace(prior, record)
    }

    pub(crate) fn retry_rotation_after_not_issued(
        &self,
        mut record: ManagementRecordV2,
        index: usize,
        acceptance: ProviderEvidenceAcceptanceV1,
    ) -> Result<ManagementRecordV2, HostError> {
        let prior = record.operation.state_revision;
        let rotation = record
            .revocation_saga
            .as_mut()
            .and_then(|saga| saga.rotations.get_mut(index))
            .ok_or(HostError::StateInvalid)?;
        if let Some(prior_acceptance) = rotation.provider_acceptance.take() {
            archive(rotation, prior_acceptance)?;
        }
        archive(rotation, acceptance)?;
        rotation.attempt_number = next(rotation.attempt_number)?;
        let (request, operation, nonce) = crate::management_v2_revocation_plan::attempt(
            &record.operation.operation_id,
            &rotation.credential_ref,
            rotation.attempt_number,
        );
        rotation.provider_request_id = request;
        rotation.provider_operation_ref = operation;
        rotation.provider_nonce = nonce;
        rotation.attempted = false;
        rotation.provider_acceptance = None;
        rotation.provider_reconcile_request_id = None;
        record.operation.state_revision = next(prior)?;
        self.journal.replace(prior, record)
    }
}
