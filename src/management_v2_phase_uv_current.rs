impl ManagementV2Handler {
    pub(crate) fn current(
        &self,
        verified: &VerifiedManagementIdentity<'_>,
        prepared: &EndpointPreparedOperationV2,
        id: &str,
        revision: u64,
        state: ManagementOperationState,
        now: u64,
    ) -> Result<crate::management_v2_record::ManagementRecordV2, HostError> {
        let value = self.journal.record(&verified.owner.opaque_owner_ref, id)?;
        if value.owner_ref != verified.owner.opaque_owner_ref
            || value.prepared != *prepared
            || value.service_id != verified.identity.assertion.service_id
            || value.pairwise_subject != verified.identity.assertion.pairwise_subject
            || value.operation.state_revision != revision
            || value.operation.state != state
            || now >= value.operation.expires_at_epoch_s
        {
            return Err(HostError::StateInvalid);
        }
        Ok(value)
    }
}
