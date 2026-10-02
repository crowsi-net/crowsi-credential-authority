impl ManagementV2Handler {
    fn apply_rotation_receipt(
        &self,
        mut record: ManagementRecordV2,
        index: usize,
        target_device_ref: &str,
        plan: &crate::management_v2_record::RevocationRotationV2,
        document: crate::ProviderEvidenceDocumentV1,
        now: u64,
    ) -> Result<ManagementRecordV2, HostError> {
        let credential = CredentialId::parse(plan.credential_ref.clone())?;
        let target = DeviceId::parse(plan.target_device_ref.clone())?;
        let owner = crate::OpaqueOwnerRef::parse(record.owner_ref.clone())?;
        let (acceptance, receipt) = match plan.provider_acceptance.as_ref() {
            Some(value) if value.document.kind == "reissue-receipt" => (
                value.clone(),
                crate::management_v2_provider_acceptance::historic_receipt(
                    value,
                    &owner,
                    &credential,
                    &target,
                    &plan.provider_nonce,
                    now,
                )?,
            ),
            _ => {
                let route = self.core.provider_route(&record.service_id)?;
                crate::management_v2_provider_acceptance::accept_receipt(
                    document,
                    route,
                    &owner,
                    &credential,
                    &target,
                    &plan.provider_nonce,
                    now,
                    plan.attempted,
                )?
            }
        };
        if plan.provider_acceptance.as_ref() != Some(&acceptance) {
            record = self.persist_rotation_acceptance(record, index, acceptance.clone())?;
        }
        let mut mutation = crate::management_v2_adapter::source_mutation_with_provider_key(
            &self.core,
            &record,
            now,
            &acceptance.response_public_key_hex,
        )?;
        mutation.adapter.apply_host_revocation_rotation(
            &plan.provider_request_id,
            &mutation.owner,
            &credential,
            &DeviceId::parse(target_device_ref.to_owned())?,
            &plan.provider_nonce,
            plan.target_binding
                .as_ref()
                .ok_or(HostError::StateInvalid)?,
            receipt,
        )?;
        self.mark_rotation_applied(record, index)
    }
}
