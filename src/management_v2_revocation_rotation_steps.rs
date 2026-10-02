impl ManagementV2Handler {
    fn rotation_document(
        &self,
        mut record: ManagementRecordV2,
        index: usize,
        mut plan: crate::management_v2_record::RevocationRotationV2,
    ) -> Result<
        (
            ManagementRecordV2,
            crate::management_v2_record::RevocationRotationV2,
            Option<crate::ProviderEvidenceDocumentV1>,
        ),
        HostError,
    > {
        if plan
            .provider_acceptance
            .as_ref()
            .is_some_and(|value| value.document.kind == "reissue-receipt")
        {
            let document = plan
                .provider_acceptance
                .clone()
                .ok_or(HostError::StateInvalid)?
                .document;
            return Ok((record, plan, Some(document)));
        }
        let route = self.core.provider_route(&record.service_id)?;
        if plan.attempted {
            record = self.begin_rotation_reconciliation(record, index)?;
            plan = record
                .revocation_saga
                .as_ref()
                .and_then(|saga| saga.rotations.get(index))
                .cloned()
                .ok_or(HostError::StateInvalid)?;
            let document = ProviderOperationTransport::new(route).reconcile(
                plan.provider_reconcile_request_id
                    .as_deref()
                    .ok_or(HostError::StateInvalid)?,
                &record.owner_ref,
                &plan.credential_ref,
                &plan.target_device_ref,
                &plan.provider_nonce,
                &plan.provider_operation_ref,
                &plan.provider_nonce,
            )?;
            return Ok((record, plan, Some(document)));
        }
        record = self.mark_rotation_attempted(record, index)?;
        let document = ProviderOperationTransport::new(route)
            .reissue(
                &plan.provider_operation_ref,
                &record.owner_ref,
                &plan.credential_ref,
                &plan.target_device_ref,
                &plan.provider_nonce,
            )
            .ok();
        Ok((record, plan, document))
    }

    fn apply_rotation_document(
        &self,
        mut record: ManagementRecordV2,
        index: usize,
        target_device_ref: &str,
        plan: &crate::management_v2_record::RevocationRotationV2,
        document: crate::ProviderEvidenceDocumentV1,
        now: u64,
    ) -> Result<(ManagementRecordV2, bool), HostError> {
        match document.kind.as_str() {
            "reissue-receipt" => {
                record = self.apply_rotation_receipt(
                    record,
                    index,
                    target_device_ref,
                    plan,
                    document,
                    now,
                )?;
                Ok((record, true))
            }
            "unknown-outcome" => {
                let route = self.core.provider_route(&record.service_id)?;
                let (acceptance, _) = crate::management_v2_provider_acceptance::accept_unknown(
                    document,
                    route,
                    &plan.provider_operation_ref,
                    &plan.provider_nonce,
                    now,
                )?;
                record = self.persist_rotation_acceptance(record, index, acceptance)?;
                Ok((record, false))
            }
            "not-issued-reconciliation" => {
                let route = self.core.provider_route(&record.service_id)?;
                let (acceptance, _) =
                    crate::management_v2_provider_acceptance::accept_reconciliation(
                        document,
                        route,
                        &plan.provider_operation_ref,
                        &plan.provider_nonce,
                        now,
                    )?;
                record = self.retry_rotation_after_not_issued(record, index, acceptance)?;
                Ok((record, false))
            }
            _ => Err(HostError::EvidenceInvalid),
        }
    }
}

include!("management_v2_revocation_rotation_receipt.rs");
