use crowsi_credential_authority_contracts::{ManagementOperationState, ManagementReasonCode};

use crate::{
    CredentialId, DeviceId, HostError, host_provider_transport::ProviderOperationTransport,
    management_v2_handler::ManagementV2Handler, management_v2_journal_update::EvidenceUse,
    management_v2_record::ManagementRecordV2,
};

impl ManagementV2Handler {
    pub(crate) fn reconcile_transfer(
        &self,
        mut record: ManagementRecordV2,
        evidence: &[EvidenceUse<'_>],
        now: u64,
    ) -> Result<ManagementRecordV2, HostError> {
        match record
            .transfer_provider_acceptance
            .as_ref()
            .map(|item| item.document.kind.as_str())
        {
            Some("reissue-receipt") => return self.apply_transfer_receipt(record, now),
            Some("not-issued-reconciliation") => {
                return self.apply_transfer_not_issued(record, evidence, now);
            }
            _ => {}
        }
        let context = match record.transfer_context.clone() {
            Some(value) => value,
            None => crate::management_v2_transfer_prepare::prepare(&self.core, &record, now)?,
        };
        record = self.persist_transfer_context(record, context.clone())?;
        record = self.begin_transfer_reconciliation(record)?;
        let context = record
            .transfer_context
            .clone()
            .ok_or(HostError::StateInvalid)?;
        let reconciliation_request = context
            .provider_reconcile_request_id
            .as_deref()
            .ok_or(HostError::StateInvalid)?;
        let route = self.core.provider_route(&record.service_id)?;
        let document = ProviderOperationTransport::new(route).reconcile(
            reconciliation_request,
            &context.owner_ref,
            &context.credential_ref,
            &context.target_device_ref,
            &context.target_nonce,
            &context.provider_operation_ref,
            &context.provider_nonce,
        )?;
        let target = DeviceId::parse(context.target_device_ref.clone())?;
        match document.kind.as_str() {
            "reissue-receipt" => {
                let owner = crate::OpaqueOwnerRef::parse(context.owner_ref.clone())?;
                let credential = CredentialId::parse(context.credential_ref.clone())?;
                let (acceptance, _) = crate::management_v2_provider_acceptance::accept_receipt(
                    document,
                    route,
                    &owner,
                    &credential,
                    &target,
                    &context.provider_nonce,
                    now,
                    true,
                )?;
                record = self.persist_transfer_acceptance(record, acceptance)?;
                self.apply_transfer_receipt(record, now)
            }
            "not-issued-reconciliation" => {
                let (acceptance, _) =
                    crate::management_v2_provider_acceptance::accept_reconciliation(
                        document,
                        route,
                        &context.provider_operation_ref,
                        &context.provider_nonce,
                        now,
                    )?;
                record = self.persist_transfer_acceptance(record, acceptance.clone())?;
                self.apply_transfer_not_issued(record, evidence, now)
            }
            "unknown-outcome" => {
                let (acceptance, _) = crate::management_v2_provider_acceptance::accept_unknown(
                    document,
                    route,
                    &context.provider_operation_ref,
                    &context.provider_nonce,
                    now,
                )?;
                self.persist_transfer_acceptance(record, acceptance)
            }
            _ => Err(HostError::EvidenceInvalid),
        }
    }

    fn apply_transfer_not_issued(
        &self,
        mut record: ManagementRecordV2,
        evidence: &[EvidenceUse<'_>],
        now: u64,
    ) -> Result<ManagementRecordV2, HostError> {
        let context = record
            .transfer_context
            .clone()
            .ok_or(HostError::StateInvalid)?;
        let acceptance = record
            .transfer_provider_acceptance
            .as_ref()
            .filter(|item| item.document.kind == "not-issued-reconciliation")
            .ok_or(HostError::StateInvalid)?;
        let signed = crate::management_v2_provider_acceptance::historic_reconciliation(
            acceptance,
            &context.provider_operation_ref,
            &context.provider_nonce,
            now,
        )?;
        let mut mutation = crate::management_v2_adapter::mutation_with_provider_key(
            &self.core,
            &record,
            now,
            &acceptance.response_public_key_hex,
        )?;
        mutation.adapter.reconcile_provider_not_issued(
            &crate::TransferId::parse(context.transfer_id)?,
            signed,
        )?;
        let prior = record.operation.state_revision;
        crate::management_v2_transfer_state::terminal(
            &mut record,
            ManagementOperationState::Cancelled,
            Some(ManagementReasonCode::OperationCancelled),
        )?;
        self.journal.replace_consuming(prior, record, evidence, now)
    }
}
