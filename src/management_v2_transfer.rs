use crowsi_credential_authority_contracts::{ManagementOperationState, ManagementReasonCode};

use crate::{
    CredentialId, DeviceId, HostError, TransferAcceptance,
    host_provider_transport::ProviderOperationTransport,
    management_v2_handler::ManagementV2Handler, management_v2_record::ManagementRecordV2,
};

impl ManagementV2Handler {
    pub(crate) fn execute_transfer(
        &self,
        mut record: ManagementRecordV2,
        now: u64,
    ) -> Result<ManagementRecordV2, HostError> {
        if record.operation.state != ManagementOperationState::Unknown {
            return Err(HostError::StateInvalid);
        }
        if record.transfer_context.is_none() {
            match crate::management_v2_transfer_prepare::prepare(&self.core, &record, now) {
                Ok(context) => {
                    record.provider_transfer_id = Some(context.transfer_id.clone());
                    record.transfer_context = Some(context);
                    crate::management_v2_transfer_state::bump(&mut record)?;
                    record = self
                        .journal
                        .replace(record.operation.state_revision - 1, record)?;
                }
                Err(_) => return self.reject(record, ManagementReasonCode::StateConflict),
            }
        }
        let context = record
            .transfer_context
            .clone()
            .ok_or(HostError::StateInvalid)?;
        let route = self.core.provider_route(&record.service_id)?;
        let Ok(document) = ProviderOperationTransport::new(route).reissue(
            &context.provider_operation_ref,
            &context.owner_ref,
            &context.credential_ref,
            &context.target_device_ref,
            &context.provider_nonce,
        ) else {
            return Ok(record);
        };
        match document.kind.as_str() {
            "reissue-receipt" => {
                let owner = crate::OpaqueOwnerRef::parse(context.owner_ref.clone())?;
                let credential = CredentialId::parse(context.credential_ref.clone())?;
                let target = DeviceId::parse(context.target_device_ref.clone())?;
                let (acceptance, _) = crate::management_v2_provider_acceptance::accept_receipt(
                    document,
                    route,
                    &owner,
                    &credential,
                    &target,
                    &context.provider_nonce,
                    now,
                    false,
                )?;
                record = self.persist_transfer_acceptance(record, acceptance)?;
                self.apply_transfer_receipt(record, now)
            }
            "unknown-outcome" => {
                let (acceptance, outcome) =
                    crate::management_v2_provider_acceptance::accept_unknown(
                        document,
                        route,
                        &context.provider_operation_ref,
                        &context.provider_nonce,
                        now,
                    )?;
                record = self.persist_transfer_acceptance(record, acceptance.clone())?;
                let mut mutation = crate::management_v2_adapter::mutation_with_provider_key(
                    &self.core,
                    &record,
                    now,
                    &acceptance.response_public_key_hex,
                )?;
                mutation.adapter.record_unknown_provider_outcome(
                    &crate::TransferId::parse(context.transfer_id)?,
                    outcome,
                )?;
                Ok(record)
            }
            _ => Err(HostError::EvidenceInvalid),
        }
    }

    fn reject(
        &self,
        mut value: ManagementRecordV2,
        reason: ManagementReasonCode,
    ) -> Result<ManagementRecordV2, HostError> {
        let prior = value.operation.state_revision;
        value.operation.state = ManagementOperationState::Rejected;
        value.operation.state_revision = prior.checked_add(1).ok_or(HostError::StateInvalid)?;
        value.operation.reason = Some(reason);
        value.operation.reconcile_digest = None;
        value.operation.actor = crate::management_v2_state::none_actor();
        self.journal.replace(prior, value)
    }
}

include!("management_v2_transfer_progress.rs");
