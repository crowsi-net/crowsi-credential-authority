use crowsi_credential_authority_contracts::ManagementIntentV2;

use crate::{
    CredentialId, DeviceId, HostError, host_provider_transport::ProviderOperationTransport,
    management_v2_handler::ManagementV2Handler, management_v2_record::ManagementRecordV2,
};

impl ManagementV2Handler {
    pub(crate) fn advance_revocation_rotations(
        &self,
        mut record: ManagementRecordV2,
        now: u64,
    ) -> Result<(ManagementRecordV2, bool), HostError> {
        let target_device_ref = match &record.prepared.intent {
            ManagementIntentV2::DeviceRevocation {
                target_device_ref, ..
            } => target_device_ref.clone(),
            _ => return Ok((record, true)),
        };
        record = self.start_revocation(record)?;
        loop {
            let Some(index) = record.revocation_saga.as_ref().and_then(|saga| {
                saga.rotations
                    .iter()
                    .position(|item| !item.authority_applied)
            }) else {
                return Ok((record, true));
            };
            let mut plan = record
                .revocation_saga
                .as_ref()
                .and_then(|saga| saga.rotations.get(index))
                .cloned()
                .ok_or(HostError::StateInvalid)?;
            let stored_receipt = plan
                .provider_acceptance
                .as_ref()
                .is_some_and(|value| value.document.kind == "reissue-receipt");
            if !stored_receipt {
                crate::management_v2_revocation_target::validate_rotation(
                    &self.core,
                    &record.owner_ref,
                    &record.service_id,
                    &target_device_ref,
                    &plan.credential_ref,
                    &plan.target_device_ref,
                    plan.target_binding
                        .as_ref()
                        .ok_or(HostError::StateInvalid)?,
                    now,
                )?;
            }
            let (next_record, next_plan, document) = self.rotation_document(record, index, plan)?;
            record = next_record;
            plan = next_plan;
            let Some(document) = document else {
                return Ok((record, false));
            };
            let (next_record, continue_rotation) = self.apply_rotation_document(
                record,
                index,
                &target_device_ref,
                &plan,
                document,
                now,
            )?;
            record = next_record;
            if !continue_rotation {
                return Ok((record, false));
            }
        }
    }
}

include!("management_v2_revocation_rotation_steps.rs");
