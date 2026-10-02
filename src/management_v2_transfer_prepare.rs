use crowsi_credential_authority_contracts::ManagementIntentV2;

use crate::{
    CredentialAuthority, CredentialId, DeviceId, FileAuthorityStore, GrantAction, GrantAudience,
    HostError, OpaqueOwnerRef, ServiceId, TargetKeyProof, TransferMechanism, TransferRequest,
    management_v2_host_context::ManagementHostContext, management_v2_record::ManagementRecordV2,
    management_v2_transfer_context::TransferContextV2,
};

pub(crate) fn prepare(
    core: &ManagementHostContext,
    record: &ManagementRecordV2,
    now: u64,
) -> Result<TransferContextV2, HostError> {
    let ManagementIntentV2::DeviceTransfer {
        credential_refs,
        target_device_ref,
        ..
    } = &record.prepared.intent
    else {
        return Err(HostError::OperationInvalid);
    };
    let [credential_ref] = credential_refs.as_slice() else {
        return Err(HostError::OperationInvalid);
    };
    let owner = OpaqueOwnerRef::parse(record.owner_ref.clone())?;
    let source = DeviceId::parse(record.prepared.source_device_ref.clone())?;
    let target = DeviceId::parse(target_device_ref.clone())?;
    let credential = CredentialId::parse(credential_ref.clone())?;
    let authorization = record
        .source_approval_acceptance_sha256
        .as_deref()
        .ok_or(HostError::EvidenceInvalid)?;
    let source_identity = record
        .source_approval_identity_exchange
        .as_ref()
        .ok_or(HostError::EvidenceInvalid)
        .and_then(|value| {
            crowsi_credential_authority_contracts::identity_evidence_from_exchange(value)
                .map_err(|_| HostError::EvidenceInvalid)
        })?;
    let target_identity = record
        .target_identity()?
        .ok_or(HostError::EvidenceInvalid)?;
    let source_binding =
        crate::transfer::ManagementDeviceBinding::from_assertion(&source_identity.assertion)?;
    let target_binding =
        crate::transfer::ManagementDeviceBinding::from_assertion(&target_identity.assertion)?;
    let target_proof = record
        .target_proof
        .as_ref()
        .ok_or(HostError::EvidenceInvalid)?;
    let target_key = TargetKeyProof::verified(
        owner.clone(),
        target.clone(),
        target_proof.binding.device_proof_key_ref.clone(),
        target_proof.binding.nonce.clone(),
        target_proof.binding.issued_at_epoch_s.saturating_mul(1_000),
    );
    let store = FileAuthorityStore::open_anchored(
        &core.config.document.authority_store_directory,
        &core.config.document.authority_anchor_directory,
    )?;
    if let Some(receipt) = CredentialAuthority::with_store(store, now.saturating_mul(1_000))
        .recover_management_transfer(
            &owner,
            &credential,
            &ServiceId::parse(record.service_id.clone())?,
            &source,
            &target,
            target_key.nonce(),
            authorization,
            &source_binding,
            &target_binding,
        )?
    {
        return Ok(context(
            &receipt,
            &owner,
            &target_key,
            record,
            credential_ref,
        ));
    }
    let mut mutation = crate::management_v2_adapter::mutation(core, record, now)?;
    let action = GrantAction::parse(
        record
            .grant_action
            .clone()
            .ok_or(HostError::OperationInvalid)?,
    )?;
    let ttl_ms = 30_000;
    let request = TransferRequest::new(
        mutation.owner.clone(),
        credential.clone(),
        mutation.source.clone(),
        target.clone(),
        GrantAudience::parse(core.config.document.management_audience.clone())?,
        action,
        TransferMechanism::ProviderReissue,
        ttl_ms,
        mutation.step_up,
        mutation.target.clone(),
    );
    let receipt = mutation.adapter.prepare_management_transfer(
        request,
        authorization,
        &source_binding,
        &target_binding,
    )?;
    Ok(context(
        &receipt,
        &mutation.owner,
        &mutation.target,
        record,
        credential_ref,
    ))
}

fn context(
    receipt: &crate::TransferReceipt,
    owner: &OpaqueOwnerRef,
    target: &TargetKeyProof,
    record: &ManagementRecordV2,
    credential: &str,
) -> TransferContextV2 {
    TransferContextV2::new(
        receipt.id(),
        owner,
        target,
        &record.service_id,
        credential,
        &crate::provider::provider_operation_ref(target.nonce()),
        target.nonce(),
    )
}
