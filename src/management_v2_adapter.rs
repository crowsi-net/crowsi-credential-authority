use crate::{
    CoelaAuthorityAdapter, DeviceId, GrantAudience, HostError, OpaqueOwnerRef, StepUpProof,
    TargetKeyProof,
    host_identity::{HostIdentityVerifier, HostOwnerMapper},
    host_proofs::HostProofVerifier,
    management_v2_host_context::{ManagementHostAdapter, ManagementHostContext},
    management_v2_record::ManagementRecordV2,
};

pub(crate) struct MutationContext {
    pub adapter: ManagementHostAdapter,
    pub owner: OpaqueOwnerRef,
    pub source: DeviceId,
    pub target: TargetKeyProof,
    pub step_up: StepUpProof,
}

pub(crate) struct SourceMutationContext {
    pub adapter: ManagementHostAdapter,
    pub owner: OpaqueOwnerRef,
}

pub(crate) fn mutation(
    core: &ManagementHostContext,
    value: &ManagementRecordV2,
    now: u64,
) -> Result<MutationContext, HostError> {
    let key = core
        .provider_route(&value.service_id)?
        .response_public_key_hex
        .clone();
    mutation_with_provider_key(core, value, now, &key)
}

pub(crate) fn mutation_with_provider_key(
    core: &ManagementHostContext,
    value: &ManagementRecordV2,
    now: u64,
    provider_public_key: &str,
) -> Result<MutationContext, HostError> {
    let fresh = value.source_fresh_uv()?;
    let target = value
        .target_proof
        .as_ref()
        .ok_or(HostError::EvidenceInvalid)?;
    let owner = OpaqueOwnerRef::parse(value.owner_ref.clone())?;
    let source = DeviceId::parse(value.prepared.source_device_ref.clone())?;
    let target_proof = TargetKeyProof::verified(
        owner.clone(),
        DeviceId::parse(target.binding.target_device_ref.clone())?,
        target.binding.device_proof_key_ref.clone(),
        target.binding.nonce.clone(),
        target.binding.issued_at_epoch_s.saturating_mul(1_000),
    );
    let step_up = StepUpProof::verified(
        owner.clone(),
        source.clone(),
        fresh.issued_at_epoch_s.saturating_mul(1_000),
        fresh.expires_at_epoch_s.saturating_mul(1_000),
    );
    let source_identity = value.source_identity()?;
    let identity = HostIdentityVerifier::new(&core.config, source_identity.current_status.clone());
    let mapper = HostOwnerMapper(core.config.document.owner_mappings.clone());
    let proofs = HostProofVerifier::new(
        Some(step_up.clone()),
        Some(target_proof.clone()),
        provider_public_key.to_owned(),
    );
    let adapter = CoelaAuthorityAdapter::open_anchored(
        &core.config.document.authority_store_directory,
        &core.config.document.authority_anchor_directory,
        now.saturating_mul(1_000),
        crate::GrantAudience::parse(core.config.document.registration_audience.clone())?,
        crate::GrantAudience::parse(core.config.document.management_audience.clone())?,
        identity,
        mapper,
        proofs,
    )?;
    Ok(MutationContext {
        adapter,
        owner,
        source,
        target: target_proof,
        step_up,
    })
}

pub(crate) fn source_mutation_with_provider_key(
    core: &ManagementHostContext,
    value: &ManagementRecordV2,
    now: u64,
    provider_public_key: &str,
) -> Result<SourceMutationContext, HostError> {
    let fresh = value.source_fresh_uv()?;
    let owner = OpaqueOwnerRef::parse(value.owner_ref.clone())?;
    let source = DeviceId::parse(value.prepared.source_device_ref.clone())?;
    let step_up = StepUpProof::verified(
        owner.clone(),
        source,
        fresh.issued_at_epoch_s.saturating_mul(1_000),
        fresh.expires_at_epoch_s.saturating_mul(1_000),
    );
    let source_identity = value.source_identity()?;
    let identity = HostIdentityVerifier::new(&core.config, source_identity.current_status.clone());
    let mapper = HostOwnerMapper(core.config.document.owner_mappings.clone());
    let proofs =
        HostProofVerifier::new(Some(step_up.clone()), None, provider_public_key.to_owned());
    let adapter = CoelaAuthorityAdapter::open_anchored(
        &core.config.document.authority_store_directory,
        &core.config.document.authority_anchor_directory,
        now.saturating_mul(1_000),
        GrantAudience::parse(core.config.document.registration_audience.clone())?,
        GrantAudience::parse(core.config.document.management_audience.clone())?,
        identity,
        mapper,
        proofs,
    )?;
    Ok(SourceMutationContext { adapter, owner })
}
