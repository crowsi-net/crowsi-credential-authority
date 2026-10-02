use crate::{
    CoelaAuthorityAdapter, GrantAudience, HostError, OpaqueOwnerRef,
    host_identity::{HostIdentityVerifier, HostOwnerMapper},
    host_proofs::HostProofVerifier,
    management_v2_host_context::{ManagementHostAdapter, ManagementHostContext},
    management_v2_record::ManagementRecordV2,
};

pub(crate) struct HostMutationContext {
    pub adapter: ManagementHostAdapter,
    pub owner: OpaqueOwnerRef,
}

pub(crate) fn open(
    core: &ManagementHostContext,
    value: &ManagementRecordV2,
    now: u64,
) -> Result<HostMutationContext, HostError> {
    let owner = OpaqueOwnerRef::parse(value.owner_ref.clone())?;
    let source_identity = value.source_identity()?;
    let identity = HostIdentityVerifier::new(&core.config, source_identity.current_status.clone());
    let mapper = HostOwnerMapper(core.config.document.owner_mappings.clone());
    // Local iHAT-authorized revocation never consumes provider evidence. Keeping
    // this adapter independent of the current provider route lets a previously
    // accepted final iHAT result finish after a signed config rotation removes
    // that route.
    let proofs = HostProofVerifier::new(None, None, String::new());
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
    Ok(HostMutationContext { adapter, owner })
}
