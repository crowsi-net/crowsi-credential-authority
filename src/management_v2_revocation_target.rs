use crate::{
    CredentialAuthority, CredentialId, DeviceId, FileAuthorityStore, HostError, OpaqueOwnerRef,
    ServiceId, management_v2_host_context::ManagementHostContext,
    management_v2_record::RevocationSagaV2,
};

pub(crate) fn bind(
    core: &ManagementHostContext,
    owner: &str,
    service: &str,
    compromised: &str,
    candidates: &[String],
    saga: &mut RevocationSagaV2,
    now: u64,
) -> Result<(), HostError> {
    let store = FileAuthorityStore::open_anchored(
        &core.config.document.authority_store_directory,
        &core.config.document.authority_anchor_directory,
    )?;
    let authority = CredentialAuthority::with_store(store, now.saturating_mul(1_000));
    let owner = OpaqueOwnerRef::parse(owner.to_owned())?;
    let service = ServiceId::parse(service.to_owned())?;
    let compromised = DeviceId::parse(compromised.to_owned())?;
    for rotation in &mut saga.rotations {
        let (target, binding) = authority.management_rotation_target(
            &owner,
            &service,
            &CredentialId::parse(rotation.credential_ref.clone())?,
            &compromised,
            candidates,
        )?;
        target.as_str().clone_into(&mut rotation.target_device_ref);
        rotation.target_binding = Some(binding);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn validate_rotation(
    core: &ManagementHostContext,
    owner: &str,
    service: &str,
    compromised: &str,
    credential: &str,
    target: &str,
    expected: &crate::management_v2_record::RevocationTargetBindingV1,
    now: u64,
) -> Result<(), HostError> {
    let store = FileAuthorityStore::open_anchored(
        &core.config.document.authority_store_directory,
        &core.config.document.authority_anchor_directory,
    )?;
    CredentialAuthority::with_store(store, now.saturating_mul(1_000))
        .management_rotation_target_current(
            &OpaqueOwnerRef::parse(owner.to_owned())?,
            &ServiceId::parse(service.to_owned())?,
            &CredentialId::parse(credential.to_owned())?,
            &DeviceId::parse(target.to_owned())?,
            &DeviceId::parse(compromised.to_owned())?,
            expected,
        )?;
    Ok(())
}
