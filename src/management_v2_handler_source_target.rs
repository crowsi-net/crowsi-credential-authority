fn bind_revocation_target(
    handler: &ManagementV2Handler,
    verified: &VerifiedManagementIdentity<'_>,
    prepared: &EndpointPreparedOperationV2,
    snapshot: &crowsi_credential_authority_contracts::ManagementSnapshotV2,
    revocation_saga: &mut Option<crate::management_v2_record::RevocationSagaV2>,
    now: u64,
) -> Result<(), HostError> {
    let (
        crowsi_credential_authority_contracts::ManagementIntentV2::DeviceRevocation {
            target_device_ref,
            ..
        },
        Some(saga),
    ) = (&prepared.intent, revocation_saga)
    else {
        return Ok(());
    };
    let mut candidates = snapshot
        .devices
        .iter()
        .filter(|item| {
            item.device_ref != *target_device_ref
                && item.status
                    == crowsi_credential_authority_contracts::ManagementLifecycleV2::Active
        })
        .map(|item| item.device_ref.clone())
        .collect::<Vec<_>>();
    candidates.sort();
    crate::management_v2_revocation_target::bind(
        &handler.core,
        &verified.owner.opaque_owner_ref,
        &verified.identity.assertion.service_id,
        target_device_ref,
        &candidates,
        saga,
        now,
    )
}
