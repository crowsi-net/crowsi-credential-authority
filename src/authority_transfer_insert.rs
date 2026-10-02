#[allow(clippy::too_many_arguments)]
fn insert_prepared_transfer(
    snapshot: &mut crate::DurableSnapshot,
    request: TransferRequest,
    identity_nonce: String,
    management_bindings: Option<(
        &crate::transfer::ManagementDeviceBinding,
        &crate::transfer::ManagementDeviceBinding,
    )>,
    credential_revision: u64,
    source: crate::state::DeviceRecord,
    target_device: crate::state::DeviceRecord,
    now: u64,
) -> TransferReceipt {
    let source_id = GrantId::trusted(format!("grant-{}", snapshot.next_sequence()));
    let target_id = GrantId::trusted(format!("grant-{}", snapshot.next_sequence()));
    let transfer_id = TransferId::trusted(format!("transfer-{}", snapshot.next_sequence()));
    let expires = now.saturating_add(request.ttl_ms);
    let base = DeviceGrant {
        id: source_id.clone(),
        owner: request.owner.clone(),
        credential_id: request.credential_id.clone(),
        credential_revision,
        source_device: request.source_device.clone(),
        target_device: request.source_device.clone(),
        audience: request.audience.clone(),
        action: request.action.clone(),
        source_epoch: source.epoch,
        target_epoch: source.epoch,
        pairwise_subject_ref: source.pairwise_subject_ref.clone(),
        identity_issuer: source.issuer.clone(),
        identity_service_id: source.service_id.clone(),
        source_key_thumbprint: source.key_thumbprint.clone(),
        target_key_thumbprint: source.key_thumbprint.clone(),
        source_posture_revision: source.posture_revision,
        target_posture_revision: source.posture_revision,
        source_posture_state: source.posture_state.clone(),
        subject_revocation_epoch: source.subject_revocation_epoch,
        service_revocation_epoch: source.service_revocation_epoch,
        session_revocation_epoch: source.session_revocation_epoch,
        identity_key_id: source.key_id,
        expires_at_ms: expires,
        state: GrantState::Active,
    };
    let mut target = base.clone();
    target.id = target_id.clone();
    target.target_device = request.target_device.clone();
    target.target_epoch = target_device.epoch;
    target.target_key_thumbprint = target_device.key_thumbprint;
    target.target_posture_revision = target_device.posture_revision;
    target.state = GrantState::Pending;
    snapshot.grants.insert(source_id.clone(), base);
    snapshot.grants.insert(target_id.clone(), target);
    snapshot.transfers.insert(
        transfer_id.clone(),
        TransferRecord {
            id: transfer_id.clone(),
            owner: request.owner,
            credential_id: request.credential_id,
            source_device: request.source_device,
            target_device: request.target_device,
            source_grant: source_id.clone(),
            target_grant: target_id.clone(),
            mechanism: request.mechanism,
            target_nonce: request.target_proof.nonce,
            identity_nonce,
            management_source_binding: management_bindings.map(|item| item.0.clone()),
            management_target_binding: management_bindings.map(|item| item.1.clone()),
            state: TransferState::Prepared,
            provider_revision: None,
            provider_receipt_id: None,
            provider_receipt_signature: None,
            provider_attempts: 1,
            unknown_outcome: None,
        },
    );
    TransferReceipt {
        id: transfer_id,
        source_grant: source_id,
        target_grant: target_id,
        state: TransferState::Prepared,
        provider_revision: None,
    }
}
