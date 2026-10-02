#[allow(clippy::too_many_arguments)]
fn apply_transfer_commit(
    snapshot: &mut crate::DurableSnapshot,
    record: crate::state::TransferRecord,
    acceptance: TransferAcceptance,
    target_identity: crate::state::DeviceRecord,
    provider_revision: Option<u64>,
    provider_receipt_identity: Option<(String, String)>,
    management: bool,
    now: u64,
    fail_point: Option<CommitFailPoint>,
) -> Result<TransferReceipt, AuthorityError> {
    if fail_point == Some(CommitFailPoint::BeforeSourceRevoke) {
        return Err(AuthorityError::AtomicCommitFailed);
    }
    if !snapshot.grants.contains_key(&record.source_grant) {
        return Err(AuthorityError::NotFound);
    }
    for (id, grant) in &mut snapshot.grants {
        if *id != record.target_grant
            && grant.credential_id == record.credential_id
            && matches!(grant.state, GrantState::Active | GrantState::Pending)
        {
            grant.state = GrantState::Revoked;
        }
    }
    if fail_point == Some(CommitFailPoint::AfterSourceRevokeBeforeTargetActivate) {
        return Err(AuthorityError::AtomicCommitFailed);
    }
    let target = snapshot
        .grants
        .get_mut(&record.target_grant)
        .ok_or(AuthorityError::NotFound)?;
    promote_to_target_identity(target, &record.target_device, &target_identity);
    if management {
        target.expires_at_ms = now.saturating_add(30_000);
    }
    target.state = GrantState::Active;
    if let Some(revision) = provider_revision {
        target.credential_revision = revision;
    }
    if fail_point == Some(CommitFailPoint::BeforeReceiptPersist) {
        return Err(AuthorityError::AtomicCommitFailed);
    }
    snapshot
        .used_nonces
        .insert(format!("target:{}", acceptance.target_proof.nonce));
    if let Some(receipt) = acceptance.provider_receipt {
        snapshot.used_provider_receipts.insert(receipt.receipt_id);
        if let Some(credential) = snapshot.credentials.get_mut(&record.credential_id) {
            credential.revision = receipt.revision;
            credential.updated_at_ms = now;
        }
    }
    let transfer = snapshot
        .transfers
        .get_mut(&record.id)
        .ok_or(AuthorityError::NotFound)?;
    transfer.state = TransferState::Committed;
    transfer.unknown_outcome = None;
    transfer.provider_revision = provider_revision;
    if let Some((receipt_id, signature)) = provider_receipt_identity {
        transfer.provider_receipt_id = Some(receipt_id);
        transfer.provider_receipt_signature = Some(signature);
    }
    Ok(TransferReceipt {
        id: record.id,
        source_grant: record.source_grant,
        target_grant: record.target_grant,
        state: TransferState::Committed,
        provider_revision,
    })
}
