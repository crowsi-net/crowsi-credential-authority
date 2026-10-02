fn prepare_transfer_snapshot(
    snapshot: &mut crate::DurableSnapshot,
    request: TransferRequest,
    identity_nonce: String,
    management_bindings: Option<(
        &crate::transfer::ManagementDeviceBinding,
        &crate::transfer::ManagementDeviceBinding,
    )>,
    now: u64,
) -> Result<TransferReceipt, AuthorityError> {
    crate::authority_grant_limits::expire(snapshot, now);
    active_account(snapshot, &request.owner)?;
    let credential = snapshot
        .credentials
        .get(&request.credential_id)
        .ok_or(AuthorityError::NotFound)?
        .clone();
    validate_transfer_request(snapshot, &request, management_bindings, &credential, now)?;
    if let Some(receipt) = existing_transfer(snapshot, &request, &identity_nonce)? {
        return Ok(receipt);
    }
    if !crate::authority_grant_limits::transfer_available(
        snapshot,
        &request.owner,
        &request.credential_id,
    ) {
        return Err(AuthorityError::InvalidValue(
            "device credential grant capacity",
        ));
    }
    if !snapshot.used_nonces.insert(identity_nonce.clone()) {
        return Err(AuthorityError::IdentityAssertionReplay);
    }
    let source = snapshot
        .devices
        .get(&(request.owner.clone(), request.source_device.clone()))
        .ok_or(AuthorityError::WrongDevice)?
        .clone();
    let target = snapshot
        .devices
        .get(&(request.owner.clone(), request.target_device.clone()))
        .ok_or(AuthorityError::WrongDevice)?
        .clone();
    if source.revoked
        || target.revoked
        || source.service_id != credential.service
        || source.owner != request.owner
        || target.owner != request.owner
    {
        return Err(AuthorityError::AccountUnavailable);
    }
    Ok(insert_prepared_transfer(
        snapshot,
        request,
        identity_nonce,
        management_bindings,
        credential.revision,
        source,
        target,
        now,
    ))
}
