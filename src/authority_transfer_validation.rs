fn validate_transfer_request(
    snapshot: &crate::DurableSnapshot,
    request: &TransferRequest,
    management_bindings: Option<(
        &crate::transfer::ManagementDeviceBinding,
        &crate::transfer::ManagementDeviceBinding,
    )>,
    credential: &crate::CredentialMetadata,
    now: u64,
) -> Result<(), AuthorityError> {
    if credential.owner != request.owner {
        return Err(AuthorityError::WrongOwner);
    }
    if credential.revoked {
        return Err(AuthorityError::AccountUnavailable);
    }
    if let Some((source, target)) = management_bindings {
        let exact = source.device_id == request.source_device
            && target.device_id == request.target_device
            && source.service_id == credential.service
            && target.service_id == credential.service
            && source.issuer == target.issuer
            && source.pairwise_subject == target.pairwise_subject
            && management_binding_current(snapshot, &request.owner, source)
            && management_binding_current(snapshot, &request.owner, target);
        if !exact {
            return Err(AuthorityError::IdentityAssertionInvalid);
        }
    }
    step_up(
        snapshot,
        &request.owner,
        &request.source_device,
        &request.step_up,
        now,
    )?;
    target_proof(
        snapshot,
        &request.owner,
        &request.target_device,
        &request.target_proof,
        now,
    )
}

fn existing_transfer(
    snapshot: &crate::DurableSnapshot,
    request: &TransferRequest,
    identity_nonce: &str,
) -> Result<Option<TransferReceipt>, AuthorityError> {
    let Some(existing) = snapshot
        .transfers
        .values()
        .find(|value| value.target_nonce == request.target_proof.nonce)
    else {
        return Ok(None);
    };
    let exact = existing.owner == request.owner
        && existing.credential_id == request.credential_id
        && existing.source_device == request.source_device
        && existing.target_device == request.target_device
        && existing.mechanism == request.mechanism
        && existing.identity_nonce == identity_nonce;
    if !exact {
        return Err(AuthorityError::TargetKeyProofInvalid);
    }
    Ok(Some(TransferReceipt {
        id: existing.id.clone(),
        source_grant: existing.source_grant.clone(),
        target_grant: existing.target_grant.clone(),
        state: existing.state,
        provider_revision: existing.provider_revision,
    }))
}
