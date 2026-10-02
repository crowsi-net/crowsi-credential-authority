impl<S: AuthorityStore> CredentialAuthority<S> {
    #[allow(clippy::too_many_arguments)]
    fn accept_transfer_snapshot<V: ProviderEvidenceVerifier>(
        snapshot: &mut crate::DurableSnapshot,
        acceptance: TransferAcceptance,
        verifier: &V,
        management_authorization: Option<&str>,
        now: u64,
        fail_point: Option<CommitFailPoint>,
    ) -> Result<TransferReceipt, AuthorityError> {
        let record = snapshot
            .transfers
            .get(&acceptance.transfer_id)
            .ok_or(AuthorityError::NotFound)?
            .clone();
        if management_authorization.is_some_and(|value| {
            record.identity_nonce != format!("management-source-approval:{value}")
        }) {
            return Err(AuthorityError::IdentityAssertionInvalid);
        }
        match record.state {
            TransferState::Committed => {
                return crate::authority_commit_replay::committed_replay(
                    &record,
                    &acceptance,
                    verifier,
                );
            }
            TransferState::Cancelled => return Err(AuthorityError::TransferCancelled),
            TransferState::Prepared => {}
        }
        if record.unknown_outcome.is_some() && management_authorization.is_none() {
            return Err(AuthorityError::ProviderReconciliationRequired);
        }
        if acceptance.owner != record.owner {
            return Err(AuthorityError::WrongOwner);
        }
        if acceptance.target_device != record.target_device {
            return Err(AuthorityError::TargetDeviceMismatch);
        }
        target_proof(
            snapshot,
            &record.owner,
            &record.target_device,
            &acceptance.target_proof,
            now,
        )?;
        if acceptance.target_proof.nonce != record.target_nonce {
            return Err(AuthorityError::TargetKeyProofInvalid);
        }
        let provider_revision = Self::validate_provider_receipt(
            snapshot,
            &record,
            acceptance.provider_receipt.as_ref(),
            verifier,
            now,
        )?;
        let provider_receipt_identity = acceptance
            .provider_receipt
            .as_ref()
            .map(|value| (value.receipt_id.clone(), value.signature.clone()));
        let target_expired = snapshot
            .grants
            .get(&record.target_grant)
            .is_none_or(|grant| now > grant.expires_at_ms);
        if target_expired && management_authorization.is_none() {
            return Err(AuthorityError::GrantExpired);
        }
        let target_identity = snapshot
            .devices
            .get(&(record.owner.clone(), record.target_device.clone()))
            .ok_or(AuthorityError::WrongDevice)?
            .clone();
        if management_authorization.is_some() {
            validate_management_acceptance(snapshot, &record, &target_identity)?;
        }
        apply_transfer_commit(
            snapshot,
            record,
            acceptance,
            target_identity,
            provider_revision,
            provider_receipt_identity,
            management_authorization.is_some(),
            now,
            fail_point,
        )
    }
}

fn validate_management_acceptance(
    snapshot: &crate::DurableSnapshot,
    record: &crate::state::TransferRecord,
    target_identity: &crate::state::DeviceRecord,
) -> Result<(), AuthorityError> {
    let source_binding = record
        .management_source_binding
        .as_ref()
        .ok_or(AuthorityError::IdentityAssertionInvalid)?;
    let target_binding = record
        .management_target_binding
        .as_ref()
        .ok_or(AuthorityError::IdentityAssertionInvalid)?;
    let source_identity = snapshot
        .devices
        .get(&(record.owner.clone(), record.source_device.clone()))
        .ok_or(AuthorityError::WrongDevice)?;
    let source_grant = snapshot
        .grants
        .get(&record.source_grant)
        .ok_or(AuthorityError::NotFound)?;
    let current = !source_identity.revoked
        && !target_identity.revoked
        && matches!(source_grant.state, GrantState::Active | GrantState::Expired)
        && source_grant.source_epoch == source_identity.epoch
        && crate::authority_transfer::management_binding_current(
            snapshot,
            &record.owner,
            source_binding,
        )
        && crate::authority_transfer::management_binding_current(
            snapshot,
            &record.owner,
            target_binding,
        );
    current
        .then_some(())
        .ok_or(AuthorityError::AccountUnavailable)
}
