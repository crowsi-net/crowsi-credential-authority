impl<S: AuthorityStore> CredentialAuthority<S> {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn apply_host_revocation_rotation<V: ProviderEvidenceVerifier>(
        &mut self,
        operation_id: &str,
        owner: &OpaqueOwnerRef,
        credential_id: &CredentialId,
        compromised: &DeviceId,
        provider_nonce: &str,
        target_binding: &crate::management_v2_record::RevocationTargetBindingV1,
        receipt: ProviderReissueReceipt,
        verifier: &V,
    ) -> Result<RevisionReceipt, AuthorityError> {
        let now = self.now_ms()?;
        self.store.transact(|snapshot| {
            let credential = snapshot
                .credentials
                .get(credential_id)
                .ok_or(AuthorityError::NotFound)?
                .clone();
            let receipt_exact = crate::provider_evidence::receipt_verified(&receipt, verifier)
                && credential.owner == *owner
                && receipt.owner == *owner
                && receipt.credential_id == *credential_id
                && receipt.service == credential.service
                && target_binding.service_id == credential.service.as_str()
                && receipt.provider_account == credential.provider_account
                && receipt.previous_revision.saturating_add(1) == receipt.revision
                && receipt.target_device != *compromised
                && receipt.nonce == provider_nonce
                && receipt.issued_at_ms <= now;
            if !receipt_exact {
                return Err(AuthorityError::ProviderReceiptInvalid);
            }
            let replay = replay_key(
                operation_id,
                provider_nonce,
                target_binding,
                &receipt.receipt_id,
            )?;
            if snapshot
                .used_provider_receipts
                .contains(&receipt.receipt_id)
            {
                return snapshot
                    .used_nonces
                    .contains(&replay)
                    .then_some(RevisionReceipt {
                        previous: receipt.previous_revision,
                        current: receipt.revision,
                    })
                    .ok_or(AuthorityError::ProviderReceiptInvalid);
            }
            let target_identity = snapshot
                .devices
                .get(&(owner.clone(), receipt.target_device.clone()))
                .ok_or(AuthorityError::WrongDevice)?
                .clone();
            let current = !credential.revoked
                && credential.revision == receipt.previous_revision
                && credential.revision == target_binding.credential_revision
                && target_identity.service_id == credential.service
                && target_exact(&target_identity, target_binding);
            if !current {
                return Err(AuthorityError::ProviderReceiptInvalid);
            }
            let templates =
                bound_grants(snapshot, owner, credential_id, compromised, target_binding)?;
            let updated = snapshot
                .credentials
                .get_mut(credential_id)
                .ok_or(AuthorityError::NotFound)?;
            updated.revision = receipt.revision;
            updated.updated_at_ms = now;
            for grant in snapshot.grants.values_mut().filter(|grant| {
                grant.owner == *owner
                    && grant.credential_id == *credential_id
                    && grant.credential_revision == receipt.previous_revision
            }) {
                if grant.source_device == *compromised || grant.target_device == *compromised {
                    grant.state = GrantState::Revoked;
                } else if matches!(grant.state, GrantState::Active | GrantState::Pending) {
                    grant.credential_revision = receipt.revision;
                }
            }
            crate::authority_grant_limits::expire(snapshot, now);
            for template in templates {
                promote_bound_grant(
                    snapshot,
                    owner,
                    credential_id,
                    &receipt.target_device,
                    &target_identity,
                    receipt.revision,
                    now,
                    template,
                );
            }
            if !crate::authority_grant_limits::capacity_complete(snapshot) {
                return Err(AuthorityError::ProviderReceiptInvalid);
            }
            snapshot.used_provider_receipts.insert(receipt.receipt_id);
            snapshot.used_nonces.insert(replay);
            Ok(RevisionReceipt {
                previous: receipt.previous_revision,
                current: receipt.revision,
            })
        })
    }
}
