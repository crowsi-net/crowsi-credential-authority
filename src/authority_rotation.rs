use crate::validation::{active_account, step_up};
use crate::{
    AuthorityError, AuthorityStore, CredentialAuthority, CredentialId, GrantState, OpaqueOwnerRef,
    ProviderEvidenceVerifier, ProviderReissueReceipt, RevisionReceipt, StepUpProof,
};

impl<S: AuthorityStore> CredentialAuthority<S> {
    pub fn record_provider_reissue<V: ProviderEvidenceVerifier>(
        &mut self,
        owner: &OpaqueOwnerRef,
        id: &CredentialId,
        receipt: ProviderReissueReceipt,
        proof: StepUpProof,
        verifier: &V,
    ) -> Result<RevisionReceipt, AuthorityError> {
        let now = self.now_ms()?;
        self.store.transact(|snapshot| {
            active_account(snapshot, owner)?;
            step_up(snapshot, owner, &proof.device, &proof, now)?;
            let credential = snapshot
                .credentials
                .get(id)
                .ok_or(AuthorityError::NotFound)?
                .clone();
            let target_registered = snapshot
                .devices
                .contains_key(&(owner.clone(), receipt.target_device.clone()));
            let valid = crate::provider_evidence::receipt_verified(&receipt, verifier)
                && &receipt.owner == owner
                && &receipt.credential_id == id
                && receipt.service == credential.service
                && receipt.provider_account == credential.provider_account
                && receipt.previous_revision == credential.revision
                && receipt.revision == credential.revision.saturating_add(1)
                && receipt.issued_at_ms <= now
                && target_registered
                && !receipt.receipt_id.is_empty()
                && !snapshot
                    .used_provider_receipts
                    .contains(&receipt.receipt_id);
            if !valid {
                return Err(AuthorityError::ProviderReceiptInvalid);
            }
            let previous = credential.revision;
            let updated = snapshot
                .credentials
                .get_mut(id)
                .ok_or(AuthorityError::NotFound)?;
            updated.revision = receipt.revision;
            updated.updated_at_ms = now;
            for grant in snapshot.grants.values_mut() {
                if &grant.credential_id == id
                    && grant.credential_revision == previous
                    && matches!(grant.state, GrantState::Active | GrantState::Pending)
                {
                    grant.state = GrantState::Revoked;
                }
            }
            snapshot.used_provider_receipts.insert(receipt.receipt_id);
            snapshot
                .used_nonces
                .insert(format!("provider:{}", receipt.nonce));
            Ok(RevisionReceipt {
                previous,
                current: receipt.revision,
            })
        })
    }
}
