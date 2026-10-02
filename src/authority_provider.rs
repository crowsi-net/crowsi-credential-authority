use crate::{
    AuthorityError, AuthorityStore, CredentialAuthority, ProviderEvidenceVerifier,
    ProviderOperationOutcome, SignedProviderReconciliation, TransferId, TransferMechanism,
    TransferState,
};

impl<S: AuthorityStore> CredentialAuthority<S> {
    pub fn record_provider_outcome<V: ProviderEvidenceVerifier>(
        &mut self,
        id: &TransferId,
        outcome: ProviderOperationOutcome,
        verifier: &V,
    ) -> Result<(), AuthorityError> {
        let now = self.now_ms()?;
        if !crate::provider_evidence::outcome_verified(&outcome, verifier)
            || outcome.operation_id.is_empty()
            || outcome.operation_id.len() > 128
            || outcome.nonce.is_empty()
            || outcome.nonce.len() > 128
            || outcome.signature.is_empty()
            || outcome.signature.len() > 1_024
            || outcome.issued_at_ms > now
        {
            return Err(AuthorityError::ProviderReconciliationSignatureInvalid);
        }
        self.store.transact(|snapshot| {
            let transfer = snapshot
                .transfers
                .get_mut(id)
                .ok_or(AuthorityError::NotFound)?;
            if transfer.state != TransferState::Prepared
                || !matches!(transfer.mechanism, TransferMechanism::ProviderReissue)
            {
                return Err(AuthorityError::TransferAlreadyConsumed);
            }
            if outcome.operation_id
                != crate::provider::provider_operation_ref(&transfer.target_nonce)
                || outcome.nonce != transfer.target_nonce
            {
                return Err(AuthorityError::ProviderReconciliationSignatureInvalid);
            }
            if transfer.unknown_outcome.is_some() {
                return Err(AuthorityError::ProviderReconciliationRequired);
            }
            transfer.unknown_outcome = Some(outcome);
            Ok(())
        })
    }

    #[cfg(feature = "test-support")]
    pub fn provider_issue_attempts(&self, id: &TransferId) -> usize {
        self.store
            .read(|snapshot| {
                Ok(snapshot
                    .transfers
                    .get(id)
                    .map_or(0, |value| value.provider_attempts))
            })
            .unwrap_or(0)
    }

    #[cfg(feature = "test-support")]
    pub fn retry_provider_reissue(&mut self, id: &TransferId) -> Result<(), AuthorityError> {
        self.store.read(|snapshot| {
            let transfer = snapshot.transfers.get(id).ok_or(AuthorityError::NotFound)?;
            if transfer.unknown_outcome.is_some() {
                Err(AuthorityError::BlindProviderRetryForbidden)
            } else {
                Err(AuthorityError::ProviderReconciliationRequired)
            }
        })
    }

    #[cfg(feature = "test-support")]
    pub fn reconcile_provider_outcome<V: ProviderEvidenceVerifier>(
        &mut self,
        id: &TransferId,
        reconciliation: SignedProviderReconciliation,
        verifier: &V,
    ) -> Result<(), AuthorityError> {
        let now = self.now_ms()?;
        self.store.transact(|snapshot| {
            reconcile_not_issued(snapshot, id, reconciliation, verifier, now, true)
        })
    }

    pub fn reconcile_provider_not_issued<V: ProviderEvidenceVerifier>(
        &mut self,
        id: &TransferId,
        reconciliation: SignedProviderReconciliation,
        verifier: &V,
    ) -> Result<(), AuthorityError> {
        let now = self.now_ms()?;
        self.store.transact(|snapshot| {
            reconcile_not_issued(snapshot, id, reconciliation, verifier, now, false)
        })
    }
}

fn reconcile_not_issued<V: ProviderEvidenceVerifier>(
    snapshot: &mut crate::state::DurableSnapshot,
    id: &TransferId,
    reconciliation: SignedProviderReconciliation,
    verifier: &V,
    now: u64,
    require_unknown: bool,
) -> Result<(), AuthorityError> {
    let transfer = snapshot
        .transfers
        .get(id)
        .ok_or(AuthorityError::NotFound)?
        .clone();
    let expected_operation = crate::provider::provider_operation_ref(&transfer.target_nonce);
    let nonce_key = format!("reconciliation:{}", reconciliation.nonce);
    let signed = crate::provider_evidence::reconciliation_verified(&reconciliation, verifier)
        && reconciliation.operation_id == expected_operation
        && reconciliation.nonce == transfer.target_nonce
        && !reconciliation.signature.is_empty()
        && reconciliation.signature.len() <= 1_024
        && reconciliation.issued_at_ms <= now
        && !reconciliation.was_issued;
    if transfer.state == TransferState::Cancelled
        && signed
        && snapshot.used_nonces.contains(&nonce_key)
    {
        return Ok(());
    }
    if transfer.state != TransferState::Prepared {
        return Err(AuthorityError::TransferAlreadyConsumed);
    }
    let unknown_matches = transfer.unknown_outcome.as_ref().is_some_and(|value| {
        value.operation_id == expected_operation && value.nonce == transfer.target_nonce
    });
    if require_unknown && !unknown_matches {
        return Err(AuthorityError::ProviderReconciliationRequired);
    }
    let valid = signed && !snapshot.used_nonces.contains(&nonce_key);
    if !valid {
        return Err(AuthorityError::ProviderReconciliationSignatureInvalid);
    }
    crate::authority_transfer_cancel::grants(snapshot, &transfer, now)?;
    snapshot
        .transfers
        .get_mut(id)
        .ok_or(AuthorityError::NotFound)?
        .state = TransferState::Cancelled;
    snapshot.used_nonces.insert(nonce_key);
    Ok(())
}
