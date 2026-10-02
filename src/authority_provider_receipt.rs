use crate::{
    AuthorityError, AuthorityStore, CredentialAuthority, DurableSnapshot, ProviderEvidenceVerifier,
    ProviderReissueReceipt,
};

impl<S: AuthorityStore> CredentialAuthority<S> {
    pub(crate) fn validate_provider_receipt<V: ProviderEvidenceVerifier>(
        snapshot: &DurableSnapshot,
        record: &crate::state::TransferRecord,
        receipt: Option<&ProviderReissueReceipt>,
        verifier: &V,
        now: u64,
    ) -> Result<Option<u64>, AuthorityError> {
        let receipt = receipt.ok_or(AuthorityError::ProviderReissueReceiptRequired)?;
        let credential = snapshot
            .credentials
            .get(&record.credential_id)
            .ok_or(AuthorityError::NotFound)?;
        let valid = crate::provider_evidence::receipt_verified(receipt, verifier)
            && receipt.owner == record.owner
            && receipt.credential_id == record.credential_id
            && receipt.service == credential.service
            && receipt.provider_account == credential.provider_account
            && receipt.previous_revision == credential.revision
            && receipt.revision == credential.revision.saturating_add(1)
            && receipt.target_device == record.target_device
            && receipt.nonce == record.target_nonce
            && receipt.issued_at_ms <= now
            && !receipt.receipt_id.is_empty()
            && receipt.receipt_id.len() <= 128
            && !receipt.nonce.is_empty()
            && receipt.nonce.len() <= 128
            && !receipt.signature.is_empty()
            && receipt.signature.len() <= 1_024
            && !snapshot
                .used_provider_receipts
                .contains(&receipt.receipt_id);
        if valid {
            Ok(Some(receipt.revision))
        } else {
            Err(AuthorityError::ProviderReceiptInvalid)
        }
    }
}
