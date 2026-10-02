use crate::{
    AuthorityError, ProviderEvidenceVerifier, TransferAcceptance, TransferReceipt, TransferState,
};

pub(crate) fn committed_replay<V: ProviderEvidenceVerifier>(
    record: &crate::state::TransferRecord,
    acceptance: &TransferAcceptance,
    verifier: &V,
) -> Result<TransferReceipt, AuthorityError> {
    let receipt = acceptance
        .provider_receipt
        .as_ref()
        .ok_or(AuthorityError::ProviderReissueReceiptRequired)?;
    let exact = acceptance.owner == record.owner
        && acceptance.target_device == record.target_device
        && acceptance.target_proof.nonce == record.target_nonce
        && receipt.owner == record.owner
        && receipt.credential_id == record.credential_id
        && receipt.target_device == record.target_device
        && receipt.nonce == record.target_nonce
        && Some(receipt.revision) == record.provider_revision
        && Some(&receipt.receipt_id) == record.provider_receipt_id.as_ref()
        && Some(&receipt.signature) == record.provider_receipt_signature.as_ref()
        && crate::provider_evidence::receipt_verified(receipt, verifier);
    if !exact {
        return Err(AuthorityError::TransferAlreadyConsumed);
    }
    Ok(TransferReceipt {
        id: record.id.clone(),
        source_grant: record.source_grant.clone(),
        target_grant: record.target_grant.clone(),
        state: TransferState::Committed,
        provider_revision: record.provider_revision,
    })
}
