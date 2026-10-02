use crate::{
    AuthorityError, ProviderOperationOutcome, ProviderReissueReceipt, SignedProviderReconciliation,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderEvidenceKind {
    ReissueReceipt,
    UnknownOutcome,
    Reconciliation,
}

pub trait ProviderEvidenceVerifier {
    fn verify(&self, kind: ProviderEvidenceKind, canonical_payload: &[u8], signature: &str)
    -> bool;
}

pub(crate) fn receipt_verified<V: ProviderEvidenceVerifier>(
    value: &ProviderReissueReceipt,
    verifier: &V,
) -> bool {
    value.signature_intact()
        && encode(serde_json::json!({
            "credential_id": value.credential_id.as_str(),
            "issued_at_epoch_ms": value.issued_at_ms,
            "nonce": value.nonce,
            "owner_ref": value.owner.as_str(),
            "previous_revision": value.previous_revision,
            "provider_account_ref": value.provider_account.as_str(),
            "receipt_id": value.receipt_id,
            "revision": value.revision,
            "service_id": value.service.as_str(),
            "target_device_id": value.target_device.as_str(),
        }))
        .is_ok_and(|payload| {
            verifier.verify(
                ProviderEvidenceKind::ReissueReceipt,
                &payload,
                &value.signature,
            )
        })
}

pub(crate) fn outcome_verified<V: ProviderEvidenceVerifier>(
    value: &ProviderOperationOutcome,
    verifier: &V,
) -> bool {
    encode(serde_json::json!({
        "issued_at_epoch_ms": value.issued_at_ms,
        "nonce": value.nonce,
        "operation_id": value.operation_id,
    }))
    .is_ok_and(|payload| {
        verifier.verify(
            ProviderEvidenceKind::UnknownOutcome,
            &payload,
            &value.signature,
        )
    })
}

pub(crate) fn reconciliation_verified<V: ProviderEvidenceVerifier>(
    value: &SignedProviderReconciliation,
    verifier: &V,
) -> bool {
    encode(serde_json::json!({
        "issued_at_epoch_ms": value.issued_at_ms,
        "nonce": value.nonce,
        "operation_id": value.operation_id,
        "was_issued": value.was_issued,
    }))
    .is_ok_and(|payload| {
        verifier.verify(
            ProviderEvidenceKind::Reconciliation,
            &payload,
            &value.signature,
        )
    })
}

fn encode(value: serde_json::Value) -> Result<Vec<u8>, AuthorityError> {
    serde_json::to_vec(&value).map_err(|_| AuthorityError::ProviderReceiptInvalid)
}
