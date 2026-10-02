fn common(
    value: &HostProviderEvidence,
    response_key_id: &str,
    response_public_key_hex: &str,
    kind: &str,
    now: u64,
    current: bool,
) -> Result<(), HostError> {
    let canonical = canonical_payload(value)?;
    let signed = crate::host_crypto::provider_payload(kind, &canonical);
    let valid = value.schema == "crowsi://credential-authority/provider-evidence/v1"
        && value.kind == kind
        && value.key_id == response_key_id
        && value.exact_shape()
        && !value.signature.is_empty()
        && value.signature.len() <= 1_024
        && !value.nonce.is_empty()
        && value.nonce.len() <= 128
        && value.issued_at_epoch_s <= now
        && (!current || now.saturating_sub(value.issued_at_epoch_s) <= 300)
        && crate::host_crypto::verify(response_public_key_hex, &value.signature, &signed);
    if valid {
        Ok(())
    } else {
        Err(HostError::EvidenceInvalid)
    }
}

fn canonical_payload(value: &HostProviderEvidence) -> Result<Vec<u8>, HostError> {
    let issued = value.issued_at_epoch_s.saturating_mul(1_000);
    let payload = match value.kind.as_str() {
        "reissue-receipt" => serde_json::json!({
            "credential_id": text(value.credential_ref.as_deref())?, "issued_at_epoch_ms":issued,
            "nonce":value.nonce, "owner_ref":text(value.owner_ref.as_deref())?,
            "previous_revision":value.previous_revision.ok_or(HostError::EvidenceInvalid)?,
            "provider_account_ref":text(value.provider_account_ref.as_deref())?,
            "receipt_id":text(value.receipt_id.as_deref())?,
            "revision":value.revision.ok_or(HostError::EvidenceInvalid)?,
            "service_id":text(value.service_id.as_deref())?,
            "target_device_id":text(value.target_device_ref.as_deref())?}),
        "unknown-outcome" => serde_json::json!({"issued_at_epoch_ms":issued,
            "nonce":value.nonce,"operation_id":text(value.operation_ref.as_deref())?}),
        "not-issued-reconciliation" => serde_json::json!({"issued_at_epoch_ms":issued,
            "nonce":value.nonce,"operation_id":text(value.operation_ref.as_deref())?,
            "was_issued":false}),
        _ => return Err(HostError::EvidenceInvalid),
    };
    serde_json::to_vec(&payload).map_err(|_| HostError::EvidenceInvalid)
}

fn text(value: Option<&str>) -> Result<&str, HostError> {
    value
        .filter(|item| !item.is_empty() && item.len() <= 128)
        .ok_or(HostError::EvidenceInvalid)
}
