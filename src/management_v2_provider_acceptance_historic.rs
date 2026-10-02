pub(crate) fn historic_reconciliation(
    value: &ProviderEvidenceAcceptanceV1,
    operation: &str,
    nonce: &str,
    now: u64,
) -> Result<SignedProviderReconciliation, HostError> {
    value.validate()?;
    crate::host_provider_evidence::historic_reconciliation(
        &value.document,
        &value.response_key_id,
        &value.response_public_key_hex,
        operation,
        nonce,
        now,
    )
}

fn digest(value: &HostProviderEvidence) -> Result<String, HostError> {
    let wire = serde_json::to_vec(value).map_err(|_| HostError::EvidenceInvalid)?;
    Ok(crate::host_crypto::digest(&wire))
}
