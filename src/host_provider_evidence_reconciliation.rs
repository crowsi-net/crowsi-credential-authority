pub(crate) fn unknown(
    value: &HostProviderEvidence,
    route: &HostProviderRoute,
    expected_operation: &str,
    expected_nonce: &str,
    now: u64,
) -> Result<ProviderOperationOutcome, HostError> {
    common(
        value,
        &route.response_key_id,
        &route.response_public_key_hex,
        "unknown-outcome",
        now,
        true,
    )?;
    if value.operation_ref.as_deref() != Some(expected_operation) || value.nonce != expected_nonce {
        return Err(HostError::EvidenceInvalid);
    }
    Ok(ProviderOperationOutcome::unknown_signed(
        text(value.operation_ref.as_deref())?,
        value.nonce.clone(),
        value.signature.clone(),
        value.issued_at_epoch_s * 1_000,
    ))
}

pub(crate) fn historic_reconciliation(
    value: &HostProviderEvidence,
    response_key_id: &str,
    response_public_key_hex: &str,
    expected_operation: &str,
    expected_nonce: &str,
    now: u64,
) -> Result<SignedProviderReconciliation, HostError> {
    reconciliation_with_trust(
        value,
        response_key_id,
        response_public_key_hex,
        expected_operation,
        expected_nonce,
        now,
        false,
    )
}

#[allow(clippy::too_many_arguments)]
fn reconciliation_with_trust(
    value: &HostProviderEvidence,
    response_key_id: &str,
    response_public_key_hex: &str,
    expected_operation: &str,
    expected_nonce: &str,
    now: u64,
    current: bool,
) -> Result<SignedProviderReconciliation, HostError> {
    common(
        value,
        response_key_id,
        response_public_key_hex,
        "not-issued-reconciliation",
        now,
        current,
    )?;
    if value.operation_ref.as_deref() != Some(expected_operation) || value.nonce != expected_nonce {
        return Err(HostError::EvidenceInvalid);
    }
    Ok(SignedProviderReconciliation::not_issued(
        text(value.operation_ref.as_deref())?,
        value.nonce.clone(),
        value.signature.clone(),
        value.issued_at_epoch_s * 1_000,
    ))
}
