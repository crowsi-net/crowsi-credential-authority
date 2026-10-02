fn replay_key(
    operation_id: &str,
    provider_nonce: &str,
    binding: &crate::management_v2_record::RevocationTargetBindingV1,
    receipt_id: &str,
) -> Result<String, AuthorityError> {
    let wire = serde_json::to_vec(&(
        "CROWSI-REVOCATION-ROTATION-REPLAY-V2",
        operation_id,
        provider_nonce,
        binding,
        receipt_id,
    ))
    .map_err(|_| AuthorityError::ProviderReceiptInvalid)?;
    Ok(format!(
        "revocation-rotation:{}",
        crate::host_crypto::digest(&wire)
    ))
}

fn target_exact(
    value: &crate::state::DeviceRecord,
    expected: &crate::management_v2_record::RevocationTargetBindingV1,
) -> bool {
    !value.revoked
        && value.service_id.as_str() == expected.service_id
        && value.pairwise_subject_ref == expected.pairwise_subject
        && value.issuer == expected.issuer
        && value.key_thumbprint == expected.device_proof_key_ref
        && value.epoch == expected.device_epoch
        && value.posture_state == expected.posture_state
        && value.posture_revision == expected.posture_revision
        && value.subject_revocation_epoch == expected.subject_epoch
        && value.service_revocation_epoch == expected.service_epoch
        && value.session_revocation_epoch == expected.session_epoch
        && value.key_id == expected.identity_key_id
}
