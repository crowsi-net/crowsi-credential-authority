pub(crate) fn receipt(
    value: &HostProviderEvidence,
    route: &HostProviderRoute,
    owner: &OpaqueOwnerRef,
    credential: &CredentialId,
    target: &crate::DeviceId,
    expected_nonce: &str,
    now: u64,
) -> Result<ProviderReissueReceipt, HostError> {
    receipt_with_trust(
        value,
        &route.response_key_id,
        &route.response_public_key_hex,
        owner,
        credential,
        target,
        expected_nonce,
        now,
        true,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn historic_receipt(
    value: &HostProviderEvidence,
    response_key_id: &str,
    response_public_key_hex: &str,
    owner: &OpaqueOwnerRef,
    credential: &CredentialId,
    target: &crate::DeviceId,
    expected_nonce: &str,
    now: u64,
) -> Result<ProviderReissueReceipt, HostError> {
    receipt_with_trust(
        value,
        response_key_id,
        response_public_key_hex,
        owner,
        credential,
        target,
        expected_nonce,
        now,
        false,
    )
}

#[allow(clippy::too_many_arguments)]
fn receipt_with_trust(
    value: &HostProviderEvidence,
    response_key_id: &str,
    response_public_key_hex: &str,
    owner: &OpaqueOwnerRef,
    credential: &CredentialId,
    target: &crate::DeviceId,
    expected_nonce: &str,
    now: u64,
    current: bool,
) -> Result<ProviderReissueReceipt, HostError> {
    common(
        value,
        response_key_id,
        response_public_key_hex,
        "reissue-receipt",
        now,
        current,
    )?;
    let previous = value.previous_revision.ok_or(HostError::EvidenceInvalid)?;
    let revision = value.revision.ok_or(HostError::EvidenceInvalid)?;
    let receipt = ProviderReissueReceipt::signed(
        text(value.receipt_id.as_deref())?,
        owner.clone(),
        ServiceId::parse(text(value.service_id.as_deref())?)?,
        ProviderAccountRef::parse(text(value.provider_account_ref.as_deref())?)?,
        CredentialId::parse(text(value.credential_ref.as_deref())?)?,
        previous,
        revision,
        crate::DeviceId::parse(text(value.target_device_ref.as_deref())?)?,
        value.nonce.clone(),
        value.issued_at_epoch_s * 1_000,
        value.signature.clone(),
    );
    if receipt_owner_fields(value, owner, credential, target)
        && value.nonce == expected_nonce
        && revision > previous
    {
        Ok(receipt)
    } else {
        Err(HostError::EvidenceInvalid)
    }
}

fn receipt_owner_fields(
    value: &HostProviderEvidence,
    owner: &OpaqueOwnerRef,
    credential: &CredentialId,
    target: &crate::DeviceId,
) -> bool {
    value.owner_ref.as_deref() == Some(owner.as_str())
        && value.credential_ref.as_deref() == Some(credential.as_str())
        && value.target_device_ref.as_deref() == Some(target.as_str())
}
