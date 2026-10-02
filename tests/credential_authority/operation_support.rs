use super::*;

pub(super) fn prepared(class: CredentialClass) -> support::TestAuthority {
    let mut authority = authority();
    let owner = owner_a();
    register_device(&mut authority, &owner, &source_device());
    register_device(&mut authority, &owner, &target_device());
    register_device(&mut authority, &owner, &unrelated_device());
    register_credential(&mut authority, &owner, class);
    authority
}

pub(super) fn grant_request(target: crowsi_credential_authority::DeviceId) -> DeviceGrantRequest {
    DeviceGrantRequest::new(
        owner_a(),
        credential_id(),
        source_device(),
        target.clone(),
        audience(),
        action(),
        GRANT_TTL_MS,
        fresh_step_up(&owner_a(), &source_device()),
        unique_grant_target_key_proof(&owner_a(), &target),
    )
}

pub(super) fn transfer_request(mechanism: TransferMechanism) -> TransferRequest {
    TransferRequest::new(
        owner_a(),
        credential_id(),
        source_device(),
        target_device(),
        audience(),
        action(),
        mechanism,
        GRANT_TTL_MS,
        fresh_step_up(&owner_a(), &source_device()),
        target_key_proof(&owner_a(), &target_device()),
    )
}

pub(super) fn provider_receipt() -> ProviderReissueReceipt {
    ProviderReissueReceipt::signed(
        "provider-receipt-01",
        owner_a(),
        service(),
        provider_account(),
        credential_id(),
        3,
        4,
        target_device(),
        "transfer-nonce-01",
        NOW_MS,
        "valid-provider-reissue-signature",
    )
}
