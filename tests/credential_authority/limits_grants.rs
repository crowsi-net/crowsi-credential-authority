use super::*;

#[test]
fn sixty_fifth_active_grant_is_rejected_before_mutation() {
    let mut authority = prepared(CredentialClass::OperationOnly);
    for _ in 0..64 {
        authority
            .issue_device_grant(grant_request(target_device()))
            .expect("grant within signed capacity");
    }
    assert_eq!(
        authority.issue_device_grant(grant_request(target_device())),
        Err(AuthorityError::InvalidValue(
            "device credential grant capacity"
        ))
    );
}

#[test]
fn transfer_reserves_both_source_grant_slots_before_prepare() {
    let mut authority = prepared(CredentialClass::OperationOnly);
    for _ in 0..63 {
        authority
            .issue_device_grant(grant_request(target_device()))
            .expect("grant within signed capacity");
    }
    assert_eq!(
        authority.prepare_transfer(transfer_request(TransferMechanism::ProviderReissue)),
        Err(AuthorityError::InvalidValue(
            "device credential grant capacity"
        ))
    );
}

#[test]
fn current_revision_device_revocation_keeps_rotation_capacity_reserved() {
    let mut authority = prepared(CredentialClass::OperationOnly);
    for _ in 0..64 {
        authority
            .issue_device_grant(grant_request(target_device()))
            .expect("grant within signed capacity");
    }
    authority
        .revoke_device(
            &owner_a(),
            &target_device(),
            RevocationCause::DeviceCompromised,
            fresh_step_up(&owner_a(), &source_device()),
        )
        .expect("local revoke reserves rotation slots");
    assert_eq!(
        authority.issue_device_grant(grant_request(unrelated_device())),
        Err(AuthorityError::InvalidValue(
            "device credential grant capacity"
        ))
    );
}
