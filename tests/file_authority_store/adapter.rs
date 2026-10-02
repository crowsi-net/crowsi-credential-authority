use super::*;

#[test]
fn coela_adapter_lists_secret_free_devices_and_credentials_with_one_use_identity() {
    let temporary = TemporaryStore::new("coela-adapter");
    let _authority = provision(&temporary);
    let registration_audience =
        GrantAudience::parse("crowsi://identity/register").expect("registration audience");
    let management_audience =
        GrantAudience::parse("crowsi://coela/manage").expect("management audience");
    let mut adapter = CoelaAuthorityAdapter::open_anchored(
        temporary.path(),
        temporary.anchor(),
        NOW_MS,
        registration_audience,
        management_audience.clone(),
        Verifier,
        OwnerMapper,
        Verifier,
    )
    .expect("production adapter");
    let (grant, grant_wire) = grant_request("coela-adapter-grant");
    adapter
        .issue_grant(grant, &grant_wire)
        .expect("proof-verified adapter grant");
    let wire = assertion(&source_device(), &management_audience, "coela-list-once");
    let projection = adapter
        .list_account(&wire, 10)
        .expect("authorized projection");
    let encoded = projection.encode_json().expect("bounded JSON");
    assert!(encoded.contains("crowsi-coela-management-projection-v1"));
    assert!(encoded.contains(credential_id().as_str()));
    assert!(encoded.contains(source_device().as_str()));
    assert!(encoded.contains(target_device().as_str()));
    assert!(!projection.contains_secret_values());
    for forbidden in ["access_token", "refresh_token", "private_key", "password"] {
        assert!(!encoded.contains(forbidden));
    }
    assert!(matches!(
        adapter.list_account(&wire, 10),
        Err(AuthorityError::IdentityAssertionReplay)
    ));
}

#[test]
fn coela_adapter_revokes_device_with_current_identity_uv_cas_and_one_use_nonce() {
    let temporary = TemporaryStore::new("coela-revoke-device");
    let _authority = provision(&temporary);
    let registration =
        GrantAudience::parse("crowsi://identity/register").expect("registration audience");
    let management = GrantAudience::parse("crowsi://coela/manage").expect("management audience");
    let mut adapter = CoelaAuthorityAdapter::open_anchored(
        temporary.path(),
        temporary.anchor(),
        NOW_MS,
        registration,
        management.clone(),
        Verifier,
        OwnerMapper,
        Verifier,
    )
    .expect("production adapter");
    let request = CoelaDeviceRevocationRequest::new(
        owner_a(),
        target_device(),
        7,
        crowsi_credential_authority::RevocationCause::DeviceCompromised,
        fresh_step_up(&owner_a(), &source_device()),
    );
    let wire = assertion(&source_device(), &management, "coela-revoke-once");
    let receipt = adapter
        .revoke_device(request.clone(), &wire)
        .expect("verified revocation");
    assert_eq!((receipt.previous_epoch(), receipt.current_epoch()), (7, 8));
    assert!(matches!(
        adapter.revoke_device(request, &wire),
        Err(AuthorityError::IdentityAssertionReplay | AuthorityError::StaleRevocationEpoch)
    ));
}

#[test]
fn coela_adapter_revoke_rejects_wrong_owner_source_and_target_epoch() {
    for mutation in ["owner", "source", "epoch"] {
        let temporary = TemporaryStore::new(mutation);
        let _authority = provision(&temporary);
        let registration =
            GrantAudience::parse("crowsi://identity/register").expect("registration audience");
        let management =
            GrantAudience::parse("crowsi://coela/manage").expect("management audience");
        let mut adapter = CoelaAuthorityAdapter::open_anchored(
            temporary.path(),
            temporary.anchor(),
            NOW_MS,
            registration,
            management.clone(),
            Verifier,
            OwnerMapper,
            Verifier,
        )
        .expect("production adapter");
        let owner = if mutation == "owner" {
            crowsi_credential_authority::OpaqueOwnerRef::parse("psa_other_owner_mapping_01")
                .expect("opaque owner")
        } else {
            owner_a()
        };
        let source = if mutation == "source" {
            target_device()
        } else {
            source_device()
        };
        let epoch = if mutation == "epoch" { 6 } else { 7 };
        let request = CoelaDeviceRevocationRequest::new(
            owner,
            target_device(),
            epoch,
            crowsi_credential_authority::RevocationCause::DeviceCompromised,
            fresh_step_up(&owner_a(), &source),
        );
        let wire = assertion(&source_device(), &management, &format!("reject-{mutation}"));
        assert!(adapter.revoke_device(request, &wire).is_err());
    }
}
