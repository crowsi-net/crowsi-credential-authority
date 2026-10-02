pub(super) fn fixture() -> Fixture {
    let store = MemoryStore::new(NOW);
    let mut authority = CredentialAuthority::with_store(store.clone(), NOW);
    let owner = OpaqueOwnerRef::parse("psa_service-a_01JOWNER000000000000000001").expect("owner");
    let source = DeviceId::parse("device-source").expect("source");
    let target = DeviceId::parse("device-target").expect("target");
    let credential = CredentialId::parse("credential-a").expect("credential");
    let service = ServiceId::parse("service-a").expect("service");
    let audience = GrantAudience::parse("crowsi://service-a/operate").expect("audience");
    let action = GrantAction::parse("operate").expect("action");
    authority
        .register_credential(CredentialRegistration::metadata_only(
            credential.clone(),
            owner.clone(),
            service.clone(),
            ProviderAccountRef::parse("provider-a").expect("provider"),
            "alias",
            CredentialClass::OperationOnly,
            1,
        ))
        .expect("credential");
    let prior_grant = GrantId::trusted("prior-source-grant");
    store
        .transact(|snapshot| {
            snapshot.devices.insert(
                (owner.clone(), source.clone()),
                device(&owner, &source, &service),
            );
            snapshot.devices.insert(
                (owner.clone(), target.clone()),
                device(&owner, &target, &service),
            );
            snapshot.grants.insert(
                prior_grant.clone(),
                grant(
                    &owner,
                    &source,
                    &credential,
                    &service,
                    &audience,
                    &action,
                    &prior_grant,
                ),
            );
            Ok(())
        })
        .expect("identity state");
    let source_binding = binding(&source, &service);
    let target_binding = binding(&target, &service);
    let authorization = format!("sha256:{}", "a".repeat(64));
    let request = TransferRequest::new(
        owner.clone(),
        credential.clone(),
        source.clone(),
        target.clone(),
        audience.clone(),
        action.clone(),
        TransferMechanism::ProviderReissue,
        30_000,
        StepUpProof::verified(owner.clone(), source.clone(), NOW, NOW + 30_000),
        target_proof(&owner, &target),
    );
    let transfer = authority
        .prepare_management_transfer(request, &authorization, &source_binding, &target_binding)
        .expect("management prepare");
    Fixture {
        authority,
        owner,
        source,
        target,
        credential,
        audience,
        action,
        authorization,
        transfer,
        prior_grant,
    }
}
