use super::*;

pub(super) fn assertion(
    device: &crowsi_credential_authority::DeviceId,
    audience: &GrantAudience,
    nonce: &str,
) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "schema": DEVICE_IDENTITY_ASSERTION_SCHEMA,
        "issuer": "ihat://identity-authority",
        "audience": audience.as_str(),
        "service_id": "github-api",
        "pairwise_subject": "psu_service-a_01JSUBJECT000000000000001",
        "device_id": device.as_str(),
        "device_proof_key_ref": format!("key-thumbprint:{device}"),
        "session_ref": format!("sref_{}", "c".repeat(64)),
        "device_posture": {"state": "compliant", "revision": 11},
        "revocation_epochs": {"subject": 5, "service": 3, "device": 7, "session": 9},
        "issued_at_epoch_s": NOW_MS / 1_000 - 1,
        "expires_at_epoch_s": NOW_MS / 1_000 + 120,
        "nonce": nonce,
        "key_id": "ihat-key-01",
        "signature": "opaque-signature"
    }))
    .expect("assertion wire")
}

pub(super) fn open_authority(store: &TemporaryStore) -> CredentialAuthority<FileAuthorityStore> {
    let store =
        FileAuthorityStore::open_anchored(store.path(), store.anchor()).expect("secure file store");
    CredentialAuthority::with_store(store, NOW_MS)
}

pub(super) fn provision(store: &TemporaryStore) -> CredentialAuthority<FileAuthorityStore> {
    initialize_file_authority_store(store.path(), store.anchor(), NOW_MS)
        .expect("initialize anchored store");
    let mut authority = open_authority(store);
    let registration_audience =
        GrantAudience::parse("crowsi://identity/register").expect("audience");
    for (device, nonce) in [
        (source_device(), "register-source"),
        (target_device(), "register-target"),
    ] {
        authority
            .register_device_from_assertion(
                &assertion(&device, &registration_audience, nonce),
                &registration_audience,
                &Verifier,
                &OwnerMapper,
            )
            .expect("assertion device registration");
    }
    authority
        .register_credential(CredentialRegistration::metadata_only(
            credential_id(),
            owner_a(),
            service(),
            provider_account(),
            "file-store credential",
            CredentialClass::OperationOnly,
            3,
        ))
        .expect("credential metadata");
    authority
}

pub(super) fn grant_request(nonce: &str) -> (DeviceGrantRequest, Vec<u8>) {
    let request = DeviceGrantRequest::new(
        owner_a(),
        credential_id(),
        source_device(),
        target_device(),
        audience(),
        action(),
        GRANT_TTL_MS,
        fresh_step_up(&owner_a(), &source_device()),
        TargetKeyProof::verified(
            owner_a(),
            target_device(),
            format!("key-thumbprint:{}", target_device()),
            nonce,
            NOW_MS,
        ),
    );
    let wire = assertion(&source_device(), &audience(), &format!("identity-{nonce}"));
    (request, wire)
}
