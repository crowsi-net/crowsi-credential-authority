use super::*;

// CR-01: ownership is an opaque, pairwise service-account reference and cannot be rebound.
#[test]
fn cr_01_opaque_pairwise_owner_isolated_from_other_accounts() {
    assert!(OpaqueOwnerRef::parse("psa_service-a_01JOWNER000000000000000001").is_ok());
    assert!(matches!(
        OpaqueOwnerRef::parse("alice@example.com"),
        Err(AuthorityError::OwnerReferenceNotOpaque)
    ));
    assert!(matches!(
        OpaqueOwnerRef::parse("global-user-42"),
        Err(AuthorityError::OwnerReferenceNotPairwise)
    ));

    let mut authority = prepared(CredentialClass::Certificate);
    assert!(matches!(
        authority.credential_metadata(&owner_b(), &credential_id()),
        Err(AuthorityError::WrongOwner)
    ));
    assert!(matches!(
        authority.claim_existing_credential(
            owner_b(),
            credential_id(),
            service(),
            provider_account(),
        ),
        Err(AuthorityError::CredentialAlreadyOwned)
    ));
}
// CR-02: only bounded metadata is accepted/projected; secrets and unknown query fields fail closed.
#[test]
fn cr_02_metadata_only_projection_has_no_secret_and_enforces_schema_and_limit() {
    let authority = prepared(CredentialClass::Certificate);
    let metadata = authority
        .credential_metadata(&owner_a(), &credential_id())
        .expect("owner metadata");
    assert!(!metadata.contains_secret_values());

    let projection = authority
        .project_metadata(MetadataProjectionQuery::new(owner_a(), 50))
        .expect("metadata projection");
    assert!(!projection.contains_secret_values());
    let encoded = projection.encode_json().expect("projection JSON");
    for forbidden in [
        "secret_value",
        "raw_secret",
        "access_token",
        "private_key",
        "wrapped_envelope",
        "target_key_proof",
    ] {
        assert!(!encoded.contains(forbidden), "forbidden field: {forbidden}");
    }
    assert!(matches!(
        authority.project_metadata(MetadataProjectionQuery::new(owner_a(), 0)),
        Err(AuthorityError::ProjectionLimitOutOfRange)
    ));
    assert!(matches!(
        authority.project_metadata(MetadataProjectionQuery::new(owner_a(), 101)),
        Err(AuthorityError::ProjectionLimitOutOfRange)
    ));
    let unknown = r#"{"owner_ref":"psa_service-a_01JOWNER000000000000000001","limit":50,"include_secret_values":true}"#;
    assert!(matches!(
        MetadataProjectionQuery::decode_strict(unknown),
        Err(AuthorityError::UnknownField(field)) if field == "include_secret_values"
    ));
}
