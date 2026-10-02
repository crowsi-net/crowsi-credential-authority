use super::*;
use crate::support::{
    TestIdentityVerifier, TestOwnerMapper, next_identity_nonce,
    signed_identity_assertion as support_identity_assertion,
};

#[test]
fn sixty_fifth_owner_credential_is_rejected_before_insert() {
    let mut authority = authority();
    let owner = owner_a();
    for index in 0..64 {
        authority
            .register_credential(credential(&owner, index))
            .expect("credential within signed capacity");
    }
    assert_eq!(
        authority.register_credential(credential(&owner, 64)),
        Err(AuthorityError::InvalidValue("owner credential capacity"))
    );
}

#[test]
fn sixty_fifth_owner_device_is_rejected_before_insert() {
    let mut authority = authority();
    let owner = owner_a();
    for index in 0..64 {
        register_device(&mut authority, &owner, &device(index));
    }
    let registration = GrantAudience::parse("crowsi://identity/register").expect("audience");
    let result = authority.register_device_from_assertion(
        &support_identity_assertion(
            &device(64),
            &registration,
            &next_identity_nonce("device-capacity"),
        ),
        &registration,
        &TestIdentityVerifier,
        &TestOwnerMapper,
    );
    assert_eq!(
        result,
        Err(AuthorityError::InvalidValue("owner identity capacity"))
    );
}

#[test]
fn five_hundred_thirteenth_session_is_rejected_before_insert() {
    let mut authority = authority();
    let registration = GrantAudience::parse("crowsi://identity/register").expect("audience");
    for index in 0..512 {
        authority
            .register_device_from_assertion(
                &identity_with_session(index, &registration),
                &registration,
                &TestIdentityVerifier,
                &TestOwnerMapper,
            )
            .expect("session within signed capacity");
    }
    assert_eq!(
        authority.register_device_from_assertion(
            &identity_with_session(512, &registration),
            &registration,
            &TestIdentityVerifier,
            &TestOwnerMapper,
        ),
        Err(AuthorityError::InvalidValue("owner identity capacity"))
    );
}

fn credential(owner: &OpaqueOwnerRef, index: usize) -> CredentialRegistration {
    CredentialRegistration::metadata_only(
        crowsi_credential_authority::CredentialId::parse(format!("cred-limit-{index:02}"))
            .expect("credential id"),
        owner.clone(),
        service(),
        provider_account(),
        format!("credential {index}"),
        CredentialClass::OperationOnly,
        1,
    )
}

fn device(index: usize) -> crowsi_credential_authority::DeviceId {
    crowsi_credential_authority::DeviceId::parse(format!("dev_limit_{index:02}"))
        .expect("device id")
}

fn identity_with_session(index: usize, audience: &GrantAudience) -> Vec<u8> {
    let mut value: serde_json::Value = serde_json::from_slice(&support_identity_assertion(
        &source_device(),
        audience,
        &next_identity_nonce("session-capacity"),
    ))
    .expect("identity fixture");
    value["session_ref"] = serde_json::json!(format!("sref_{index:064x}"));
    serde_json::to_vec(&value).expect("identity wire")
}
