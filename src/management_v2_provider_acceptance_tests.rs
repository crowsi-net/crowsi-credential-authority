use ed25519_dalek::SigningKey;

use crate::{
    CredentialId, DeviceId, OpaqueOwnerRef, host_config_types::HostProviderRoute,
    host_provider_contract::HostProviderEvidence,
};

const NOW: u64 = 10_000;

#[test]
fn accepted_receipt_is_historic_pinned_and_nonce_exact() {
    let key = SigningKey::from_bytes(&[7; 32]);
    let route = route(&key);
    let owner = OpaqueOwnerRef::parse("psa_service-a_01JOWNER000000000000000001").expect("owner");
    let credential = CredentialId::parse("credential-a").expect("credential");
    let target = DeviceId::parse("device-b").expect("target");
    let document = receipt_document(&key, "nonce-a");
    let (accepted, _) = crate::management_v2_provider_acceptance::accept_receipt(
        document.clone(),
        &route,
        &owner,
        &credential,
        &target,
        "nonce-a",
        NOW,
        false,
    )
    .expect("current receipt");
    assert!(
        crate::management_v2_provider_acceptance::historic_receipt(
            &accepted,
            &owner,
            &credential,
            &target,
            "nonce-a",
            NOW + 301,
        )
        .is_ok()
    );
    assert!(
        crate::management_v2_provider_acceptance::historic_receipt(
            &accepted,
            &owner,
            &credential,
            &target,
            "nonce-b",
            NOW + 301,
        )
        .is_err()
    );
    assert!(
        crate::management_v2_provider_acceptance::accept_receipt(
            document,
            &route,
            &owner,
            &credential,
            &target,
            "nonce-a",
            NOW + 301,
            false,
        )
        .is_err()
    );
}

#[test]
fn rotation_attempts_are_unique_per_credential_and_retry() {
    let first = crate::management_v2_revocation_plan::attempt("operation-a", "credential-a", 1);
    let other = crate::management_v2_revocation_plan::attempt("operation-a", "credential-b", 1);
    let retry = crate::management_v2_revocation_plan::attempt("operation-a", "credential-a", 2);
    assert_ne!(first, other);
    assert_ne!(first, retry);
    assert!(first.0.starts_with("request-"));
    let reconcile_one = crate::management_v2_revocation_plan::reconcile_request(
        "operation-a",
        "credential-a",
        1,
        1,
    );
    let reconcile_two = crate::management_v2_revocation_plan::reconcile_request(
        "operation-a",
        "credential-a",
        1,
        2,
    );
    assert_ne!(reconcile_one, reconcile_two);
    assert_ne!(
        crate::management_v2_provider_progress::transfer_reconcile_request("operation-a", 1),
        crate::management_v2_provider_progress::transfer_reconcile_request("operation-a", 2)
    );
}

#[test]
fn provider_acceptance_history_rolls_without_stopping() {
    let key = SigningKey::from_bytes(&[7; 32]);
    let route = route(&key);
    let owner = OpaqueOwnerRef::parse("psa_service-a_01JOWNER000000000000000001").expect("owner");
    let credential = CredentialId::parse("credential-a").expect("credential");
    let target = DeviceId::parse("device-b").expect("target");
    let (accepted, _) = crate::management_v2_provider_acceptance::accept_receipt(
        receipt_document(&key, "nonce-a"),
        &route,
        &owner,
        &credential,
        &target,
        "nonce-a",
        NOW,
        false,
    )
    .expect("acceptance");
    let mut values = Vec::new();
    let mut count = 0;
    let mut digest = crate::management_v2_provider_progress::empty_digest("rotation");
    for _ in 0..12 {
        crate::management_v2_provider_progress::append(
            "rotation",
            &mut values,
            &mut count,
            &mut digest,
            accepted.clone(),
        )
        .expect("append");
    }
    assert_eq!(values.len(), 8);
    assert_eq!(count, 12);
    assert!(crate::management_v2_provider_progress::valid(
        "rotation", &values, count, &digest
    ));
}

include!("management_v2_provider_acceptance_test_helpers.rs");
