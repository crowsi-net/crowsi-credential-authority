use super::*;

pub fn signed_identity_assertion(
    device: &DeviceId,
    assertion_audience: &GrantAudience,
    nonce: &str,
) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "schema": DEVICE_IDENTITY_ASSERTION_SCHEMA,
        "issuer": "ihat://identity-authority",
        "audience": assertion_audience.as_str(),
        "service_id": "github-api",
        "pairwise_subject": "psu_service-a_01JSUBJECT000000000000001",
        "device_id": device.as_str(),
        "device_proof_key_ref": format!("key-thumbprint:{device}"),
        "session_ref": format!("sref_{}", "a".repeat(64)),
        "device_posture": { "state": "compliant", "revision": 11 },
        "revocation_epochs": { "subject": 5, "service": 3, "device": 7, "session": 9 },
        "issued_at_epoch_s": NOW_MS / 1_000 - 1,
        "expires_at_epoch_s": NOW_MS / 1_000 + 120,
        "nonce": nonce,
        "key_id": "ihat-key-01",
        "signature": "opaque-signature"
    }))
    .expect("closed assertion JSON")
}

pub fn register_device(authority: &mut TestAuthority, owner: &OpaqueOwnerRef, device: &DeviceId) {
    assert_eq!(owner, &owner_a(), "fixture mapper has one pairwise owner");
    let registration_audience =
        GrantAudience::parse("crowsi://identity/register").expect("registration audience");
    authority
        .register_device_from_assertion(
            &signed_identity_assertion(
                device,
                &registration_audience,
                &next_identity_nonce("registration"),
            ),
            &registration_audience,
            &TestIdentityVerifier,
            &TestOwnerMapper,
        )
        .expect("signed assertion device registration");
}

static IDENTITY_NONCE_SEQUENCE: AtomicU64 = AtomicU64::new(1);

pub fn next_identity_nonce(label: &str) -> String {
    let sequence = IDENTITY_NONCE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    format!("{label}-identity-{sequence}")
}
