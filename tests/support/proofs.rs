use super::*;

static GRANT_NONCE_SEQUENCE: AtomicU64 = AtomicU64::new(1);

pub fn register_credential(
    authority: &mut TestAuthority,
    owner: &OpaqueOwnerRef,
    class: CredentialClass,
) {
    authority
        .register_credential(CredentialRegistration::metadata_only(
            credential_id(),
            owner.clone(),
            service(),
            provider_account(),
            "operator-visible alias",
            class,
            3,
        ))
        .expect("credential registration fixture");
}

pub fn fresh_step_up(owner: &OpaqueOwnerRef, device: &DeviceId) -> StepUpProof {
    StepUpProof::verified(
        owner.clone(),
        device.clone(),
        NOW_MS - 1_000,
        NOW_MS + FRESH_STEP_UP_MS,
    )
}

pub fn target_key_proof(owner: &OpaqueOwnerRef, device: &DeviceId) -> TargetKeyProof {
    TargetKeyProof::verified(
        owner.clone(),
        device.clone(),
        format!("key-thumbprint:{device}"),
        "transfer-nonce-01",
        NOW_MS,
    )
}

pub fn provider_operation_ref() -> String {
    use sha2::{Digest, Sha256};
    format!(
        "provider-{}",
        hex::encode(Sha256::digest(b"transfer-nonce-01"))
    )
}

pub fn unique_grant_target_key_proof(owner: &OpaqueOwnerRef, device: &DeviceId) -> TargetKeyProof {
    let sequence = GRANT_NONCE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    TargetKeyProof::verified(
        owner.clone(),
        device.clone(),
        format!("key-thumbprint:{device}"),
        format!("grant-nonce-{sequence}"),
        NOW_MS,
    )
}
