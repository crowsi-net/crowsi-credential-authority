pub(super) struct Verifier;
impl ProviderEvidenceVerifier for Verifier {
    fn verify(&self, _kind: ProviderEvidenceKind, payload: &[u8], signature: &str) -> bool {
        !payload.is_empty() && signature == "valid"
    }
}

fn target_proof(owner: &OpaqueOwnerRef, target: &DeviceId) -> TargetKeyProof {
    TargetKeyProof::verified(
        owner.clone(),
        target.clone(),
        key(target),
        "target-nonce",
        NOW,
    )
}

pub(super) fn binding(device: &DeviceId, service: &ServiceId) -> ManagementDeviceBinding {
    ManagementDeviceBinding {
        issuer: "ihat://authority".into(),
        service_id: service.clone(),
        pairwise_subject: "psu_service-a_subject".into(),
        device_id: device.clone(),
        device_proof_key_ref: key(device),
        posture_state: "compliant".into(),
        posture_revision: 1,
        subject_revocation_epoch: 1,
        service_revocation_epoch: 1,
        device_revocation_epoch: 1,
        session_revocation_epoch: 1,
        identity_key_id: "identity-key".into(),
    }
}

pub(super) fn device(owner: &OpaqueOwnerRef, id: &DeviceId, service: &ServiceId) -> DeviceRecord {
    DeviceRecord {
        owner: owner.clone(),
        key_thumbprint: key(id),
        epoch: 1,
        pairwise_subject_ref: "psu_service-a_subject".into(),
        issuer: "ihat://authority".into(),
        service_id: service.clone(),
        posture_state: "compliant".into(),
        posture_revision: 1,
        subject_revocation_epoch: 1,
        service_revocation_epoch: 1,
        session_revocation_epoch: 1,
        key_id: "identity-key".into(),
        enrolled_at_ms: NOW,
        last_seen_at_ms: NOW,
        revoked: false,
    }
}

fn grant(
    owner: &OpaqueOwnerRef,
    source: &DeviceId,
    credential: &CredentialId,
    service: &ServiceId,
    audience: &GrantAudience,
    action: &GrantAction,
    id: &GrantId,
) -> DeviceGrant {
    DeviceGrant {
        id: id.clone(),
        owner: owner.clone(),
        credential_id: credential.clone(),
        credential_revision: 1,
        source_device: source.clone(),
        target_device: source.clone(),
        audience: audience.clone(),
        action: action.clone(),
        source_epoch: 1,
        target_epoch: 1,
        pairwise_subject_ref: "psu_service-a_subject".into(),
        identity_issuer: "ihat://authority".into(),
        identity_service_id: service.clone(),
        source_key_thumbprint: key(source),
        target_key_thumbprint: key(source),
        source_posture_revision: 1,
        target_posture_revision: 1,
        source_posture_state: "compliant".into(),
        subject_revocation_epoch: 1,
        service_revocation_epoch: 1,
        session_revocation_epoch: 1,
        identity_key_id: "identity-key".into(),
        expires_at_ms: NOW + 900_000,
        state: GrantState::Active,
    }
}

fn key(device: &DeviceId) -> String {
    format!("key:{device}")
}
