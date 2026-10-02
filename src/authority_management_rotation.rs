use crate::{
    AuthorityError, AuthorityStore, CredentialAuthority, CredentialId, DeviceId, OpaqueOwnerRef,
    ServiceId, management_v2_record::RevocationTargetBindingV1,
};

include!("authority_management_rotation_queries.rs");

fn binding(
    credential_revision: u64,
    value: &crate::state::DeviceRecord,
    grants: Vec<crate::management_v2_record::RevocationGrantBindingV1>,
) -> RevocationTargetBindingV1 {
    RevocationTargetBindingV1 {
        credential_revision,
        service_id: value.service_id.as_str().to_owned(),
        pairwise_subject: value.pairwise_subject_ref.clone(),
        issuer: value.issuer.clone(),
        device_proof_key_ref: value.key_thumbprint.clone(),
        device_epoch: value.epoch,
        posture_state: value.posture_state.clone(),
        posture_revision: value.posture_revision,
        subject_epoch: value.subject_revocation_epoch,
        service_epoch: value.service_revocation_epoch,
        session_epoch: value.session_revocation_epoch,
        identity_key_id: value.key_id.clone(),
        grants,
    }
}

fn target_fields(
    revision: u64,
    value: &crate::state::DeviceRecord,
    expected: &RevocationTargetBindingV1,
) -> bool {
    let mut observed = binding(revision, value, expected.grants.clone());
    observed
        .grants
        .sort_by(|left, right| left.grant_id.cmp(&right.grant_id));
    observed == *expected
}

fn grant_bindings(
    snapshot: &crate::DurableSnapshot,
    owner: &OpaqueOwnerRef,
    credential: &CredentialId,
    compromised: &DeviceId,
    now: u64,
) -> Vec<crate::management_v2_record::RevocationGrantBindingV1> {
    let mut values = snapshot
        .grants
        .values()
        .filter(|grant| {
            grant.owner == *owner
                && grant.credential_id == *credential
                && (grant.source_device == *compromised || grant.target_device == *compromised)
                && matches!(
                    grant.state,
                    crate::GrantState::Active | crate::GrantState::Pending
                )
                && grant.expires_at_ms > now
        })
        .map(grant_binding)
        .collect::<Vec<_>>();
    values.sort_by(|left, right| left.grant_id.cmp(&right.grant_id));
    values
}

fn grant_binding(
    grant: &crate::DeviceGrant,
) -> crate::management_v2_record::RevocationGrantBindingV1 {
    crate::management_v2_record::RevocationGrantBindingV1 {
        grant_id: grant.id.as_str().into(),
        source_device_ref: grant.source_device.as_str().into(),
        target_device_ref: grant.target_device.as_str().into(),
        audience: grant.audience.as_str().into(),
        action: grant.action.as_str().into(),
        credential_revision: grant.credential_revision,
        expires_at_ms: grant.expires_at_ms,
        state: match grant.state {
            crate::GrantState::Active => "active",
            crate::GrantState::Pending => "pending",
            _ => "invalid",
        }
        .into(),
    }
}

fn bound_grants_current(
    snapshot: &crate::DurableSnapshot,
    owner: &OpaqueOwnerRef,
    credential: &CredentialId,
    compromised: &DeviceId,
    expected: &RevocationTargetBindingV1,
) -> bool {
    !expected.grants.is_empty()
        && expected.grants.iter().all(|binding| {
            crate::GrantId::parse(binding.grant_id.clone())
                .ok()
                .and_then(|id| snapshot.grants.get(&id))
                .is_some_and(|grant| {
                    grant.owner == *owner
                        && grant.credential_id == *credential
                        && (grant.source_device == *compromised
                            || grant.target_device == *compromised)
                        && grant.id.as_str() == binding.grant_id
                        && grant.source_device.as_str() == binding.source_device_ref
                        && grant.target_device.as_str() == binding.target_device_ref
                        && grant.audience.as_str() == binding.audience
                        && grant.action.as_str() == binding.action
                        && grant.credential_revision == binding.credential_revision
                        && grant.expires_at_ms == binding.expires_at_ms
                        && matches!(binding.state.as_str(), "active" | "pending")
                        && matches!(
                            grant.state,
                            crate::GrantState::Active
                                | crate::GrantState::Pending
                                | crate::GrantState::Revoked
                                | crate::GrantState::Expired
                        )
                })
        })
}
