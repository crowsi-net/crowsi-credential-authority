#[allow(clippy::too_many_arguments)]
fn promote_bound_grant(
    snapshot: &mut crate::DurableSnapshot,
    owner: &OpaqueOwnerRef,
    credential: &CredentialId,
    target: &DeviceId,
    identity: &crate::state::DeviceRecord,
    revision: u64,
    now: u64,
    template: crate::DeviceGrant,
) {
    if template.expires_at_ms <= now {
        return;
    }
    let existing = snapshot
        .grants
        .iter()
        .find(|(_, grant)| {
            grant.owner == *owner
                && grant.credential_id == *credential
                && grant.source_device == *target
                && grant.target_device == *target
                && grant.audience == template.audience
                && grant.action == template.action
                && matches!(grant.state, GrantState::Active | GrantState::Pending)
        })
        .map(|(id, _)| id.clone());
    let id = existing
        .unwrap_or_else(|| crate::GrantId::trusted(format!("grant-{}", snapshot.next_sequence())));
    let grant = snapshot
        .grants
        .entry(id.clone())
        .or_insert(template.clone());
    grant.id = id;
    crate::grant_promotion::promote_to_target_identity(grant, target, identity);
    grant.credential_revision = revision;
    grant.expires_at_ms = template.expires_at_ms.min(now.saturating_add(30_000));
    grant.state = match template.state {
        GrantState::Pending => GrantState::Pending,
        _ => GrantState::Active,
    };
}

fn bound_grants(
    snapshot: &crate::DurableSnapshot,
    owner: &OpaqueOwnerRef,
    credential: &CredentialId,
    compromised: &DeviceId,
    binding: &crate::management_v2_record::RevocationTargetBindingV1,
) -> Result<Vec<crate::DeviceGrant>, AuthorityError> {
    if binding.grants.is_empty() {
        return Err(AuthorityError::ProviderReceiptInvalid);
    }
    binding
        .grants
        .iter()
        .map(|expected| {
            let id = crate::GrantId::parse(expected.grant_id.clone())?;
            let grant = snapshot
                .grants
                .get(&id)
                .ok_or(AuthorityError::ProviderReceiptInvalid)?;
            let exact = grant.owner == *owner
                && grant.credential_id == *credential
                && (grant.source_device == *compromised || grant.target_device == *compromised)
                && grant.source_device.as_str() == expected.source_device_ref
                && grant.target_device.as_str() == expected.target_device_ref
                && grant.audience.as_str() == expected.audience
                && grant.action.as_str() == expected.action
                && grant.credential_revision == expected.credential_revision
                && grant.expires_at_ms == expected.expires_at_ms
                && matches!(expected.state.as_str(), "active" | "pending")
                && matches!(
                    grant.state,
                    GrantState::Active
                        | GrantState::Pending
                        | GrantState::Revoked
                        | GrantState::Expired
                );
            if !exact {
                return Err(AuthorityError::ProviderReceiptInvalid);
            }
            let mut template = grant.clone();
            template.state = if expected.state == "pending" {
                GrantState::Pending
            } else {
                GrantState::Active
            };
            Ok(template)
        })
        .collect()
}
