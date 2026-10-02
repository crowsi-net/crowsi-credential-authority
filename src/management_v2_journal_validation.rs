fn provider_state_valid(value: &crate::management_v2_record::ManagementRecordV2) -> bool {
    let transfer = crate::management_v2_provider_progress::valid(
        "transfer",
        &value.transfer_provider_history,
        value.transfer_provider_history_count,
        &value.transfer_provider_history_digest_sha256,
    ) && value
        .transfer_provider_history
        .iter()
        .all(|item| item.validate().is_ok())
        && value
            .transfer_provider_acceptance
            .as_ref()
            .is_none_or(|item| item.validate().is_ok());
    let transfer_context = value.transfer_context.as_ref().is_none_or(|context| {
        context
            .provider_reconcile_request_id
            .as_ref()
            .is_none_or(|id| context.reconcile_sequence > 0 && valid_id(id))
    });
    let rotations = value.revocation_saga.as_ref().is_none_or(|saga| {
        saga.rotations.len() <= crate::authority_limits::OWNER_CREDENTIALS
            && saga.rotations.iter().all(|item| {
                item.attempt_number > 0
                    && item
                        .target_binding
                        .as_ref()
                        .is_some_and(rotation_binding_valid)
                    && crate::management_v2_provider_progress::valid(
                        "rotation",
                        &item.prior_acceptances,
                        item.prior_acceptance_count,
                        &item.prior_acceptance_digest_sha256,
                    )
                    && item
                        .provider_reconcile_request_id
                        .as_ref()
                        .is_none_or(|id| {
                            item.attempted && item.reconcile_sequence > 0 && valid_id(id)
                        })
                    && item
                        .prior_acceptances
                        .iter()
                        .all(|acceptance| acceptance.validate().is_ok())
                    && item
                        .provider_acceptance
                        .as_ref()
                        .is_none_or(|acceptance| acceptance.validate().is_ok())
            })
    });
    transfer && transfer_context && rotations
}

fn rotation_binding_valid(value: &crate::management_v2_record::RevocationTargetBindingV1) -> bool {
    let mut grants = std::collections::BTreeSet::new();
    value.credential_revision > 0
        && value.device_epoch > 0
        && value.posture_revision > 0
        && value.subject_epoch > 0
        && value.service_epoch > 0
        && value.session_epoch > 0
        && valid_id(&value.service_id)
        && valid_id(&value.pairwise_subject)
        && valid_id(&value.issuer)
        && valid_id(&value.device_proof_key_ref)
        && valid_id(&value.identity_key_id)
        && !value.grants.is_empty()
        && value.grants.len() <= crate::authority_limits::DEVICE_CREDENTIAL_GRANTS
        && value.grants.iter().all(|grant| {
            valid_id(&grant.grant_id)
                && valid_id(&grant.source_device_ref)
                && valid_id(&grant.target_device_ref)
                && grant.audience.starts_with("crowsi://")
                && grant.audience.len() <= 128
                && valid_id(&grant.action)
                && grant.credential_revision == value.credential_revision
                && grant.expires_at_ms > 0
                && matches!(grant.state.as_str(), "active" | "pending")
                && grants.insert(&grant.grant_id)
        })
}

fn valid_consumed(values: &[crate::management_v2_record::ConsumedEvidenceV2]) -> bool {
    let mut used = std::collections::BTreeSet::new();
    values.iter().all(|item| {
        valid_digest(&item.digest)
            && valid_digest(&item.binding_sha256)
            && item.expires_at_epoch_s > 0
            && used.insert(&item.digest)
    })
}

fn valid_transport_replays(values: &[crate::management_v2_record::TransportReplayV1]) -> bool {
    let mut used = std::collections::BTreeSet::new();
    let mut per_device = std::collections::BTreeMap::<&str, usize>::new();
    values.iter().all(|item| {
        let count = per_device.entry(&item.device_id).or_default();
        *count += 1;
        valid_id(&item.device_id)
            && valid_digest(&item.digest)
            && item.expires_at_epoch_s > 0
            && *count <= 256
            && used.insert((&item.device_id, &item.digest))
    })
}

fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

fn valid_digest(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|item| item.is_ascii_digit() || matches!(item, b'a'..=b'f'))
}
