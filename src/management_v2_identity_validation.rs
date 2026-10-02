fn verify_actor<'a>(
    config: &'a VerifiedHostConfig,
    identity_exchange: &'a SignedAuthorityExchangeV1,
    identity: &'a IdentityEvidenceMetadata,
    peer_device: &str,
    service: &str,
    now: u64,
    prepared: Option<&EndpointPreparedOperationV2>,
    allow_historic_prepared: bool,
) -> Result<VerifiedManagementIdentity<'a>, HostError> {
    verify_endpoint_identity_at(
        identity,
        &EndpointIdentityTrustV2 {
            issuer: &config.document.identity_issuer,
            audience: &config.document.management_audience,
            assertion_key_id: &config.document.identity_key_id,
            assertion_public_key_hex: &config.document.identity_public_key_hex,
            current_status_key_id: &config.document.current_status_key_id,
            current_status_public_key_hex: &config.document.current_status_public_key_hex,
            now_epoch_s: now,
        },
    )
    .map_err(|_| HostError::EvidenceInvalid)?;
    if identity.assertion.device_id != peer_device || identity.assertion.service_id != service {
        return Err(HostError::EvidenceInvalid);
    }
    let owner = config
        .document
        .owner_mappings
        .iter()
        .find(|item| {
            item.issuer == identity.assertion.issuer
                && item.service_id == service
                && item.pairwise_subject == identity.assertion.pairwise_subject
        })
        .ok_or(HostError::EvidenceInvalid)?;
    if let Some(prepared) = prepared
        && (prepared.opaque_owner_ref != owner.opaque_owner_ref
            || prepared.pairwise_subject != owner.pairwise_subject
            || (!allow_historic_prepared
                && (now < prepared.issued_at_epoch_s || now >= prepared.expires_at_epoch_s)))
    {
        return Err(HostError::EvidenceInvalid);
    }
    let actor_key = config
        .document
        .device_proof_keys
        .iter()
        .find(|item| {
            item.opaque_owner_ref == owner.opaque_owner_ref
                && item.device_id == identity.assertion.device_id
                && item.device_proof_key_ref == identity.assertion.device_proof_key_ref
        })
        .ok_or(HostError::EvidenceInvalid)?;
    if actor_key.custody_revision.is_empty() {
        return Err(HostError::EvidenceInvalid);
    }
    Ok(VerifiedManagementIdentity {
        identity_exchange,
        identity,
        owner,
    })
}

fn evidence(
    value: &EndpointManagementEvidenceV2,
) -> (
    &SignedAuthorityExchangeV1,
    Option<&EndpointPreparedOperationV2>,
) {
    match value {
        EndpointManagementEvidenceV2::Passive { identity_exchange } => (identity_exchange, None),
        EndpointManagementEvidenceV2::SourceOptions {
            identity_exchange,
            prepared,
            ..
        }
        | EndpointManagementEvidenceV2::SourceApprove {
            identity_exchange,
            prepared,
            ..
        }
        | EndpointManagementEvidenceV2::ActorOptions {
            identity_exchange,
            prepared,
            ..
        }
        | EndpointManagementEvidenceV2::TargetApprove {
            identity_exchange,
            prepared,
            ..
        }
        | EndpointManagementEvidenceV2::IndependentApprove {
            identity_exchange,
            prepared,
            ..
        }
        | EndpointManagementEvidenceV2::Cancel {
            identity_exchange,
            prepared,
        }
        | EndpointManagementEvidenceV2::Reconcile {
            identity_exchange,
            prepared,
            ..
        } => (identity_exchange, Some(prepared)),
    }
}

fn request_service<'a>(
    command: &'a ManagementCommandV2,
    prepared: Option<&'a EndpointPreparedOperationV2>,
) -> Result<&'a str, HostError> {
    match command {
        ManagementCommandV2::Snapshot { service_id }
        | ManagementCommandV2::PendingList { service_id } => Ok(service_id),
        ManagementCommandV2::SourceOptions { intent } => Ok(intent_service(intent)),
        _ => prepared
            .map(|value| intent_service(&value.intent))
            .ok_or(HostError::RequestInvalid),
    }
}

fn intent_service(value: &ManagementIntentV2) -> &str {
    match value {
        ManagementIntentV2::DeviceTransfer { service_id, .. }
        | ManagementIntentV2::DeviceRevocation { service_id, .. }
        | ManagementIntentV2::SessionRevocation { service_id, .. } => service_id,
    }
}
