#[allow(clippy::too_many_arguments)]
fn recover(
    ledger: &ManagementLedgerV2,
    envelope: &EndpointManagementEnvelopeV2,
    identity_exchange: &SignedAuthorityExchangeV1,
    prepared: &EndpointPreparedOperationV2,
    operation_id: &str,
    peer: &str,
    request_digest: &str,
    identity_digest: &str,
    now: u64,
) -> Result<Option<MutationRecovery>, HostError> {
    let Some(receipt) = ledger
        .durable_responses
        .iter()
        .find(|item| item.request_digest_sha256 == request_digest)
    else {
        return Ok(None);
    };
    let (operation, stored_prepared, owner, service, pairwise) =
        entry(ledger, operation_id).ok_or(HostError::StateInvalid)?;
    let DurableResponseV1::Projection(response) = &receipt.response else {
        return Err(HostError::StateInvalid);
    };
    let crowsi_credential_authority_contracts::ManagementProjectionBodyV2::Operation {
        operation: accepted,
    } = &response.body
    else {
        return Err(HostError::StateInvalid);
    };
    let identity =
        crowsi_credential_authority_contracts::identity_evidence_from_exchange(identity_exchange)
            .map_err(|_| HostError::StateInvalid)?;
    let assertion = &identity.assertion;
    let epochs = &assertion.revocation_epochs;
    let command_digest =
        crowsi_credential_authority_contracts::management_command_digest(&envelope.browser_request)
            .map_err(|_| HostError::StateInvalid)?;
    let valid = now >= response.issued_at_epoch_s
        && now < receipt.retain_until_epoch_s
        && !receipt.read_only
        && receipt.phase.as_deref()
            == Some(crate::management_v2_command::route(
                &envelope.browser_request.command,
            ))
        && receipt.identity_exchange_sha256 == identity_digest
        && receipt.actor_device_ref == peer
        && receipt.operation_id.as_deref() == Some(operation_id)
        && stored_prepared == prepared
        && owner == &prepared.opaque_owner_ref
        && pairwise == &prepared.pairwise_subject
        && assertion.device_id == peer
        && assertion.service_id == *service
        && assertion.pairwise_subject == *pairwise
        && response.request_id == envelope.browser_request.request_id
        && response.command_digest_sha256 == command_digest
        && response.service_id == assertion.service_id
        && response.pairwise_subject == assertion.pairwise_subject
        && response.opaque_account_ref == *owner
        && response.current_device_ref == assertion.device_id
        && response.current_session_ref == assertion.session_ref
        && response.subject_revocation_epoch == epochs.subject
        && response.service_revocation_epoch == epochs.service
        && response.device_revocation_epoch == epochs.device
        && response.session_revocation_epoch == epochs.session
        && response.device_posture_state == assertion.device_posture.state
        && response.device_posture_revision == assertion.device_posture.revision
        && response.device_proof_key_ref == assertion.device_proof_key_ref
        && response.snapshot_revision == receipt.accepted_ledger_revision
        && accepted.operation_id == operation_id
        && accepted.scope == operation.scope
        && accepted.created_at_epoch_s == operation.created_at_epoch_s
        && accepted.state_revision <= operation.state_revision
        && accepted.state
            != crowsi_credential_authority_contracts::ManagementOperationState::AwaitingRevocationFinal;
    if !valid {
        return Err(HostError::StateInvalid);
    }
    Ok(Some(MutationRecovery {
        owner_ref: owner.clone(),
        accepted_snapshot_revision: receipt.accepted_ledger_revision,
        current_snapshot_revision: ledger.revision,
        accepted_generation_head: receipt.accepted_generation_head,
        current_generation_head: ledger.authority_config_generation_head,
        identity_exchange: identity_exchange.clone(),
        original_response: response.as_ref().clone(),
    }))
}

type Entry<'a> = (
    &'a ManagementOperationV2,
    &'a EndpointPreparedOperationV2,
    &'a String,
    &'a String,
    &'a String,
);

fn entry<'a>(ledger: &'a ManagementLedgerV2, operation_id: &str) -> Option<Entry<'a>> {
    ledger
        .records
        .iter()
        .find(|item| item.operation.operation_id == operation_id)
        .map(|item| {
            (
                &item.operation,
                &item.prepared,
                &item.owner_ref,
                &item.service_id,
                &item.pairwise_subject,
            )
        })
        .or_else(|| {
            ledger
                .tombstones
                .iter()
                .find(|item| item.operation.operation_id == operation_id)
                .map(|item| {
                    (
                        &item.operation,
                        &item.prepared,
                        &item.owner_ref,
                        &item.service_id,
                        &item.pairwise_subject,
                    )
                })
        })
}
