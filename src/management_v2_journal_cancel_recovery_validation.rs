#[allow(clippy::too_many_arguments)]
fn recover(
    ledger: &ManagementLedgerV2,
    envelope: &EndpointManagementEnvelopeV2,
    peer: &str,
    now: u64,
    operation_id: &str,
    expected_state_revision: u64,
    request_digest: &str,
    identity_digest: &str,
) -> Result<Option<CancelRecovery>, HostError> {
    let Some(receipt) = ledger
        .durable_responses
        .iter()
        .find(|item| item.request_digest_sha256 == request_digest)
    else {
        return Ok(None);
    };
    let Some((operation, prepared, owner_ref, service_id, pairwise_subject)) =
        terminal(ledger, operation_id)
    else {
        return Err(HostError::StateInvalid);
    };
    let EndpointManagementEvidenceV2::Cancel {
        identity_exchange,
        prepared: supplied,
    } = &envelope.evidence
    else {
        return Err(HostError::StateInvalid);
    };
    let identity =
        identity_evidence_from_exchange(identity_exchange).map_err(|_| HostError::StateInvalid)?;
    let DurableResponseV1::Projection(response) = &receipt.response else {
        return Err(HostError::StateInvalid);
    };
    let ManagementProjectionBodyV2::Operation {
        operation: response_operation,
    } = &response.body
    else {
        return Err(HostError::StateInvalid);
    };
    let command_digest = management_command_digest(&envelope.browser_request)
        .map_err(|_| HostError::StateInvalid)?;
    let valid = now < receipt.retain_until_epoch_s
        && !receipt.read_only
        && receipt.identity_exchange_sha256 == identity_digest
        && receipt.actor_device_ref == peer
        && receipt.operation_id.as_deref() == Some(operation_id)
        && owner_ref == &supplied.opaque_owner_ref
        && prepared == supplied
        && identity.assertion.device_id == peer
        && identity.assertion.service_id == *service_id
        && identity.assertion.pairwise_subject == *pairwise_subject
        && operation.state == ManagementOperationState::Cancelled
        && expected_state_revision.checked_add(1) == Some(operation.state_revision)
        && response_operation == operation
        && response.snapshot_revision == receipt.accepted_ledger_revision
        && response.request_id == envelope.browser_request.request_id
        && response.command_digest_sha256 == command_digest;
    if !valid {
        return Err(HostError::StateInvalid);
    }
    Ok(Some(CancelRecovery {
        owner_ref: owner_ref.clone(),
        accepted_snapshot_revision: receipt.accepted_ledger_revision,
        current_snapshot_revision: ledger.revision,
        operation: operation.clone(),
        identity_exchange: identity_exchange.clone(),
        original_response: response.as_ref().clone(),
    }))
}

type Terminal<'a> = (
    &'a ManagementOperationV2,
    &'a crowsi_credential_authority_contracts::EndpointPreparedOperationV2,
    &'a String,
    &'a String,
    &'a String,
);

fn terminal<'a>(ledger: &'a ManagementLedgerV2, operation_id: &str) -> Option<Terminal<'a>> {
    ledger
        .records
        .iter()
        .find(|item| item.operation.operation_id == operation_id)
        .map(record_parts)
        .or_else(|| {
            ledger
                .tombstones
                .iter()
                .find(|item| item.operation.operation_id == operation_id)
                .map(tombstone_parts)
        })
}

fn record_parts(value: &crate::management_v2_record::ManagementRecordV2) -> Terminal<'_> {
    (
        &value.operation,
        &value.prepared,
        &value.owner_ref,
        &value.service_id,
        &value.pairwise_subject,
    )
}

fn tombstone_parts(value: &crate::management_v2_record::ManagementTombstoneV2) -> Terminal<'_> {
    (
        &value.operation,
        &value.prepared,
        &value.owner_ref,
        &value.service_id,
        &value.pairwise_subject,
    )
}
