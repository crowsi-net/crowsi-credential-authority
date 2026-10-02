fn exact(
    ledger: &crate::management_v2_record::ManagementLedgerV2,
    location: Location,
    request: &EndpointRevocationExecutionCancelRequestV1,
    peer: &str,
) -> Result<(), HostError> {
    let operation = operation(ledger, location);
    let (prepared, owner) = match location {
        Location::Record(index) => (
            &ledger.records[index].prepared,
            &ledger.records[index].owner_ref,
        ),
        Location::Tombstone(index) => (
            &ledger.tombstones[index].prepared,
            &ledger.tombstones[index].owner_ref,
        ),
    };
    let crowsi_credential_authority_contracts::EndpointManagementEvidenceV2::Cancel {
        identity_exchange,
        ..
    } = &request.cancel_envelope.evidence
    else {
        return Err(HostError::RequestInvalid);
    };
    let identity =
        crowsi_credential_authority_contracts::identity_evidence_from_exchange(identity_exchange)
            .map_err(|_| HostError::EvidenceInvalid)?;
    let valid = owner == &request.prepared.opaque_owner_ref
        && prepared == &request.prepared
        && operation.state
            == crowsi_credential_authority_contracts::ManagementOperationState::Cancelled
        && operation.state_revision == request.expected_cancelled_state_revision
        && identity.assertion.device_id == peer
        && identity.assertion.device_id == request.prepared.source_device_ref
        && identity.assertion.session_ref == request.prepared.source_session_ref;
    if !valid || !acceptance_exact(ledger, location, request) {
        return Err(HostError::StateInvalid);
    }
    cancel_receipt(ledger, request, peer, identity_exchange)
}

fn cancel_receipt(
    ledger: &crate::management_v2_record::ManagementLedgerV2,
    request: &EndpointRevocationExecutionCancelRequestV1,
    peer: &str,
    identity: &crowsi_credential_authority_contracts::SignedAuthorityExchangeV1,
) -> Result<(), HostError> {
    let request_digest =
        crate::management_v2_journal_policy::envelope_digest(&request.cancel_envelope)?;
    let identity_digest = crate::management_v2_journal_policy::exchange_digest(identity)?;
    let receipt = ledger
        .durable_responses
        .iter()
        .find(|item| {
            item.request_digest_sha256 == request_digest
                && item.identity_exchange_sha256 == identity_digest
                && item.actor_device_ref == peer
                && item.phase.as_deref() == Some("cancel")
                && !item.read_only
                && item.operation_id.as_deref() == Some(&request.operation_id)
        })
        .ok_or(HostError::StateInvalid)?;
    let crate::management_v2_record::DurableResponseV1::Projection(projection) = &receipt.response
    else {
        return Err(HostError::StateInvalid);
    };
    let crowsi_credential_authority_contracts::ManagementProjectionBodyV2::Operation { operation } =
        &projection.body
    else {
        return Err(HostError::StateInvalid);
    };
    (operation.state == crowsi_credential_authority_contracts::ManagementOperationState::Cancelled
        && operation.state_revision == request.expected_cancelled_state_revision
        && receipt.accepted_ledger_revision <= ledger.revision)
        .then_some(())
        .ok_or(HostError::StateInvalid)
}

fn acceptance_exact(
    ledger: &crate::management_v2_record::ManagementLedgerV2,
    location: Location,
    request: &EndpointRevocationExecutionCancelRequestV1,
) -> bool {
    let (self_value, independent) = acceptances(ledger, location);
    self_value.is_some_and(|item| {
        item.source_approve_request_sha256 == request.pre_final_acceptance_request_sha256
            && item.begin_exchange == request.begin_exchange
            && slot_self(item)
    }) || independent.is_some_and(|item| {
        item.pre_final_request_sha256 == request.pre_final_acceptance_request_sha256
            && item.begin_exchange == request.begin_exchange
            && slot_independent(item)
    })
}

include!("management_v2_journal_execution_cancellation_validation_support.rs");
