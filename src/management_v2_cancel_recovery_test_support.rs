use crowsi_credential_authority_contracts::{
    ActorRequirementV2, ENDPOINT_MANAGEMENT_ENVELOPE_SCHEMA, EndpointManagementEnvelopeV2,
    EndpointManagementEvidenceV2, MANAGEMENT_REQUEST_SCHEMA, ManagementCommandV2,
    ManagementOperationState, ManagementReasonCode, ManagementRequestV2, RequiredActorRole,
    canonical_management_projection, identity_evidence_from_exchange, management_command_digest,
};
use ed25519_dalek::Signer;

use crate::{
    management_v2_journal_fixture::{Fixture, NOW, record},
    management_v2_receipt_test_support::receipt,
};

struct AcceptedCancel {
    fixture: Fixture,
    envelope: EndpointManagementEnvelopeV2,
    cancelled: crate::management_v2_record::ManagementRecordV2,
    original_wire: Vec<u8>,
}

fn accepted_cancel() -> AcceptedCancel {
    let fixture = Fixture::new();
    let journal = fixture.journal();
    let mut active = record("owner", "device-a", "a");
    let ihat_identity_assertion_contracts::ResponseOutcome::Committed {
        result: ihat_identity_assertion_contracts::AuthorityResult::IdentityEvidence(identity),
    } = &mut active.source_identity_exchange.response.outcome
    else {
        unreachable!()
    };
    identity.assertion.device_posture.state = "compliant".into();
    identity.current_status.device_posture.state = "compliant".into();
    active.prepared.issued_at_epoch_s = NOW;
    active.prepared.operation_id =
        crowsi_credential_authority_contracts::endpoint_operation_id(&active.prepared)
            .expect("operation id");
    active
        .operation
        .operation_id
        .clone_from(&active.prepared.operation_id);
    journal.insert(active.clone(), NOW).expect("active");
    let envelope = cancel_envelope(&active);
    let mut cancelled = active;
    cancelled.operation.state = ManagementOperationState::Cancelled;
    cancelled.operation.state_revision = 2;
    cancelled.operation.actor = no_actor();
    cancelled.operation.reason = Some(ManagementReasonCode::OperationCancelled);
    cancelled.operation.reconcile_digest = None;
    let mut accepted = receipt(&cancelled, 'a', 'b', 3, false, NOW + 30);
    accepted.request_digest_sha256 =
        crate::management_v2_journal_policy::envelope_digest(&envelope).expect("envelope digest");
    let EndpointManagementEvidenceV2::Cancel {
        identity_exchange, ..
    } = &envelope.evidence
    else {
        unreachable!()
    };
    accepted.identity_exchange_sha256 =
        crate::management_v2_journal_policy::exchange_digest(identity_exchange)
            .expect("identity digest");
    accepted.retain_until_epoch_s = u64::MAX;
    let crate::management_v2_record::DurableResponseV1::Projection(response) =
        &mut accepted.response
    else {
        unreachable!()
    };
    bind_response(response, &envelope);
    let (_, original_wire) = journal
        .replace_consuming_response(1, cancelled.clone(), &[], accepted, NOW, None)
        .expect("atomic cancel receipt");
    AcceptedCancel {
        fixture,
        envelope,
        cancelled,
        original_wire,
    }
}

include!("management_v2_cancel_recovery_test_projection.rs");

fn cancel_envelope(
    value: &crate::management_v2_record::ManagementRecordV2,
) -> EndpointManagementEnvelopeV2 {
    EndpointManagementEnvelopeV2 {
        schema: ENDPOINT_MANAGEMENT_ENVELOPE_SCHEMA.into(),
        browser_request: ManagementRequestV2 {
            schema: MANAGEMENT_REQUEST_SCHEMA.into(),
            request_id: "cancel-recovery".into(),
            command: ManagementCommandV2::Cancel {
                operation_id: value.operation.operation_id.clone(),
                expected_state_revision: 1,
            },
        },
        evidence: EndpointManagementEvidenceV2::Cancel {
            identity_exchange: value.source_identity_exchange.clone(),
            prepared: value.prepared.clone(),
        },
    }
}

fn no_actor() -> ActorRequirementV2 {
    ActorRequirementV2 {
        role: RequiredActorRole::NoActor,
        required_actor_device_ref: None,
        required_approval_authority_ref: None,
        excluded_actor_device_refs: Vec::new(),
    }
}

fn move_to_tombstone(
    fixture: &crate::management_v2_journal_test_environment::Fixture,
    record: &crate::management_v2_record::ManagementRecordV2,
) {
    let mut ledger =
        crate::management_v2_journal_io::read(&fixture.state, &fixture.anchor, "owner")
            .expect("ledger");
    ledger.records.clear();
    ledger.tombstones.push(
        crate::management_v2_record::ManagementTombstoneV2::from_record(record).expect("tombstone"),
    );
    ledger.revision += 1;
    crate::management_v2_journal_io::write(&fixture.state, &fixture.anchor, "owner", &ledger)
        .expect("persist tombstone");
}

fn compact_after_long_stop(fixture: &Fixture) {
    let mut ledger =
        crate::management_v2_journal_io::read(&fixture.state, &fixture.anchor, "owner")
            .expect("ledger");
    crate::management_v2_journal_policy::compact(&mut ledger, NOW + 601).expect("compact");
    ledger.revision += 1;
    crate::management_v2_journal_io::write(&fixture.state, &fixture.anchor, "owner", &ledger)
        .expect("persist compacted tombstone");
}
