use crowsi_credential_authority_contracts::{
    ActorRequirementV2, ManagementOperationState, ManagementProjectionBodyV2, RequiredActorRole,
    decode_management_projection_strict,
};

use crate::{
    gateway_peer_response_fixture::{DEVICE_C, NOW},
    management_v2_journal_fixture::Fixture,
    management_v2_mutation_recovery_test_support::{
        OWNER, RecoveryFixture, projection, recovery_fixture,
    },
};

#[test]
fn active_cross_phase_receipts_recover_old_exact_request_at_current_head() {
    let state = Fixture::new();
    let value = recovery_fixture();
    let original_operation = value.record.operation.clone();
    let (_, original_wire) = state
        .journal()
        .insert_consuming_response(value.record.clone(), &[], value.receipt.clone(), NOW)
        .expect("source options acceptance");
    assert_eq!(
        handler(&state, 7)
            .recover_mutation_response(&value.envelope, DEVICE_C, NOW + 1)
            .expect("exact recovery")
            .expect("receipt"),
        original_wire
    );

    advance_cross_phase(&state, &value);
    let ledger = crate::management_v2_journal_io::read(&state.state, &state.anchor, OWNER)
        .expect("durable cross-phase receipts");
    assert_eq!(ledger.durable_responses.len(), 3);
    assert!(
        ["source-options", "source-approve", "target-options"]
            .iter()
            .all(|phase| ledger
                .durable_responses
                .iter()
                .any(|item| item.phase.as_deref() == Some(*phase)))
    );
    let recovery = state
        .journal()
        .mutation_recovery_view(&value.envelope, DEVICE_C, NOW + 301)
        .expect("historic view")
        .expect("accepted receipt");
    assert_eq!(recovery.accepted_snapshot_revision, 2);
    assert_eq!(recovery.current_snapshot_revision, 4);
    assert_eq!(recovery.accepted_generation_head, 2);
    assert_eq!(recovery.current_generation_head, 4);

    let wire = handler(&state, 8)
        .recover_mutation_response(&value.envelope, DEVICE_C, NOW + 301)
        .expect("historic recovery")
        .expect("receipt");
    let response = decode_management_projection_strict(&wire).expect("projection");
    assert_eq!(response.snapshot_revision, 4);
    assert_eq!(response.key_id, "projection-key-rotated");
    assert!(matches!(
        response.body,
        ManagementProjectionBodyV2::Operation { operation } if operation == original_operation
    ));
    let mut unmapped = handler(&state, 8);
    unmapped.core.config.document.owner_mappings.clear();
    assert!(
        unmapped
            .recover_mutation_response(&value.envelope, DEVICE_C, NOW + 301)
            .is_err()
    );

    let mut substituted = value.envelope.clone();
    substituted.browser_request.request_id = "substituted".into();
    assert!(
        state
            .journal()
            .mutation_recovery_view(&substituted, DEVICE_C, NOW + 301)
            .is_err()
    );
    assert!(
        state
            .journal()
            .mutation_recovery_view(&value.envelope, "device-substituted", NOW + 301)
            .is_err()
    );
    let mut wrong_signature = value.envelope.clone();
    let crowsi_credential_authority_contracts::EndpointManagementEvidenceV2::SourceOptions {
        identity_exchange,
        ..
    } = &mut wrong_signature.evidence
    else {
        unreachable!()
    };
    let ihat_identity_assertion_contracts::ResponseOutcome::Committed {
        result: ihat_identity_assertion_contracts::AuthorityResult::IdentityEvidence(identity),
    } = &mut identity_exchange.response.outcome
    else {
        unreachable!()
    };
    identity.assertion.signature = "12".repeat(64);
    assert!(
        state
            .journal()
            .mutation_recovery_view(&wrong_signature, DEVICE_C, NOW + 301)
            .expect("fabricated envelope is not accepted")
            .is_none()
    );
}

fn advance_cross_phase(state: &Fixture, value: &RecoveryFixture) {
    let mut source = value.record.clone();
    source.operation.state = ManagementOperationState::AwaitingTarget;
    source.operation.state_revision = 2;
    source.operation.webauthn_options = None;
    source.operation.actor = ActorRequirementV2 {
        role: RequiredActorRole::TargetDevice,
        required_actor_device_ref: Some("device-b".into()),
        required_approval_authority_ref: None,
        excluded_actor_device_refs: vec![DEVICE_C.into()],
    };
    source.authority_config_generation = 3;
    let receipt = phase_receipt(value, &source, "source-approve", 'd', 3, DEVICE_C);
    state
        .journal()
        .replace_consuming_response(1, source.clone(), &[], receipt, NOW + 1, None)
        .expect("source approve phase");

    let mut target = source;
    target.operation.state = ManagementOperationState::AwaitingTargetUv;
    target.operation.state_revision = 3;
    target
        .operation
        .webauthn_options
        .clone_from(&value.record.operation.webauthn_options);
    target.authority_config_generation = 4;
    let receipt = phase_receipt(value, &target, "target-options", 'e', 4, "device-b");
    state
        .journal()
        .replace_consuming_response(2, target, &[], receipt, NOW + 2, None)
        .expect("target options phase");
}

include!("management_v2_mutation_recovery_test_helpers.rs");
