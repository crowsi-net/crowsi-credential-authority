use crowsi_credential_authority_contracts::{
    ActorRequirementV2, ENDPOINT_MANAGEMENT_ENVELOPE_SCHEMA,
    ENDPOINT_REVOCATION_EXECUTION_RESERVE_REQUEST_SCHEMA, EndpointManagementEnvelopeV2,
    EndpointManagementEvidenceV2, EndpointRevocationExecutionReserveRequestV1, ManagementCommandV2,
    ManagementIntentV2, ManagementOperationScopeV2, ManagementOperationState, ManagementRequestV2,
    RequiredActorRole, RevocationRequirementsV2, RevocationSourceCeremonyV1,
    SignedAuthorityExchangeV1, WebAuthnAssertionV2, endpoint_operation_id,
};

use crate::management_v2_record::{
    ManagementLedgerV2, ManagementRecordV2, RevocationFinalizationAcceptanceV1,
};

pub(crate) const NOW: u64 = crate::gateway_peer_response_fixture::NOW;
pub(crate) const DEVICE: &str = crate::gateway_peer_response_fixture::DEVICE_C;
pub(crate) const OWNER: &str = "psa_owner_0000000000000001";

pub(crate) struct RevocationCase {
    pub(crate) record: ManagementRecordV2,
    pub(crate) envelope: EndpointManagementEnvelopeV2,
    pub(crate) reserve: EndpointRevocationExecutionReserveRequestV1,
    pub(crate) final_exchange: SignedAuthorityExchangeV1,
}

pub(crate) fn revocation_case() -> RevocationCase {
    let identity = crate::gateway_peer_response_identity::identity();
    let identity_exchange = crate::gateway_peer_response_identity::exchange(&identity);
    let mut prepared =
        crate::management_v2_journal_fixture::revocation(OWNER, DEVICE, "final").prepared;
    prepared
        .source_session_ref
        .clone_from(&identity.assertion.session_ref);
    prepared
        .pairwise_subject
        .clone_from(&identity.assertion.pairwise_subject);
    prepared
        .source_identity_nonce
        .clone_from(&identity.assertion.nonce);
    prepared.issued_at_epoch_s = NOW;
    prepared.expires_at_epoch_s = NOW + 300;
    prepared.intent = ManagementIntentV2::DeviceRevocation {
        service_id: identity.assertion.service_id.clone(),
        target_device_ref: DEVICE.into(),
        expected_device_revocation_epoch: 1,
        expected_snapshot_revision: 1,
        nonce: "intent-final".into(),
    };
    prepared.revocation = Some(RevocationRequirementsV2 {
        target_device_ref: DEVICE.into(),
        required_approval_authority_ref: None,
        finalization_authority_id: "runtime-revocation-key".into(),
        expected_revoked_session_count: Some(1),
    });
    prepared.operation_id = endpoint_operation_id(&prepared).expect("operation id");
    let begin = begin_exchange(&prepared, &identity);
    let finish = finish_exchange(&begin);
    let source_request = source_request(&prepared.operation_id);
    let mut record = crate::management_v2_journal_fixture::revocation(OWNER, DEVICE, "record");
    configure_record(
        &mut record,
        &prepared,
        &identity_exchange,
        &finish,
        &source_request,
        &begin,
    );
    let envelope = source_envelope(
        &record,
        &source_request,
        &identity_exchange,
        &finish,
        &begin,
    );
    let phase = crate::management_v2_journal_policy::envelope_digest(&envelope).expect("phase");
    record.source_approval_acceptance_sha256 = Some(phase.clone());
    record.revocation_finalization = Some(Box::new(acceptance(
        &source_request,
        &identity_exchange,
        &begin,
        phase
            .strip_prefix("sha256:")
            .expect("framed phase digest")
            .into(),
    )));
    let final_revoke_exchange = final_exchange(&prepared);
    let reserve = EndpointRevocationExecutionReserveRequestV1 {
        schema: ENDPOINT_REVOCATION_EXECUTION_RESERVE_REQUEST_SCHEMA.into(),
        request_id: "internal-reserve".into(),
        operation_id: prepared.operation_id.clone(),
        expected_state_revision: 2,
        reconcile_digest: "44".repeat(32),
        original_request: source_request,
        prepared,
        pre_final_acceptance_request_sha256: phase[7..].into(),
        accepted_identity_exchange: identity_exchange.clone(),
        reservation_identity_exchange: identity_exchange,
        begin_exchange: begin,
        approval_exchange: None,
        final_revoke_request: final_revoke_exchange.request.clone(),
    };
    RevocationCase {
        record,
        envelope,
        reserve,
        final_exchange: final_revoke_exchange,
    }
}

pub(crate) fn persist(
    fixture: &crate::management_v2_journal_test_environment::Fixture,
    record: &ManagementRecordV2,
) {
    let mut ledger = ManagementLedgerV2::empty();
    ledger.revision = 2;
    ledger.authority_config_generation_head = 2;
    ledger.records.push(record.clone());
    crate::management_v2_journal_io::write(&fixture.state, &fixture.anchor, OWNER, &ledger)
        .expect("persist accepted record");
}

include!("management_v2_revocation_finalization_test_record.rs");
include!("management_v2_revocation_finalization_test_exchanges.rs");
include!("management_v2_revocation_finalization_reservation_test_support.rs");
