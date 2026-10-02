use crowsi_authority_transport::{PeerBinding, SignedRequest};
use crowsi_credential_authority_contracts::{
    ActorRequirementV2, ENDPOINT_MANAGEMENT_ENVELOPE_SCHEMA, EndpointManagementEnvelopeV2,
    EndpointManagementEvidenceV2, EndpointPreparedOperationV2, MANAGEMENT_PROJECTION_SCHEMA,
    MANAGEMENT_REQUEST_SCHEMA, ManagementCommandV2, ManagementIntentV2, ManagementOperationKind,
    ManagementOperationScopeV2, ManagementOperationState, ManagementOperationV2,
    ManagementProjectionBodyV2, ManagementProjectionV2, ManagementRequestV2, RequiredActorRole,
    WebAuthnOptionsV2, canonical_management_projection, endpoint_operation_id,
    management_command_digest,
};
use ed25519_dalek::Signer;

use crate::{
    gateway_peer_response_fixture::{DEVICE_C, NOW},
    management_v2_record::{DurableResponseReceiptV1, DurableResponseV1, ManagementRecordV2},
};

pub(crate) const OWNER: &str = "psa_owner_0000000000000001";

pub(crate) struct RecoveryFixture {
    pub(crate) envelope: EndpointManagementEnvelopeV2,
    pub(crate) request: SignedRequest,
    pub(crate) record: ManagementRecordV2,
    pub(crate) receipt: DurableResponseReceiptV1,
}

pub(crate) fn recovery_fixture() -> RecoveryFixture {
    let identity_exchange = crate::gateway_peer_response_identity::exchange(
        &crate::gateway_peer_response_identity::identity(),
    );
    let identity =
        crowsi_credential_authority_contracts::identity_evidence_from_exchange(&identity_exchange)
            .expect("identity");
    let browser = browser();
    let ManagementCommandV2::SourceOptions { intent } = &browser.command else {
        unreachable!()
    };
    let mut prepared = EndpointPreparedOperationV2 {
        operation_id: String::new(),
        origin_command_digest_sha256: management_command_digest(&browser).expect("digest"),
        source_device_ref: identity.assertion.device_id.clone(),
        source_session_ref: identity.assertion.session_ref.clone(),
        pairwise_subject: identity.assertion.pairwise_subject.clone(),
        opaque_owner_ref: OWNER.into(),
        source_identity_nonce: identity.assertion.nonce.clone(),
        nonce: "operation-nonce".into(),
        issued_at_epoch_s: NOW,
        expires_at_epoch_s: NOW + 300,
        intent: intent.clone(),
        revocation: None,
    };
    prepared.operation_id = endpoint_operation_id(&prepared).expect("operation id");
    let begin = begin(&prepared);
    crowsi_credential_authority_contracts::validate_endpoint_prepared_at(&prepared, identity, NOW)
        .expect("prepared binding");
    crowsi_credential_authority_contracts::validate_authority_exchange(
        &begin,
        "begin_fresh_user_verification",
    )
    .expect("begin exchange");
    let operation = operation(&prepared, &begin);
    let envelope = EndpointManagementEnvelopeV2 {
        schema: ENDPOINT_MANAGEMENT_ENVELOPE_SCHEMA.into(),
        browser_request: browser,
        evidence: EndpointManagementEvidenceV2::SourceOptions {
            identity_exchange: identity_exchange.clone(),
            prepared: prepared.clone(),
            uv_options: begin.clone(),
        },
    };
    let wire = serde_json::to_vec(&envelope).expect("envelope");
    crowsi_credential_authority_contracts::decode_endpoint_management_envelope_strict(&wire)
        .expect("strict envelope");
    let mut record = crate::management_v2_journal_fixture::record(OWNER, DEVICE_C, "recovery");
    record.operation = operation.clone();
    record.prepared = prepared;
    record.owner_ref = OWNER.into();
    record.service_id.clone_from(&identity.assertion.service_id);
    record
        .pairwise_subject
        .clone_from(&identity.assertion.pairwise_subject);
    record.authority_config_generation = identity_exchange.response.config_generation;
    record.source_identity_exchange = identity_exchange.clone();
    record.source_options_exchange = begin;
    let projection = projection(&envelope.browser_request, identity, operation, 2, NOW, 7);
    let receipt = DurableResponseReceiptV1 {
        request_digest_sha256: crate::management_v2_journal_policy::envelope_digest(&envelope)
            .expect("envelope digest"),
        identity_exchange_sha256: crate::management_v2_journal_policy::exchange_digest(
            &identity_exchange,
        )
        .expect("identity digest"),
        actor_device_ref: DEVICE_C.into(),
        phase: Some("source-options".into()),
        read_only: false,
        operation_id: Some(record.operation.operation_id.clone()),
        accepted_ledger_revision: 1,
        accepted_generation_head: 1,
        retain_until_epoch_s: u64::MAX,
        response: DurableResponseV1::Projection(Box::new(projection)),
    };
    let request = SignedRequest {
        peer: PeerBinding {
            device_id: DEVICE_C.into(),
            certificate_sha256: format!("sha256:{}", "c".repeat(64)),
            request_key_id: "request-c".into(),
            request_public_key_hex: crate::gateway_peer_response_identity::public(12),
        },
        command: "source-options".into(),
        payload: wire,
    };
    RecoveryFixture {
        envelope,
        request,
        record,
        receipt,
    }
}

fn browser() -> ManagementRequestV2 {
    ManagementRequestV2 {
        schema: MANAGEMENT_REQUEST_SCHEMA.into(),
        request_id: "historic-source-options".into(),
        command: ManagementCommandV2::SourceOptions {
            intent: ManagementIntentV2::DeviceTransfer {
                service_id: "service-a".into(),
                target_device_ref: "device-b".into(),
                credential_refs: vec!["credential-a".into()],
                expected_snapshot_revision: 1,
                nonce: "browser-nonce".into(),
            },
        },
    }
}

include!("management_v2_mutation_recovery_test_values.rs");
