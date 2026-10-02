use crowsi_authority_transport::{PeerBinding, SignedRequest};
use crowsi_credential_authority_contracts::{
    ENDPOINT_MANAGEMENT_ENVELOPE_SCHEMA,
    ENDPOINT_REVOCATION_EXECUTION_CANCEL_CLEANUP_COMPLETE_REQUEST_SCHEMA,
    ENDPOINT_REVOCATION_EXECUTION_CANCEL_FINALIZE_REQUEST_SCHEMA,
    ENDPOINT_REVOCATION_EXECUTION_CANCEL_REQUEST_SCHEMA, EndpointManagementEnvelopeV2,
    EndpointManagementEvidenceV2, EndpointRevocationExecutionCancelCleanupCompleteRequestV1,
    EndpointRevocationExecutionCancelFinalizeRequestV1, EndpointRevocationExecutionCancelRequestV1,
    ManagementCommandV2, ManagementOperationState,
    decode_endpoint_revocation_execution_cancellation_cleanup_strict,
    decode_endpoint_revocation_execution_cancellation_strict,
};

use crate::management_v2_revocation_finalization_tests::{
    DEVICE, NOW, OWNER, RevocationCase, persist, revocation_case,
};

fn cancel_envelope(value: &RevocationCase) -> EndpointManagementEnvelopeV2 {
    EndpointManagementEnvelopeV2 {
        schema: ENDPOINT_MANAGEMENT_ENVELOPE_SCHEMA.into(),
        browser_request: crowsi_credential_authority_contracts::ManagementRequestV2 {
            schema: crowsi_credential_authority_contracts::MANAGEMENT_REQUEST_SCHEMA.into(),
            request_id: "browser-cancel-finalization".into(),
            command: ManagementCommandV2::Cancel {
                operation_id: value.record.operation.operation_id.clone(),
                expected_state_revision: 2,
            },
        },
        evidence: EndpointManagementEvidenceV2::Cancel {
            identity_exchange: value.reserve.accepted_identity_exchange.clone(),
            prepared: value.record.prepared.clone(),
        },
    }
}

fn cancellation_request(
    value: &RevocationCase,
    cancel_envelope: EndpointManagementEnvelopeV2,
) -> Box<EndpointRevocationExecutionCancelRequestV1> {
    Box::new(EndpointRevocationExecutionCancelRequestV1 {
        schema: ENDPOINT_REVOCATION_EXECUTION_CANCEL_REQUEST_SCHEMA.into(),
        request_id: "internal-cancel-pending".into(),
        operation_id: value.record.operation.operation_id.clone(),
        expected_cancelled_state_revision: 3,
        pre_final_acceptance_request_sha256: value
            .reserve
            .pre_final_acceptance_request_sha256
            .clone(),
        cancel_envelope,
        prepared: value.record.prepared.clone(),
        begin_exchange: value.reserve.begin_exchange.clone(),
    })
}

fn cleanup_request(
    cancellation_request: Box<EndpointRevocationExecutionCancelRequestV1>,
    cancellation: Box<
        crowsi_credential_authority_contracts::EndpointRevocationExecutionCancellationV1,
    >,
    cancel_pending_exchange: crowsi_credential_authority_contracts::SignedAuthorityExchangeV1,
) -> Box<EndpointRevocationExecutionCancelFinalizeRequestV1> {
    Box::new(EndpointRevocationExecutionCancelFinalizeRequestV1 {
        schema: ENDPOINT_REVOCATION_EXECUTION_CANCEL_FINALIZE_REQUEST_SCHEMA.into(),
        request_id: "internal-cancel-finalize".into(),
        operation_id: cancellation_request.operation_id.clone(),
        cancellation_request,
        cancellation,
        cancel_pending_exchange,
    })
}

fn decode_cancellation(
    wire: &[u8],
) -> Box<crowsi_credential_authority_contracts::EndpointRevocationExecutionCancellationV1> {
    Box::new(
        decode_endpoint_revocation_execution_cancellation_strict(wire).expect("cancellation outer"),
    )
}

fn decode_cleanup(
    wire: &[u8],
) -> Box<crowsi_credential_authority_contracts::EndpointRevocationExecutionCancellationCleanupV1> {
    Box::new(
        decode_endpoint_revocation_execution_cancellation_cleanup_strict(wire)
            .expect("cleanup outer"),
    )
}

fn cleanup_complete_request(
    cancel_finalize_request: Box<EndpointRevocationExecutionCancelFinalizeRequestV1>,
    cleanup: Box<
        crowsi_credential_authority_contracts::EndpointRevocationExecutionCancellationCleanupV1,
    >,
    acknowledge_exchange: crowsi_credential_authority_contracts::SignedAuthorityExchangeV1,
) -> Box<EndpointRevocationExecutionCancelCleanupCompleteRequestV1> {
    Box::new(EndpointRevocationExecutionCancelCleanupCompleteRequestV1 {
        schema: ENDPOINT_REVOCATION_EXECUTION_CANCEL_CLEANUP_COMPLETE_REQUEST_SCHEMA.into(),
        request_id: "internal-cancel-cleanup-complete".into(),
        operation_id: cancel_finalize_request.operation_id.clone(),
        cancel_finalize_request,
        cleanup,
        acknowledge_exchange,
    })
}

include!("management_v2_execution_cancellation_test_environment.rs");
include!("management_v2_execution_cancellation_test_exchange.rs");
include!("management_v2_execution_cancellation_delivery_test_support.rs");
