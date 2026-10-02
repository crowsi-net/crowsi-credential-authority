use crowsi_credential_authority_contracts::{
    ENDPOINT_MANAGEMENT_ENVELOPE_SCHEMA, EndpointManagementEnvelopeV2,
    EndpointManagementEvidenceV2, MANAGEMENT_REQUEST_SCHEMA, ManagementCommandV2,
    ManagementRequestV2,
};
use serde_json::{Value, json};

use crate::{
    config::Documents,
    fixture::{Fixture, public},
    identity::{DEVICE_A, evidence_exchange},
};

pub(crate) fn snapshot(fixture: &Fixture, documents: &Documents) -> Vec<u8> {
    crate::process_run::initialize(fixture, documents);
    let browser_request = ManagementRequestV2 {
        schema: MANAGEMENT_REQUEST_SCHEMA.into(),
        request_id: "real-host-snapshot".into(),
        command: ManagementCommandV2::Snapshot {
            service_id: "service-a".into(),
        },
    };
    let envelope = EndpointManagementEnvelopeV2 {
        schema: ENDPOINT_MANAGEMENT_ENVELOPE_SCHEMA.into(),
        browser_request,
        evidence: EndpointManagementEvidenceV2::Passive {
            identity_exchange: evidence_exchange(fixture),
        },
    };
    let payload = serde_json::to_vec(&envelope).expect("endpoint envelope");
    let wire = serde_json::to_vec(&json!({
        "schema":"crowsi://credential-authority/gateway-host-request/v1",
        "command":"snapshot","peer":{"device_id":DEVICE_A,
            "certificate_sha256":format!("sha256:{}","a".repeat(64)),
            "request_key_id":"request-a","request_public_key_hex":public(12)},
        "payload_hex":hex::encode(payload)
    }))
    .expect("gateway host request");
    crate::process_run::run(fixture, documents, "management-v2", &wire)
}

pub(crate) fn peer_head(fixture: &Fixture, documents: &Documents) -> (Value, Vec<u8>) {
    let request = json!({
        "schema":"crowsi://credential-authority/peer-status-head-request/v1",
        "request_id":format!("peerhead_{}","a".repeat(64)),
        "deployment_id":"central-authority-1",
        "gateway_config_sha256":documents.gateway_digest,
        "authority_epoch":1
    });
    let wire = serde_json::to_vec(&request).expect("head request");
    let response = crate::process_run::run(fixture, documents, "peer-status-head", &wire);
    (request, response)
}
