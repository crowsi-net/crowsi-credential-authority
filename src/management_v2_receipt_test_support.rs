use crowsi_credential_authority_contracts::{
    MANAGEMENT_PROJECTION_SCHEMA, ManagementProjectionBodyV2, ManagementProjectionV2,
};

use crate::{
    management_v2_journal_update::EvidenceUse,
    management_v2_record::{DurableResponseReceiptV1, DurableResponseV1, ManagementRecordV2},
};

pub(crate) fn receipt(
    record: &ManagementRecordV2,
    request: char,
    identity: char,
    revision: u64,
    read_only: bool,
    retain_until: u64,
) -> DurableResponseReceiptV1 {
    DurableResponseReceiptV1 {
        request_digest_sha256: digest(request),
        identity_exchange_sha256: digest(identity),
        actor_device_ref: record.prepared.source_device_ref.clone(),
        phase: (!read_only).then(|| "source-options".into()),
        read_only,
        operation_id: (!read_only).then(|| record.operation.operation_id.clone()),
        accepted_ledger_revision: 1,
        accepted_generation_head: 1,
        retain_until_epoch_s: retain_until,
        response: DurableResponseV1::Projection(Box::new(ManagementProjectionV2 {
            schema: MANAGEMENT_PROJECTION_SCHEMA.into(),
            projection_id: format!("projection-{request}"),
            request_id: format!("request-{request}"),
            command_digest_sha256: "ab".repeat(32),
            issuer: "projection-issuer".into(),
            audience: "crowsi".into(),
            service_id: record.service_id.clone(),
            pairwise_subject: record.pairwise_subject.clone(),
            opaque_account_ref: record.owner_ref.clone(),
            current_device_ref: record.prepared.source_device_ref.clone(),
            current_session_ref: record.prepared.source_session_ref.clone(),
            subject_revocation_epoch: 1,
            service_revocation_epoch: 1,
            device_revocation_epoch: 1,
            session_revocation_epoch: 1,
            device_posture_state: "healthy".into(),
            device_posture_revision: 1,
            device_proof_key_ref: "proof-a".into(),
            snapshot_revision: revision,
            issued_at_epoch_s: 1_000,
            expires_at_epoch_s: retain_until,
            body: ManagementProjectionBodyV2::Operation {
                operation: record.operation.clone(),
            },
            key_id: "projection-key".into(),
            signature: "00".repeat(64),
        })),
    }
}

pub(crate) fn evidence<'a>(id: &'a str, binding: &'a str, expires: u64) -> EvidenceUse<'a> {
    EvidenceUse {
        kind: "identity_assertion_nonce",
        id,
        binding,
        expires_at_epoch_s: expires,
    }
}

pub(crate) fn digest(value: char) -> String {
    format!("sha256:{}", value.to_string().repeat(64))
}
