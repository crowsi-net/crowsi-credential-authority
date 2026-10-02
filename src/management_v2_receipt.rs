use std::collections::{BTreeMap, BTreeSet};

use crowsi_credential_authority_contracts::{
    EndpointManagementEnvelopeV2, EndpointPreparedLookupResponseV1, ManagementProjectionBodyV2,
    ManagementProjectionV2,
};

use crate::{
    HostError,
    host_config::VerifiedHostConfig,
    management_v2_identity::VerifiedManagementIdentity,
    management_v2_record::{DurableResponseReceiptV1 as Receipt, DurableResponseV1 as Response},
};

pub(crate) fn projection(
    config: &VerifiedHostConfig,
    envelope: &EndpointManagementEnvelopeV2,
    verified: &VerifiedManagementIdentity<'_>,
    body: ManagementProjectionBodyV2,
    snapshot_revision: u64,
    now: u64,
    retain_until: u64,
    read_only: bool,
) -> Result<Receipt, HostError> {
    let operation_id = match &body {
        ManagementProjectionBodyV2::Operation { operation } => Some(operation.operation_id.clone()),
        ManagementProjectionBodyV2::Snapshot { .. }
        | ManagementProjectionBodyV2::Pending { .. } => None,
    };
    let wire = crate::management_v2_projection::signed(
        config,
        &envelope.browser_request,
        verified.identity,
        &verified.owner.opaque_owner_ref,
        snapshot_revision,
        body,
        now,
    )?;
    let response: ManagementProjectionV2 =
        serde_json::from_slice(&wire).map_err(|_| HostError::ResponseInvalid)?;
    let retain_until = if read_only {
        retain_until.min(response.expires_at_epoch_s)
    } else {
        u64::MAX
    };
    let phase = (!read_only)
        .then(|| crate::management_v2_command::route(&envelope.browser_request.command));
    receipt(
        crate::management_v2_journal_policy::envelope_digest(envelope)?,
        crate::management_v2_journal_policy::exchange_digest(verified.identity_exchange)?,
        verified.identity.assertion.device_id.clone(),
        phase,
        read_only,
        operation_id,
        retain_until,
        Response::Projection(Box::new(response)),
    )
}

pub(crate) fn prepared_lookup(
    request_digest: String,
    identity_digest: String,
    actor: String,
    operation_id: String,
    retain_until: u64,
    response: EndpointPreparedLookupResponseV1,
) -> Result<Receipt, HostError> {
    receipt(
        request_digest,
        identity_digest,
        actor,
        None,
        true,
        Some(operation_id),
        retain_until.min(response.expires_at_epoch_s),
        Response::PreparedLookup(Box::new(response)),
    )
}

pub(crate) fn wire(value: &Receipt) -> Result<Vec<u8>, HostError> {
    let wire = match &value.response {
        Response::Projection(value) => serde_json::to_vec(value),
        Response::PreparedLookup(value) => serde_json::to_vec(value),
    }
    .map_err(|_| HostError::ResponseInvalid)?;
    (wire.len() <= 262_144)
        .then_some(wire)
        .ok_or(HostError::ResponseInvalid)
}

pub(crate) fn lookup_request_digest(value: &str) -> String {
    let mut wire = b"CROWSI-PREPARED-LOOKUP-RECEIPT-V1\0".to_vec();
    wire.extend_from_slice(value.as_bytes());
    crate::host_crypto::digest(&wire)
}

fn receipt(
    request_digest_sha256: String,
    identity_exchange_sha256: String,
    actor_device_ref: String,
    phase: Option<&str>,
    read_only: bool,
    operation_id: Option<String>,
    retain_until_epoch_s: u64,
    response: Response,
) -> Result<Receipt, HostError> {
    let value = Receipt {
        request_digest_sha256,
        identity_exchange_sha256,
        actor_device_ref,
        phase: phase.map(str::to_owned),
        read_only,
        operation_id,
        accepted_ledger_revision: 1,
        accepted_generation_head: 1,
        retain_until_epoch_s,
        response,
    };
    valid_set(std::slice::from_ref(&value))
        .then_some(value)
        .ok_or(HostError::ResponseInvalid)
}

include!("management_v2_receipt_validation.rs");
