use crowsi_credential_authority_contracts::{
    CredentialClassV2, ManagementCredentialV2, ManagementDeviceV2, ManagementLifecycleV2,
    ManagementOperationV2, ManagementSessionV2, ManagementSnapshotV2,
};
use std::collections::BTreeMap;

use crate::{HostError, host_output_contracts::Projection};

pub(crate) fn decode(
    encoded: &str,
    pending_operations: Vec<ManagementOperationV2>,
) -> Result<ManagementSnapshotV2, HostError> {
    let value: Projection =
        serde_json::from_str(encoded).map_err(|_| HostError::ResponseInvalid)?;
    if value.schema_id != "crowsi-coela-management-projection-v1" {
        return Err(HostError::ResponseInvalid);
    }
    let mut sessions_by_device: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let sessions = value
        .sessions
        .into_iter()
        .map(|item| {
            sessions_by_device
                .entry(item.device_id.clone())
                .or_default()
                .push(item.session_ref.clone());
            Ok(ManagementSessionV2 {
                session_ref: item.session_ref,
                device_ref: item.device_id,
                status: lifecycle(item.revoked),
                session_revocation_epoch: item.session_revocation_epoch,
                issued_at_rfc3339: timestamp(item.issued_at_epoch_ms)?,
                expires_at_rfc3339: timestamp(item.expires_at_epoch_ms)?,
            })
        })
        .collect::<Result<Vec<_>, HostError>>()?;
    let devices = value
        .devices
        .into_iter()
        .map(|item| {
            Ok(ManagementDeviceV2 {
                device_ref: item.device_id.clone(),
                status: lifecycle(item.revoked),
                device_revocation_epoch: item.device_revocation_epoch,
                posture_revision: item.posture_revision,
                session_refs: sessions_by_device
                    .remove(&item.device_id)
                    .unwrap_or_default(),
                created_at_rfc3339: timestamp(item.enrolled_at_epoch_ms)?,
                updated_at_rfc3339: timestamp(item.last_seen_at_epoch_ms)?,
            })
        })
        .collect::<Result<Vec<_>, HostError>>()?;
    let credentials = value
        .credentials
        .into_iter()
        .map(|item| {
            Ok(ManagementCredentialV2 {
                credential_ref: item.credential_id,
                provider: item.service_id,
                class: class(&item.class)?,
                revision: item.revision,
                status: lifecycle(item.revoked),
                assigned_device_refs: item.assigned_device_ids,
                scopes: item.scopes,
                created_at_rfc3339: timestamp(item.created_at_epoch_ms)?,
                updated_at_rfc3339: timestamp(item.updated_at_epoch_ms)?,
            })
        })
        .collect::<Result<Vec<_>, HostError>>()?;
    Ok(ManagementSnapshotV2 {
        devices,
        sessions,
        credentials,
        pending_operations,
    })
}

fn lifecycle(revoked: bool) -> ManagementLifecycleV2 {
    if revoked {
        ManagementLifecycleV2::Revoked
    } else {
        ManagementLifecycleV2::Active
    }
}

fn class(value: &str) -> Result<CredentialClassV2, HostError> {
    match value {
        "operation-only" => Ok(CredentialClassV2::OperationOnly),
        "delegated-token" => Ok(CredentialClassV2::DelegatedToken),
        "certificate" => Ok(CredentialClassV2::Certificate),
        _ => Err(HostError::ResponseInvalid),
    }
}

fn timestamp(epoch_ms: u64) -> Result<String, HostError> {
    time::OffsetDateTime::from_unix_timestamp_nanos(i128::from(epoch_ms) * 1_000_000)
        .map_err(|_| HostError::ResponseInvalid)?
        .format(&time::format_description::well_known::Rfc3339)
        .map_err(|_| HostError::ResponseInvalid)
}
