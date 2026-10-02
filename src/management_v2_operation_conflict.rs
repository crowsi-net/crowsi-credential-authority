use std::collections::BTreeSet;

use crowsi_credential_authority_contracts::ManagementOperationScopeV2;

use crate::management_v2_record::{ManagementLedgerV2, ManagementRecordV2};

pub(crate) fn available(ledger: &ManagementLedgerV2, candidate: &ManagementRecordV2) -> bool {
    available_filtering(ledger, candidate, None)
}

pub(crate) fn available_replacement(
    ledger: &ManagementLedgerV2,
    candidate: &ManagementRecordV2,
) -> bool {
    available_filtering(
        ledger,
        candidate,
        Some(candidate.operation.operation_id.as_str()),
    )
}

fn available_filtering(
    ledger: &ManagementLedgerV2,
    candidate: &ManagementRecordV2,
    excluded_operation_id: Option<&str>,
) -> bool {
    let candidate = Resources::from(candidate);
    ledger
        .records
        .iter()
        .filter(|record| !crate::management_v2_quota::terminal(record))
        .filter(|record| excluded_operation_id != Some(record.operation.operation_id.as_str()))
        .map(Resources::from)
        .all(|current| !current.overlaps(&candidate))
}

#[derive(Default)]
struct Resources {
    credentials: BTreeSet<String>,
    devices: BTreeSet<String>,
    sessions: BTreeSet<String>,
}

impl Resources {
    fn from(record: &ManagementRecordV2) -> Self {
        let mut value = Self::default();
        match &record.operation.scope {
            ManagementOperationScopeV2::DeviceTransfer {
                target_device_ref,
                credential_refs,
                ..
            } => {
                value
                    .devices
                    .insert(record.operation.source_device_ref.clone());
                value.devices.insert(target_device_ref.clone());
                value.credentials.extend(credential_refs.iter().cloned());
            }
            ManagementOperationScopeV2::DeviceRevocation {
                target_device_ref,
                revokes_session_refs,
                rotates_credential_refs,
                ..
            } => {
                value.devices.insert(target_device_ref.clone());
                if let Some(saga) = &record.revocation_saga {
                    value.devices.extend(
                        saga.rotations
                            .iter()
                            .map(|rotation| rotation.target_device_ref.clone())
                            .filter(|target| !target.is_empty()),
                    );
                }
                value.sessions.extend(revokes_session_refs.iter().cloned());
                value
                    .credentials
                    .extend(rotates_credential_refs.iter().cloned());
            }
            ManagementOperationScopeV2::SessionRevocation {
                target_session_ref,
                device_ref,
                ..
            } => {
                value.devices.insert(device_ref.clone());
                value.sessions.insert(target_session_ref.clone());
            }
        }
        if let Some(finalizer) = reserved_finalizer(record) {
            value.devices.insert(finalizer.to_owned());
        }
        value
    }

    fn overlaps(&self, other: &Self) -> bool {
        intersects(&self.credentials, &other.credentials)
            || intersects(&self.devices, &other.devices)
            || intersects(&self.sessions, &other.sessions)
    }
}

fn reserved_finalizer(record: &ManagementRecordV2) -> Option<&str> {
    record
        .revocation_finalization
        .as_ref()
        .and_then(|value| value.execution_reservation.as_ref())
        .or_else(|| {
            record
                .independent_revocation_finalization
                .as_ref()
                .and_then(|value| value.execution_reservation.as_ref())
        })
        .map(|value| value.reservation.finalizer_device_ref.as_str())
}

fn intersects(left: &BTreeSet<String>, right: &BTreeSet<String>) -> bool {
    left.iter().any(|item| right.contains(item))
}
