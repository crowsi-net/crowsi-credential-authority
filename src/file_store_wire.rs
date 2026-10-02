use crate::session::SessionRecord;
use crate::state::{DeviceRecord, TransferRecord};
use crate::{
    AccountState, AuthorityError, CredentialId, CredentialMetadata, DeviceGrant, DeviceId,
    DurableSnapshot, GrantId, OpaqueOwnerRef, TransferId,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct DeviceWire {
    owner: OpaqueOwnerRef,
    device: DeviceId,
    record: DeviceRecord,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SessionWire {
    owner: OpaqueOwnerRef,
    session_ref: String,
    record: SessionRecord,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SnapshotWire {
    pub(crate) version: u64,
    clock_floor_ms: u64,
    next_id: u64,
    accounts: BTreeMap<OpaqueOwnerRef, AccountState>,
    devices: Vec<DeviceWire>,
    sessions: Vec<SessionWire>,
    credentials: BTreeMap<CredentialId, CredentialMetadata>,
    grants: BTreeMap<GrantId, DeviceGrant>,
    transfers: BTreeMap<TransferId, TransferRecord>,
    used_nonces: BTreeSet<String>,
    used_provider_receipts: BTreeSet<String>,
    custody_secret_deletion_requests: usize,
}

impl From<&DurableSnapshot> for SnapshotWire {
    fn from(value: &DurableSnapshot) -> Self {
        let devices = value
            .devices
            .iter()
            .map(|((owner, device), record)| DeviceWire {
                owner: owner.clone(),
                device: device.clone(),
                record: record.clone(),
            })
            .collect();
        let sessions = value
            .sessions
            .iter()
            .map(|((owner, session_ref), record)| SessionWire {
                owner: owner.clone(),
                session_ref: session_ref.clone(),
                record: record.clone(),
            })
            .collect();
        Self {
            version: value.version,
            clock_floor_ms: value.clock_floor_ms,
            next_id: value.next_id,
            accounts: value.accounts.clone(),
            devices,
            sessions,
            credentials: value.credentials.clone(),
            grants: value.grants.clone(),
            transfers: value.transfers.clone(),
            used_nonces: value.used_nonces.clone(),
            used_provider_receipts: value.used_provider_receipts.clone(),
            custody_secret_deletion_requests: value.custody_secret_deletion_requests,
        }
    }
}

impl SnapshotWire {
    pub(crate) fn into_snapshot(self) -> Result<DurableSnapshot, AuthorityError> {
        let mut devices = BTreeMap::new();
        for entry in self.devices {
            if entry.record.owner != entry.owner
                || devices
                    .insert((entry.owner, entry.device), entry.record)
                    .is_some()
            {
                return Err(AuthorityError::IntegrityViolation);
            }
        }
        let mut sessions = BTreeMap::new();
        for entry in self.sessions {
            if entry.record.owner != entry.owner
                || entry.record.session_ref != entry.session_ref
                || sessions
                    .insert((entry.owner, entry.session_ref), entry.record)
                    .is_some()
            {
                return Err(AuthorityError::IntegrityViolation);
            }
        }
        let snapshot = DurableSnapshot {
            version: self.version,
            clock_floor_ms: self.clock_floor_ms,
            next_id: self.next_id,
            accounts: self.accounts,
            devices,
            sessions,
            credentials: self.credentials,
            grants: self.grants,
            transfers: self.transfers,
            used_nonces: self.used_nonces,
            used_provider_receipts: self.used_provider_receipts,
            custody_secret_deletion_requests: self.custody_secret_deletion_requests,
        };
        crate::authority_limits::store_complete(&snapshot)
            .then_some(snapshot)
            .ok_or(AuthorityError::IntegrityViolation)
    }
}
