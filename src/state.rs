use crate::session::SessionRecord;
use crate::{
    AccountState, CredentialId, CredentialMetadata, DeviceGrant, DeviceId, GrantId, OpaqueOwnerRef,
    ProviderOperationOutcome, TransferId, TransferMechanism, TransferState,
};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RevocationCause {
    DeviceCompromised,
    ProviderCredentialRotated,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeviceRevocationReceipt {
    pub(crate) previous: u64,
    pub(crate) current: u64,
}

impl DeviceRevocationReceipt {
    pub const fn previous_epoch(&self) -> u64 {
        self.previous
    }
    pub const fn current_epoch(&self) -> u64 {
        self.current
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialRevocationReceipt {
    pub(crate) revoked_grants: usize,
}
impl CredentialRevocationReceipt {
    pub const fn revoked_grants(&self) -> usize {
        self.revoked_grants
    }
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DeviceRecord {
    pub owner: OpaqueOwnerRef,
    pub key_thumbprint: String,
    pub epoch: u64,
    pub pairwise_subject_ref: String,
    pub issuer: String,
    pub service_id: crate::ServiceId,
    pub posture_state: String,
    pub posture_revision: u64,
    pub subject_revocation_epoch: u64,
    pub service_revocation_epoch: u64,
    pub session_revocation_epoch: u64,
    pub key_id: String,
    pub enrolled_at_ms: u64,
    pub last_seen_at_ms: u64,
    pub revoked: bool,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TransferRecord {
    pub id: TransferId,
    pub owner: OpaqueOwnerRef,
    pub credential_id: CredentialId,
    pub source_device: DeviceId,
    pub target_device: DeviceId,
    pub source_grant: GrantId,
    pub target_grant: GrantId,
    pub mechanism: TransferMechanism,
    pub target_nonce: String,
    pub identity_nonce: String,
    pub management_source_binding: Option<crate::transfer::ManagementDeviceBinding>,
    pub management_target_binding: Option<crate::transfer::ManagementDeviceBinding>,
    pub state: TransferState,
    pub provider_revision: Option<u64>,
    pub provider_receipt_id: Option<String>,
    pub provider_receipt_signature: Option<String>,
    pub provider_attempts: usize,
    pub unknown_outcome: Option<ProviderOperationOutcome>,
}

#[derive(Clone, Debug)]
pub struct DurableSnapshot {
    pub(crate) version: u64,
    pub(crate) clock_floor_ms: u64,
    pub(crate) next_id: u64,
    pub(crate) accounts: BTreeMap<OpaqueOwnerRef, AccountState>,
    pub(crate) devices: BTreeMap<(OpaqueOwnerRef, DeviceId), DeviceRecord>,
    pub(crate) sessions: BTreeMap<(OpaqueOwnerRef, String), SessionRecord>,
    pub(crate) credentials: BTreeMap<CredentialId, CredentialMetadata>,
    pub(crate) grants: BTreeMap<GrantId, DeviceGrant>,
    pub(crate) transfers: BTreeMap<TransferId, TransferRecord>,
    pub(crate) used_nonces: BTreeSet<String>,
    pub(crate) used_provider_receipts: BTreeSet<String>,
    pub(crate) custody_secret_deletion_requests: usize,
}

impl DurableSnapshot {
    #[must_use]
    pub fn empty(clock_floor_ms: u64) -> Self {
        Self {
            version: 0,
            clock_floor_ms,
            next_id: 1,
            accounts: BTreeMap::new(),
            devices: BTreeMap::new(),
            sessions: BTreeMap::new(),
            credentials: BTreeMap::new(),
            grants: BTreeMap::new(),
            transfers: BTreeMap::new(),
            used_nonces: BTreeSet::new(),
            used_provider_receipts: BTreeSet::new(),
            custody_secret_deletion_requests: 0,
        }
    }

    pub(crate) fn next_sequence(&mut self) -> u64 {
        let value = self.next_id;
        self.next_id = self.next_id.saturating_add(1);
        value
    }
}
