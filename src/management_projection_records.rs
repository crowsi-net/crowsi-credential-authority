use serde_json::{Value, json};
use std::collections::BTreeSet;

use crate::{CredentialClass, DurableSnapshot, GrantState, OpaqueOwnerRef};

pub(crate) fn devices(
    snapshot: &DurableSnapshot,
    owner: &OpaqueOwnerRef,
    limit: usize,
) -> Vec<Value> {
    snapshot
        .devices
        .iter()
        .filter(|((value, _), _)| value == owner)
        .take(limit)
        .map(|((_, id), item)| {
            json!({"device_id":id.as_str(),
            "device_proof_key_ref":item.key_thumbprint,"device_revocation_epoch":item.epoch,
            "posture_revision":item.posture_revision,"posture_state":item.posture_state,
            "service_id":item.service_id.as_str(),"enrolled_at_epoch_ms":item.enrolled_at_ms,
            "last_seen_at_epoch_ms":item.last_seen_at_ms,"revoked":item.revoked})
        })
        .collect()
}

pub(crate) fn sessions(
    snapshot: &DurableSnapshot,
    owner: &OpaqueOwnerRef,
    limit: usize,
) -> Vec<Value> {
    snapshot
        .sessions
        .iter()
        .filter(|((value, _), _)| value == owner)
        .take(limit.saturating_mul(10))
        .map(|((_, id), item)| {
            json!({"session_ref":id,"device_id":item.device_id.as_str(),
            "session_revocation_epoch":item.epoch,"issued_at_epoch_ms":item.issued_at_ms,
            "expires_at_epoch_ms":item.expires_at_ms,"last_seen_at_epoch_ms":item.last_seen_at_ms,
            "revoked":item.revoked})
        })
        .collect()
}

pub(crate) fn credentials(
    snapshot: &DurableSnapshot,
    owner: &OpaqueOwnerRef,
    limit: usize,
) -> Vec<Value> {
    snapshot
        .credentials
        .values()
        .filter(|item| &item.owner == owner)
        .take(limit)
        .map(|item| {
            let grants = snapshot
                .grants
                .values()
                .filter(|grant| {
                    grant.owner == *owner
                        && grant.credential_id == item.id
                        && grant.state == GrantState::Active
                })
                .collect::<Vec<_>>();
            let assigned = grants
                .iter()
                .map(|grant| grant.target_device.as_str().to_owned())
                .collect::<BTreeSet<_>>();
            let scopes = grants
                .iter()
                .map(|grant| grant.action.as_str().to_owned())
                .collect::<BTreeSet<_>>();
            json!({"alias":item.alias,"class":class(item.class),"credential_id":item.id.as_str(),
            "provider_account_ref":item.provider_account.as_str(),"revision":item.revision,
            "revoked":item.revoked,"service_id":item.service.as_str(),
            "assigned_device_ids":assigned,"scopes":scopes,
            "created_at_epoch_ms":item.created_at_ms,"updated_at_epoch_ms":item.updated_at_ms})
        })
        .collect()
}

fn class(value: CredentialClass) -> &'static str {
    match value {
        CredentialClass::OperationOnly => "operation-only",
        CredentialClass::DelegatedToken => "delegated-token",
        CredentialClass::Certificate => "certificate",
    }
}
