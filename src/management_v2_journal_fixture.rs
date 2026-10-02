pub(crate) use crate::management_v2_journal_test_environment::{Fixture, NOW};
use crate::management_v2_journal_test_environment::{identity_exchange, sref};
use crate::management_v2_record::ManagementRecordV2;
use crowsi_credential_authority_contracts::{
    ActorRequirementV2, EndpointPreparedOperationV2, ManagementIntentV2, ManagementOperationKind,
    ManagementOperationScopeV2, ManagementOperationState, ManagementOperationV2, RequiredActorRole,
    RevocationRequirementsV2, endpoint_operation_id,
};

pub(crate) fn record(owner: &str, source: &str, nonce: &str) -> ManagementRecordV2 {
    value(owner, source, nonce, false)
}

pub(crate) fn revocation(owner: &str, source: &str, nonce: &str) -> ManagementRecordV2 {
    value(owner, source, nonce, true)
}

fn value(owner: &str, source: &str, nonce: &str, revoke: bool) -> ManagementRecordV2 {
    let intent = if revoke {
        ManagementIntentV2::DeviceRevocation {
            service_id: "service-a".into(),
            target_device_ref: "device-b".into(),
            expected_device_revocation_epoch: 1,
            expected_snapshot_revision: 1,
            nonce: format!("intent-{nonce}"),
        }
    } else {
        ManagementIntentV2::DeviceTransfer {
            service_id: "service-a".into(),
            target_device_ref: "device-b".into(),
            credential_refs: vec![format!("credential-{nonce}")],
            expected_snapshot_revision: 1,
            nonce: format!("intent-{nonce}"),
        }
    };
    let mut prepared = EndpointPreparedOperationV2 {
        operation_id: String::new(),
        origin_command_digest_sha256: "aa".repeat(32),
        source_device_ref: source.into(),
        source_session_ref: sref('a'),
        pairwise_subject: format!("psu_{owner}"),
        opaque_owner_ref: owner.into(),
        source_identity_nonce: format!("identity-{nonce}"),
        nonce: nonce.into(),
        issued_at_epoch_s: NOW - 1,
        expires_at_epoch_s: NOW + 300,
        intent,
        revocation: revoke.then(|| RevocationRequirementsV2 {
            target_device_ref: "device-b".into(),
            required_approval_authority_ref: Some("recovery-c".into()),
            finalization_authority_id: "ihat-finalizer".into(),
            expected_revoked_session_count: Some(1),
        }),
    };
    prepared.operation_id = endpoint_operation_id(&prepared).expect("operation id");
    let operation = operation(&prepared, revoke);
    ManagementRecordV2 {
        operation,
        prepared,
        owner_ref: owner.into(),
        service_id: "service-a".into(),
        pairwise_subject: format!("psu_{owner}"),
        authority_config_generation: 1,
        source_identity_exchange: identity_exchange(source),
        source_options_exchange: identity_exchange(source),
        actor_options_identity_exchange: None,
        actor_options_exchange: None,
        source_finish_uv_exchange: None,
        source_approval_identity_exchange: None,
        source_approval_acceptance_sha256: None,
        target_finish_uv_exchange: None,
        independent_finish_uv_exchange: None,
        target_identity_exchange: None,
        independent_identity_exchange: None,
        target_proof: None,
        approved_by_device_ref: None,
        provider_transfer_id: None,
        grant_action: None,
        source_revocation_ceremony: None,
        revocation_finalization: None,
        independent_revocation_finalization: None,
        independent_revocation_ceremony: None,
        transfer_context: None,
        transfer_provider_acceptance: None,
        transfer_provider_history: Vec::new(),
        transfer_provider_history_count: 0,
        transfer_provider_history_digest_sha256:
            crate::management_v2_provider_progress::empty_digest("transfer"),
        revocation_saga: revoke.then(|| crate::management_v2_record::RevocationSagaV2 {
            started: false,
            local_revocation_applied: false,
            rotations: Vec::new(),
        }),
    }
}

fn operation(value: &EndpointPreparedOperationV2, revoke: bool) -> ManagementOperationV2 {
    ManagementOperationV2 {
        operation_id: value.operation_id.clone(),
        kind: if revoke {
            ManagementOperationKind::DeviceRevocation
        } else {
            ManagementOperationKind::DeviceTransfer
        },
        intent_digest_sha256: value.origin_command_digest_sha256.clone(),
        state: ManagementOperationState::AwaitingSourceUv,
        state_revision: 1,
        created_at_epoch_s: NOW,
        expires_at_epoch_s: value.expires_at_epoch_s,
        source_device_ref: value.source_device_ref.clone(),
        scope: if revoke {
            ManagementOperationScopeV2::DeviceRevocation {
                target_device_ref: "device-b".into(),
                expected_device_revocation_epoch: 1,
                revokes_session_refs: vec![sref('b')],
                rotates_credential_refs: Vec::new(),
                preserves_device_refs: vec!["device-c".into()],
            }
        } else {
            ManagementOperationScopeV2::DeviceTransfer {
                target_device_ref: "device-b".into(),
                credential_refs: vec!["credential-a".into()],
                expected_source_device_revocation_epoch: 1,
            }
        },
        actor: ActorRequirementV2 {
            role: RequiredActorRole::SourceDevice,
            required_actor_device_ref: Some(value.source_device_ref.clone()),
            required_approval_authority_ref: None,
            excluded_actor_device_refs: Vec::new(),
        },
        webauthn_options: None,
        reason: None,
        reconcile_digest: None,
    }
}
