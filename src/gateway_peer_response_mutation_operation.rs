fn operation_prepared(
    operation: &crowsi_credential_authority_contracts::ManagementOperationV2,
    prepared: &crowsi_credential_authority_contracts::EndpointPreparedOperationV2,
) -> bool {
    use crowsi_credential_authority_contracts::{
        ManagementIntentV2 as I, ManagementOperationKind as K, ManagementOperationScopeV2 as S,
    };
    operation.operation_id == prepared.operation_id
        && operation.source_device_ref == prepared.source_device_ref
        && operation.intent_digest_sha256 == prepared.origin_command_digest_sha256
        && operation.created_at_epoch_s >= prepared.issued_at_epoch_s
        && operation.expires_at_epoch_s == prepared.expires_at_epoch_s
        && match (&prepared.intent, &operation.kind, &operation.scope) {
            (
                I::DeviceTransfer {
                    target_device_ref,
                    credential_refs,
                    ..
                },
                K::DeviceTransfer,
                S::DeviceTransfer {
                    target_device_ref: target,
                    credential_refs: credentials,
                    ..
                },
            ) => target == target_device_ref && credentials == credential_refs,
            (
                I::DeviceRevocation {
                    target_device_ref,
                    expected_device_revocation_epoch,
                    ..
                },
                K::DeviceRevocation,
                S::DeviceRevocation {
                    target_device_ref: target,
                    expected_device_revocation_epoch: epoch,
                    revokes_session_refs,
                    ..
                },
            ) => {
                target == target_device_ref
                    && epoch == expected_device_revocation_epoch
                    && prepared
                        .revocation
                        .as_ref()
                        .and_then(|value| value.expected_revoked_session_count)
                        == Some(revokes_session_refs.len() as u64)
            }
            (
                I::SessionRevocation {
                    target_session_ref,
                    expected_session_revocation_epoch,
                    ..
                },
                K::SessionRevocation,
                S::SessionRevocation {
                    target_session_ref: target,
                    expected_session_revocation_epoch: epoch,
                    device_ref,
                },
            ) => {
                target == target_session_ref
                    && epoch == expected_session_revocation_epoch
                    && prepared
                        .revocation
                        .as_ref()
                        .is_some_and(|value| value.target_device_ref == *device_ref)
            }
            _ => false,
        }
}
