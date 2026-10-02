use crowsi_credential_authority_contracts::{
    EndpointPreparedOperationV2, ManagementIntentV2, ManagementSnapshotV2,
};

use crate::management_v2_record::{RevocationRotationV2, RevocationSagaV2};

pub(crate) fn plan(
    prepared: &EndpointPreparedOperationV2,
    snapshot: &ManagementSnapshotV2,
) -> Option<RevocationSagaV2> {
    let ManagementIntentV2::DeviceRevocation {
        service_id,
        target_device_ref,
        ..
    } = &prepared.intent
    else {
        return matches!(
            prepared.intent,
            ManagementIntentV2::SessionRevocation { .. }
        )
        .then(|| RevocationSagaV2 {
            started: false,
            local_revocation_applied: false,
            rotations: Vec::new(),
        });
    };
    let rotations = snapshot
        .credentials
        .iter()
        .filter(|item| {
            item.provider == *service_id
                && item.status
                    == crowsi_credential_authority_contracts::ManagementLifecycleV2::Active
                && item.assigned_device_refs.contains(target_device_ref)
        })
        .map(|credential| rotation(prepared, credential))
        .collect();
    Some(RevocationSagaV2 {
        started: false,
        local_revocation_applied: false,
        rotations,
    })
}

fn rotation(
    prepared: &EndpointPreparedOperationV2,
    credential: &crowsi_credential_authority_contracts::ManagementCredentialV2,
) -> RevocationRotationV2 {
    let (request, operation, nonce) =
        attempt(&prepared.operation_id, &credential.credential_ref, 1);
    RevocationRotationV2 {
        credential_ref: credential.credential_ref.clone(),
        target_device_ref: String::new(),
        target_binding: None,
        provider_request_id: request,
        provider_operation_ref: operation,
        provider_nonce: nonce,
        attempt_number: 1,
        reconcile_sequence: 0,
        provider_reconcile_request_id: None,
        attempted: false,
        provider_acceptance: None,
        prior_acceptances: Vec::new(),
        prior_acceptance_count: 0,
        prior_acceptance_digest_sha256: crate::management_v2_provider_progress::empty_digest(
            "rotation",
        ),
        authority_applied: false,
    }
}

pub(crate) fn reconcile_request(
    operation_id: &str,
    credential: &str,
    attempt_number: u64,
    sequence: u64,
) -> String {
    let digest = crate::host_crypto::digest(
        format!(
            "CROWSI-REVOCATION-RECONCILE-V1\0{operation_id}\0{credential}\0{attempt_number}\0{sequence}"
        )
        .as_bytes(),
    );
    format!("request-{}", digest.trim_start_matches("sha256:"))
}

pub(crate) fn attempt(
    operation_id: &str,
    credential: &str,
    number: u64,
) -> (String, String, String) {
    let digest = crate::host_crypto::digest(
        format!("CROWSI-REVOCATION-ROTATION-V3\0{operation_id}\0{credential}\0{number}").as_bytes(),
    );
    let bare = digest.trim_start_matches("sha256:");
    (
        format!("request-{bare}"),
        format!("provider-{bare}"),
        format!("rotation-{bare}"),
    )
}
