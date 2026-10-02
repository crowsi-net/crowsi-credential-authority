pub(crate) fn identity_exchange(
    value: &EndpointManagementEvidenceV2,
) -> &SignedAuthorityExchangeV1 {
    match value {
        EndpointManagementEvidenceV2::Passive { identity_exchange }
        | EndpointManagementEvidenceV2::SourceOptions {
            identity_exchange, ..
        }
        | EndpointManagementEvidenceV2::SourceApprove {
            identity_exchange, ..
        }
        | EndpointManagementEvidenceV2::ActorOptions {
            identity_exchange, ..
        }
        | EndpointManagementEvidenceV2::TargetApprove {
            identity_exchange, ..
        }
        | EndpointManagementEvidenceV2::IndependentApprove {
            identity_exchange, ..
        }
        | EndpointManagementEvidenceV2::Cancel {
            identity_exchange, ..
        }
        | EndpointManagementEvidenceV2::Reconcile {
            identity_exchange, ..
        } => identity_exchange,
    }
}

pub(crate) fn prepared(
    value: &EndpointManagementEvidenceV2,
) -> Option<&crowsi_credential_authority_contracts::EndpointPreparedOperationV2> {
    match value {
        EndpointManagementEvidenceV2::Passive { .. } => None,
        EndpointManagementEvidenceV2::SourceOptions { prepared, .. }
        | EndpointManagementEvidenceV2::SourceApprove { prepared, .. }
        | EndpointManagementEvidenceV2::ActorOptions { prepared, .. }
        | EndpointManagementEvidenceV2::TargetApprove { prepared, .. }
        | EndpointManagementEvidenceV2::IndependentApprove { prepared, .. }
        | EndpointManagementEvidenceV2::Cancel { prepared, .. }
        | EndpointManagementEvidenceV2::Reconcile { prepared, .. } => Some(prepared),
    }
}
