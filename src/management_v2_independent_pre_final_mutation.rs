use crowsi_credential_authority_contracts::{
    ActorRequirementV2, EndpointIndependentRevocationPreFinalRequestV1, ManagementOperationState,
    ManagementProjectionBodyV2, RequiredActorRole,
};

use crate::{
    HostError, management_v2_handler::ManagementV2Handler,
    management_v2_identity::VerifiedManagementIdentity, management_v2_journal_update::EvidenceUse,
    management_v2_record::ManagementRecordV2,
};

pub(super) fn apply(
    handler: &ManagementV2Handler,
    request: &EndpointIndependentRevocationPreFinalRequestV1,
    verified: &VerifiedManagementIdentity<'_>,
    fresh: &ihat_identity_assertion_contracts::FreshUvV1,
    record: &mut ManagementRecordV2,
    now: u64,
) -> Result<Vec<u8>, HostError> {
    record.authority_config_generation = crate::management_v2_config_generation::record(
        &handler.journal,
        record,
        &[
            &request.finish_uv_exchange,
            &request.accepted_identity_exchange,
            &request.revocation_ceremony.approval,
        ],
    )?;
    let acceptance = crate::management_v2_independent_finalization::preauthorize(
        record,
        request,
        &handler.core.config,
        now,
        0,
    )?;
    record.approved_by_device_ref = Some(verified.identity.assertion.device_id.clone());
    record.independent_identity_exchange = Some(request.accepted_identity_exchange.clone());
    record.independent_finish_uv_exchange = Some(request.finish_uv_exchange.clone());
    record.operation.state = ManagementOperationState::AwaitingRevocationFinal;
    record.operation.state_revision = acceptance.pre_final_state_revision;
    record.operation.actor = no_actor();
    record.operation.webauthn_options = None;
    record.operation.reconcile_digest = Some(acceptance.reconcile_digest.clone());
    record.independent_revocation_finalization = Some(Box::new(acceptance));
    let binding = format!("sha256:{}", acceptance_digest(request)?);
    let identity_digest =
        crate::management_v2_journal_policy::exchange_digest(&request.accepted_identity_exchange)?;
    let finish_digest =
        crate::management_v2_journal_policy::exchange_digest(&request.finish_uv_exchange)?;
    let approval = request
        .revocation_ceremony
        .approval
        .request
        .evidence
        .iter()
        .find_map(|item| match item {
            ihat_identity_assertion_contracts::AuthorityEvidence::Signed(item) => Some(item),
            ihat_identity_assertion_contracts::AuthorityEvidence::FreshUv(_) => None,
        })
        .ok_or(HostError::EvidenceInvalid)?;
    let uses = uses(
        request,
        verified,
        fresh,
        &identity_digest,
        &finish_digest,
        approval,
        &binding,
    );
    let expected = request.expected_state_revision;
    let (revision, stored) =
        handler
            .journal
            .accept_independent_pre_final(expected, record.clone(), &uses, now)?;
    let identity = verified.identity;
    crate::management_v2_projection::signed(
        &handler.core.config,
        &request.approve_revocation_request,
        identity,
        &stored.owner_ref,
        revision,
        ManagementProjectionBodyV2::Operation {
            operation: stored.operation,
        },
        now,
    )
}

fn acceptance_digest(
    request: &EndpointIndependentRevocationPreFinalRequestV1,
) -> Result<String, HostError> {
    crowsi_credential_authority_contracts::endpoint_independent_revocation_pre_final_request_digest(
        request,
    )
    .map_err(|_| HostError::RequestInvalid)
}

fn no_actor() -> ActorRequirementV2 {
    ActorRequirementV2 {
        role: RequiredActorRole::ReconcileOnly,
        required_actor_device_ref: None,
        required_approval_authority_ref: None,
        excluded_actor_device_refs: Vec::new(),
    }
}

include!("management_v2_independent_pre_final_uses.rs");
