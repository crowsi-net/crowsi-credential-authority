use crowsi_credential_authority_contracts::SignedAuthorityExchangeV1;
use ihat_identity_assertion_contracts::{
    AuthorityCommand, AuthorityEvidence, VerificationRole, command_digest,
};

use crate::{HostError, host_config::VerifiedHostConfig};

pub(crate) fn source_ceremony(
    config: &VerifiedHostConfig,
    current_identity: &SignedAuthorityExchangeV1,
    verified_sender_key_id: &str,
    value: &crowsi_credential_authority_contracts::RevocationSourceCeremonyV1,
    now: u64,
) -> Result<(), HostError> {
    source_sender(current_identity, verified_sender_key_id, &value.begin)?;
    let begin = match &value.begin.request.command {
        ihat_identity_assertion_contracts::AuthorityCommand::BeginDeviceRevocation(_) => {
            "begin_device_revocation"
        }
        ihat_identity_assertion_contracts::AuthorityCommand::BeginSessionRevocation(_) => {
            "begin_session_revocation"
        }
        _ => return Err(HostError::EvidenceInvalid),
    };
    crate::management_v2_evidence::verify_exchange(config, &value.begin, begin, now)?;
    if let Some(final_revoke) = &value.final_revoke {
        crate::management_v2_evidence::verify_exchange(
            config,
            final_revoke,
            final_command(final_revoke)?,
            now,
        )?;
    }
    Ok(())
}

pub(crate) fn independent_pre_final_ceremony(
    config: &VerifiedHostConfig,
    value: &crowsi_credential_authority_contracts::RevocationIndependentPreFinalCeremonyV1,
    now: u64,
) -> Result<(), HostError> {
    crate::management_v2_evidence::verify_exchange(
        config,
        &value.begin,
        begin_command(&value.begin)?,
        now,
    )?;
    let role = match value.approval.request.evidence.as_slice() {
        [AuthorityEvidence::Signed(item)] => item.role,
        _ => return Err(HostError::EvidenceInvalid),
    };
    if !matches!(
        role,
        VerificationRole::RevocationAuthority | VerificationRole::RecoveryApproval
    ) {
        return Err(HostError::EvidenceInvalid);
    }
    accepted_signed(&value.approval, role)?;
    crate::management_v2_evidence::verify_exchange(
        config,
        &value.approval,
        "approve_revocation",
        now,
    )
}

pub(crate) fn source_sender(
    current_identity: &SignedAuthorityExchangeV1,
    verified_sender_key_id: &str,
    value: &SignedAuthorityExchangeV1,
) -> Result<(), HostError> {
    let current = signed(current_identity, VerificationRole::SessionSender)?;
    let sender = signed(value, VerificationRole::SessionSender)?;
    let AuthorityCommand::IssueCurrentDeviceIdentityEvidence(current_command) =
        &current_identity.request.command
    else {
        return Err(HostError::EvidenceInvalid);
    };
    let identity =
        crowsi_credential_authority_contracts::identity_evidence_from_exchange(current_identity)
            .map_err(|_| HostError::EvidenceInvalid)?;
    let (service, pairwise, device, session, command_proof) = match &value.request.command {
        AuthorityCommand::BeginDeviceRevocation(command) => (
            &command.service_id,
            &command.pairwise_subject,
            &command.source_device_id,
            &command.source_session_ref,
            &command.sender_proof_id,
        ),
        AuthorityCommand::BeginSessionRevocation(command) => (
            &command.service_id,
            &command.pairwise_subject,
            &command.source_device_id,
            &command.source_session_ref,
            &command.sender_proof_id,
        ),
        _ => return Err(HostError::EvidenceInvalid),
    };
    let assertion = &identity.assertion;
    (current.proof_id == current_command.session_sender_proof_id
        && sender.proof_id == *command_proof
        && sender.proof_id != current.proof_id
        && sender.key_id == current.key_id
        && sender.key_id == verified_sender_key_id
        && service == &assertion.service_id
        && pairwise == &assertion.pairwise_subject
        && device == &assertion.device_id
        && session == &assertion.session_ref)
        .then_some(())
        .ok_or(HostError::EvidenceInvalid)
}

include!("management_v2_evidence_ceremony_helpers.rs");
