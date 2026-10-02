fn accepted_signed(
    value: &SignedAuthorityExchangeV1,
    role: VerificationRole,
) -> Result<(), HostError> {
    signed(value, role).map(|_| ())
}

fn signed(
    value: &SignedAuthorityExchangeV1,
    role: VerificationRole,
) -> Result<&ihat_identity_assertion_contracts::SignedEvidenceV1, HostError> {
    let proof = value
        .request
        .evidence
        .iter()
        .find_map(|item| match item {
            AuthorityEvidence::Signed(item) if item.role == role => Some(item),
            _ => None,
        })
        .ok_or(HostError::EvidenceInvalid)?;
    let binding = command_digest(&value.request).map_err(|_| HostError::EvidenceInvalid)?;
    (proof.binding_sha256 == binding)
        .then_some(proof)
        .ok_or(HostError::EvidenceInvalid)
}

fn begin_command(value: &SignedAuthorityExchangeV1) -> Result<&'static str, HostError> {
    match &value.request.command {
        ihat_identity_assertion_contracts::AuthorityCommand::BeginDeviceRevocation(_) => {
            Ok("begin_device_revocation")
        }
        ihat_identity_assertion_contracts::AuthorityCommand::BeginSessionRevocation(_) => {
            Ok("begin_session_revocation")
        }
        _ => Err(HostError::EvidenceInvalid),
    }
}

fn final_command(value: &SignedAuthorityExchangeV1) -> Result<&'static str, HostError> {
    match &value.request.command {
        ihat_identity_assertion_contracts::AuthorityCommand::RevokeDeviceByRef(_) => {
            Ok("revoke_device_by_ref")
        }
        ihat_identity_assertion_contracts::AuthorityCommand::RevokeSessionByRef(_) => {
            Ok("revoke_session_by_ref")
        }
        _ => Err(HostError::EvidenceInvalid),
    }
}
