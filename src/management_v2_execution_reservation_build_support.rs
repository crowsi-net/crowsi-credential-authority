fn empty_token(config: &VerifiedHostConfig, now: u64) -> SignedEvidenceV1 {
    SignedEvidenceV1 {
        schema: SIGNED_EVIDENCE_SCHEMA.into(),
        role: VerificationRole::RevocationExecutionReservation,
        proof_id: String::new(),
        key_id: config
            .document
            .revocation_execution_reservation_key_id
            .clone(),
        issued_at_epoch_s: now,
        expires_at_epoch_s: now.saturating_add(120),
        binding_sha256: String::new(),
        signature: String::new(),
    }
}

fn sign(
    config: &VerifiedHostConfig,
    value: &mut EndpointRevocationExecutionReservationV1,
) -> Result<(), HostError> {
    value.reservation_id =
        crowsi_credential_authority_contracts::endpoint_revocation_execution_reservation_id(value)
            .map_err(|_| HostError::ResponseInvalid)?;
    value.token.proof_id = value.reservation_id.clone();
    value.token.binding_sha256 = value.final_command_digest_sha256.clone();
    let canonical =
        canonical_signed_evidence(&value.token).map_err(|_| HostError::ResponseInvalid)?;
    value.token.signature = crate::host_crypto::sign(
        &config.revocation_execution_reservation_signing_key,
        &canonical,
    );
    let canonical =
        crowsi_credential_authority_contracts::canonical_endpoint_revocation_execution_reservation(
            value,
        )
        .map_err(|_| HostError::ResponseInvalid)?;
    value.signature =
        crate::host_crypto::sign(&config.management_projection_signing_key, &canonical);
    Ok(())
}

fn begin_target(
    request: &EndpointRevocationExecutionReserveRequestV1,
    now: u64,
) -> Result<String, HostError> {
    match &request.begin_exchange.response.outcome {
        ihat_identity_assertion_contracts::ResponseOutcome::Committed {
            result: ihat_identity_assertion_contracts::AuthorityResult::RevocationBegun(result),
        } if now < result.expires_at_epoch_s => Ok(result.target_digest.clone()),
        _ => Err(HostError::EvidenceInvalid),
    }
}
