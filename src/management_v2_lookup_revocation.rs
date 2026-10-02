fn revocation_begin_exchange(
    phase: crowsi_credential_authority_contracts::EndpointPreparedLookupPhaseV1,
    record: &crate::management_v2_record::ManagementRecordV2,
) -> Result<
    Option<(
        crowsi_credential_authority_contracts::SignedAuthorityExchangeV1,
        u64,
    )>,
    HostError,
> {
    use crowsi_credential_authority_contracts::EndpointPreparedLookupPhaseV1 as Phase;
    use ihat_identity_assertion_contracts::{AuthorityResult, ResponseOutcome};

    match phase {
        Phase::Approval => {
            let begin = record
                .source_revocation_ceremony
                .as_ref()
                .map(|ceremony| ceremony.begin.clone())
                .ok_or(HostError::StateInvalid)?;
            let ResponseOutcome::Committed {
                result: AuthorityResult::RevocationBegun(result),
            } = &begin.response.outcome
            else {
                return Err(HostError::StateInvalid);
            };
            Ok(Some((begin.clone(), result.expires_at_epoch_s)))
        }
        Phase::Target | Phase::Cancel | Phase::Reconcile => Ok(None),
    }
}

type RevocationLookupContext = (
    Option<(
        crowsi_credential_authority_contracts::SignedAuthorityExchangeV1,
        u64,
    )>,
    Option<String>,
    u64,
);

fn revocation_context(
    phase: crowsi_credential_authority_contracts::EndpointPreparedLookupPhaseV1,
    record: &crate::management_v2_record::ManagementRecordV2,
    expires: u64,
) -> Result<RevocationLookupContext, HostError> {
    let begin = revocation_begin_exchange(phase, record)?;
    let digest = pre_final_acceptance_request_sha256(phase, record)?;
    let expires = begin
        .as_ref()
        .map_or(expires, |(_, value)| expires.min(*value));
    Ok((begin, digest, expires))
}

fn pre_final_acceptance_request_sha256(
    phase: crowsi_credential_authority_contracts::EndpointPreparedLookupPhaseV1,
    record: &crate::management_v2_record::ManagementRecordV2,
) -> Result<Option<String>, HostError> {
    required_pre_final_digest(
        phase,
        record.operation.state,
        record
            .revocation_finalization
            .as_ref()
            .map(|value| value.source_approve_request_sha256.as_str()),
        record
            .independent_revocation_finalization
            .as_ref()
            .map(|value| value.pre_final_request_sha256.as_str()),
    )
}

fn required_pre_final_digest(
    phase: crowsi_credential_authority_contracts::EndpointPreparedLookupPhaseV1,
    state: crowsi_credential_authority_contracts::ManagementOperationState,
    self_digest: Option<&str>,
    independent_digest: Option<&str>,
) -> Result<Option<String>, HostError> {
    use crowsi_credential_authority_contracts::{
        EndpointPreparedLookupPhaseV1 as Phase, ManagementOperationState,
    };
    if phase != Phase::Cancel || state != ManagementOperationState::AwaitingRevocationFinal {
        return Ok(None);
    }
    match (self_digest, independent_digest) {
        (Some(value), None) | (None, Some(value)) => Ok(Some(value.to_owned())),
        _ => Err(HostError::StateInvalid),
    }
}

#[cfg(all(test, feature = "test-support"))]
mod tests {
    use super::*;

    include!("management_v2_lookup_revocation_tests.rs");
}
