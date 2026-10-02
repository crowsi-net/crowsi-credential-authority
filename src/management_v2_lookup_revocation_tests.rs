use crowsi_credential_authority_contracts::{
    EndpointPreparedLookupPhaseV1 as Phase, RevocationSourceCeremonyV1, SignedAuthorityExchangeV1,
};
use ihat_identity_assertion_contracts::{AuthorityResult, ResponseOutcome};

#[test]
fn approval_exposes_only_the_durable_source_begin() {
    let mut record =
        crate::management_v2_journal_fixture::revocation("owner-a", "device-a", &"ab".repeat(32));
    let begin = revocation_begin();
    record.source_revocation_ceremony = Some(RevocationSourceCeremonyV1 {
        begin: begin.clone(),
        final_revoke: None,
    });

    assert_eq!(
        revocation_begin_exchange(Phase::Approval, &record).expect("approval"),
        Some((
            begin,
            crate::management_v2_journal_test_environment::NOW + 20
        ))
    );
    for phase in [Phase::Target, Phase::Cancel, Phase::Reconcile] {
        assert_eq!(
            revocation_begin_exchange(phase, &record).expect("non-approval"),
            None
        );
    }
}

fn revocation_begin() -> SignedAuthorityExchangeV1 {
    let mut value = crate::management_v2_journal_test_environment::identity_exchange("device-a");
    value.response.outcome = ResponseOutcome::Committed {
        result: AuthorityResult::RevocationBegun(
            ihat_identity_assertion_contracts::RevocationCeremonyMetadata {
                attempt_id: "attempt-a".into(),
                finalize_command_id: "operation-a".into(),
                target_digest: "11".repeat(32),
                expires_at_epoch_s: crate::management_v2_journal_test_environment::NOW + 20,
                independent_approval_required: true,
                state: ihat_identity_assertion_contracts::RevocationCeremonyStateDto::AwaitingIndependentApproval,
                approval_nonce: Some("approval-a".into()),
            },
        ),
    };
    value
}

#[test]
fn approval_rejects_a_record_without_an_accepted_source_begin() {
    let record =
        crate::management_v2_journal_fixture::revocation("owner-a", "device-a", &"cd".repeat(32));
    assert_eq!(
        revocation_begin_exchange(Phase::Approval, &record),
        Err(crate::HostError::StateInvalid)
    );
}

#[test]
fn awaiting_final_cancel_exposes_exactly_one_pre_final_acceptance_digest() {
    use crowsi_credential_authority_contracts::ManagementOperationState as State;

    let self_digest = "11".repeat(32);
    let independent_digest = "22".repeat(32);
    assert_eq!(
        required_pre_final_digest(
            Phase::Cancel,
            State::AwaitingRevocationFinal,
            Some(&self_digest),
            None,
        )
        .expect("self acceptance"),
        Some(self_digest)
    );
    assert_eq!(
        required_pre_final_digest(
            Phase::Cancel,
            State::AwaitingRevocationFinal,
            None,
            Some(&independent_digest),
        )
        .expect("independent acceptance"),
        Some(independent_digest)
    );
    for digests in [(None, None), (Some("a"), Some("b"))] {
        assert_eq!(
            required_pre_final_digest(
                Phase::Cancel,
                State::AwaitingRevocationFinal,
                digests.0,
                digests.1,
            ),
            Err(crate::HostError::StateInvalid)
        );
    }
    assert_eq!(
        required_pre_final_digest(Phase::Approval, State::AwaitingRevocationFinal, None, None)
            .expect("non-Cancel phase"),
        None
    );
}
