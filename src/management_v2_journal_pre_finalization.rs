use crowsi_credential_authority_contracts::{
    EndpointManagementEnvelopeV2, EndpointManagementEvidenceV2, ManagementOperationState,
};

use crate::{
    HostError, management_v2_journal::ManagementJournalV2, management_v2_record::ManagementRecordV2,
};

impl ManagementJournalV2 {
    pub(crate) fn revocation_pre_final_view(
        &self,
        envelope: &EndpointManagementEnvelopeV2,
        peer: &str,
        now: u64,
    ) -> Result<Option<(u64, ManagementRecordV2)>, HostError> {
        let EndpointManagementEvidenceV2::SourceApprove { prepared, .. } = &envelope.evidence
        else {
            return Ok(None);
        };
        let owner = &prepared.opaque_owner_ref;
        let envelope_digest = crate::management_v2_journal_policy::envelope_digest(envelope)?;
        self.locked(owner, || {
            let ledger =
                crate::management_v2_journal_io::read(&self.root, &self.anchor_root, owner)?;
            let Some(record) = ledger
                .records
                .iter()
                .find(|item| item.operation.operation_id == prepared.operation_id)
            else {
                return Ok(None);
            };
            if exact(record, envelope, peer, &envelope_digest, now) {
                Ok(Some((ledger.revision, record.clone())))
            } else {
                Ok(None)
            }
        })
    }
}

fn exact(
    value: &ManagementRecordV2,
    envelope: &EndpointManagementEnvelopeV2,
    peer: &str,
    envelope_digest: &str,
    now: u64,
) -> bool {
    let EndpointManagementEvidenceV2::SourceApprove {
        identity_exchange,
        prepared,
        finish_uv_exchange,
        revocation_ceremony: Some(ceremony),
    } = &envelope.evidence
    else {
        return false;
    };
    let Some(acceptance) = &value.revocation_finalization else {
        return false;
    };
    value.operation.state == ManagementOperationState::AwaitingRevocationFinal
        && value.operation.state_revision == acceptance.pre_final_state_revision
        && value.operation.reconcile_digest.as_deref() == Some(&acceptance.reconcile_digest)
        && value.owner_ref == prepared.opaque_owner_ref
        && value.prepared == *prepared
        && value.prepared.source_device_ref == peer
        && value.source_approval_acceptance_sha256.as_deref() == Some(envelope_digest)
        && envelope_digest.strip_prefix("sha256:")
            == Some(&acceptance.source_approve_request_sha256)
        && acceptance.source_approve_request == envelope.browser_request
        && value.source_approval_identity_exchange.as_ref() == Some(identity_exchange)
        && acceptance.accepted_identity_exchange == *identity_exchange
        && value.source_finish_uv_exchange.as_ref() == Some(finish_uv_exchange)
        && value.source_revocation_ceremony.as_ref() == Some(ceremony)
        && acceptance.begin_exchange == ceremony.begin
        && ceremony.final_revoke.is_none()
        && acceptance.finalize_request_sha256.is_none()
        && acceptance.final_revoke_exchange.is_none()
        && begin_live(&acceptance.begin_exchange, now)
}

fn begin_live(
    value: &crowsi_credential_authority_contracts::SignedAuthorityExchangeV1,
    now: u64,
) -> bool {
    matches!(
        &value.response.outcome,
        ihat_identity_assertion_contracts::ResponseOutcome::Committed {
            result: ihat_identity_assertion_contracts::AuthorityResult::RevocationBegun(result),
        } if now < result.expires_at_epoch_s
    )
}
