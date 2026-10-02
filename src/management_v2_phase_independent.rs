use crowsi_credential_authority_contracts::{
    EndpointManagementEnvelopeV2, EndpointPreparedOperationV2, ManagementCommandV2,
    ManagementOperationState, ManagementProjectionBodyV2, RevocationIndependentCeremonyV1,
    SignedAuthorityExchangeV1,
};
use ihat_identity_assertion_contracts::AuthorityEvidence;

use crate::{
    HostError, management_v2_handler::ManagementV2Handler,
    management_v2_identity::VerifiedManagementIdentity, management_v2_journal_update::EvidenceUse,
};

impl ManagementV2Handler {
    pub(crate) fn independent_approve(
        &self,
        envelope: &EndpointManagementEnvelopeV2,
        verified: &VerifiedManagementIdentity<'_>,
        prepared: &EndpointPreparedOperationV2,
        finish: &SignedAuthorityExchangeV1,
        ceremony: &RevocationIndependentCeremonyV1,
        now: u64,
    ) -> Result<Vec<u8>, HostError> {
        crowsi_credential_authority_contracts::validate_revocation_ceremony_at(
            &envelope.evidence,
            now,
        )
        .map_err(|_| HostError::EvidenceInvalid)?;
        let (id, revision) = command(&envelope.browser_request.command)?;
        let mut record = self.current(
            verified,
            prepared,
            id,
            revision,
            ManagementOperationState::AwaitingApprovalUv,
            now,
        )?;
        if record.operation.actor.required_actor_device_ref.as_deref()
            != Some(&verified.identity.assertion.device_id)
            || record
                .source_revocation_ceremony
                .as_ref()
                .map(|item| &item.begin)
                != Some(&ceremony.begin)
        {
            return Err(HostError::EvidenceInvalid);
        }
        let begin = record
            .actor_options_exchange
            .as_ref()
            .ok_or(HostError::StateInvalid)?;
        let selected_identity = record
            .actor_options_identity_exchange
            .as_ref()
            .ok_or(HostError::StateInvalid)?;
        let approval = crate::management_v2_evidence::approval(
            &self.core.config,
            verified.owner,
            selected_identity,
            begin,
            finish,
            verified.identity_exchange,
            prepared,
            &envelope.browser_request.command,
            now,
        )?;
        let fresh = approval.fresh_uv;
        crate::management_v2_evidence::independent_ceremony(&self.core.config, ceremony, now)?;
        record.authority_config_generation = crate::management_v2_config_generation::record(
            &self.journal,
            &record,
            &[
                finish,
                verified.identity_exchange,
                &ceremony.approval,
                &ceremony.final_revoke,
            ],
        )?;
        let approval = ceremony
            .approval
            .request
            .evidence
            .iter()
            .find_map(|item| match item {
                AuthorityEvidence::Signed(item) => Some(item),
                AuthorityEvidence::FreshUv(_) => None,
            })
            .ok_or(HostError::EvidenceInvalid)?;
        record.approved_by_device_ref = Some(verified.identity.assertion.device_id.clone());
        record.independent_identity_exchange = Some(verified.identity_exchange.clone());
        record.independent_finish_uv_exchange = Some(finish.clone());
        record.independent_revocation_ceremony = Some(ceremony.clone());
        crate::management_v2_revocation::arm(&mut record)?;
        record.operation.state_revision = next(revision)?;
        record.operation.webauthn_options = None;
        let phase_binding = crate::management_v2_journal_policy::envelope_digest(envelope)?;
        let finish_digest = crate::management_v2_journal_policy::exchange_digest(finish)?;
        let identity_digest =
            crate::management_v2_journal_policy::exchange_digest(verified.identity_exchange)?;
        let uses = independent_uses(
            verified,
            &fresh.proof_id,
            fresh.expires_at_epoch_s,
            &finish_digest,
            finish.response.expires_at_epoch_s,
            &approval.proof_id,
            approval.expires_at_epoch_s,
            &identity_digest,
            &phase_binding,
        );
        let (ledger_revision, _) = self.journal.view(&verified.owner.opaque_owner_ref)?;
        let receipt = crate::management_v2_receipt::projection(
            &self.core.config,
            envelope,
            verified,
            ManagementProjectionBodyV2::Operation {
                operation: record.operation.clone(),
            },
            crate::management_v2_journal_policy::next(ledger_revision)?,
            now,
            prepared.expires_at_epoch_s.saturating_add(300),
            false,
        )?;
        let (stored, response) = self
            .journal
            .replace_consuming_response(revision, record, &uses, receipt, now, None)?;
        let _ = self.execute_revocation(stored, &[], now)?;
        Ok(response)
    }
}

fn command(value: &ManagementCommandV2) -> Result<(&str, u64), HostError> {
    let ManagementCommandV2::ApproveRevocation {
        operation_id,
        expected_state_revision,
        ..
    } = value
    else {
        return Err(HostError::RequestInvalid);
    };
    Ok((operation_id, *expected_state_revision))
}

fn next(value: u64) -> Result<u64, HostError> {
    value.checked_add(1).ok_or(HostError::StateInvalid)
}

include!("management_v2_phase_independent_uses.rs");
