use crowsi_credential_authority_contracts::{
    EndpointManagementEnvelopeV2, EndpointPreparedOperationV2, ManagementCommandV2,
    ManagementOperationState, ManagementProjectionBodyV2, RevocationSourceCeremonyV1,
    SignedAuthorityExchangeV1,
};
use ihat_identity_assertion_contracts::AuthorityEvidence;

use crate::{
    HostError, management_v2_handler::ManagementV2Handler,
    management_v2_identity::VerifiedManagementIdentity, management_v2_journal_update::EvidenceUse,
};

impl ManagementV2Handler {
    pub(crate) fn source_approve(
        &self,
        envelope: &EndpointManagementEnvelopeV2,
        verified: &VerifiedManagementIdentity<'_>,
        prepared: &EndpointPreparedOperationV2,
        finish: &SignedAuthorityExchangeV1,
        ceremony: Option<&RevocationSourceCeremonyV1>,
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
            ManagementOperationState::AwaitingSourceUv,
            now,
        )?;
        let approval = crate::management_v2_evidence::approval(
            &self.core.config,
            verified.owner,
            &record.source_identity_exchange,
            &record.source_options_exchange,
            finish,
            verified.identity_exchange,
            prepared,
            &envelope.browser_request.command,
            now,
        )?;
        let fresh = approval.fresh_uv;
        let mut generation_exchanges = vec![finish, verified.identity_exchange];
        if let Some(value) = ceremony {
            generation_exchanges.push(&value.begin);
            if let Some(final_revoke) = &value.final_revoke {
                generation_exchanges.push(final_revoke);
            }
        }
        record.authority_config_generation = crate::management_v2_config_generation::record(
            &self.journal,
            &record,
            &generation_exchanges,
        )?;
        let phase_binding = crate::management_v2_journal_policy::envelope_digest(envelope)?;
        let finish_digest = crate::management_v2_journal_policy::exchange_digest(finish)?;
        let identity_digest =
            crate::management_v2_journal_policy::exchange_digest(verified.identity_exchange)?;
        let mut uses = source_uses(
            verified,
            &fresh.proof_id,
            fresh.expires_at_epoch_s,
            &finish_digest,
            finish.response.expires_at_epoch_s,
            &identity_digest,
            &phase_binding,
        );
        if let Some(value) = ceremony {
            crate::management_v2_evidence::source_ceremony(
                &self.core.config,
                verified.identity_exchange,
                &approval.session_sender_key_id,
                value,
                now,
            )?;
            let sender = value
                .begin
                .request
                .evidence
                .iter()
                .find_map(|item| match item {
                    AuthorityEvidence::Signed(item) => Some(item),
                    AuthorityEvidence::FreshUv(_) => None,
                })
                .ok_or(HostError::EvidenceInvalid)?;
            uses.push(EvidenceUse {
                kind: "session_sender_proof",
                id: &sender.proof_id,
                binding: &phase_binding,
                expires_at_epoch_s: sender.expires_at_epoch_s,
            });
            record.source_revocation_ceremony = Some(value.clone());
        }
        record.source_approval_identity_exchange = Some(verified.identity_exchange.clone());
        record.source_approval_acceptance_sha256 = Some(phase_binding.clone());
        record.source_finish_uv_exchange = Some(finish.clone());
        let (ledger_revision, _) = self.journal.view(&verified.owner.opaque_owner_ref)?;
        let accepted_ledger_revision = crate::management_v2_journal_policy::next(ledger_revision)?;
        if record
            .prepared
            .revocation
            .as_ref()
            .is_some_and(|item| item.target_device_ref == record.prepared.source_device_ref)
        {
            record.revocation_finalization = Some(Box::new(
                crate::management_v2_revocation_finalization::preauthorize(
                    &record,
                    &envelope.browser_request,
                    &self.core.config,
                    now,
                    accepted_ledger_revision,
                )?,
            ));
        }
        crate::management_v2_phase_state::source(&mut record)?;
        let receipt = crate::management_v2_receipt::projection(
            &self.core.config,
            envelope,
            verified,
            ManagementProjectionBodyV2::Operation {
                operation: record.operation.clone(),
            },
            accepted_ledger_revision,
            now,
            prepared.expires_at_epoch_s.saturating_add(300),
            false,
        )?;
        let (stored, response) = self
            .journal
            .replace_consuming_response(revision, record, &uses, receipt, now, None)?;
        let _ = stored;
        Ok(response)
    }
}

include!("management_v2_phase_source_command.rs");
include!("management_v2_phase_source_uses.rs");
