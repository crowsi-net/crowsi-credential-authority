use crowsi_credential_authority_contracts::{
    EndpointManagementEnvelopeV2, EndpointPreparedOperationV2, ManagementCommandV2,
    ManagementOperationState, ManagementProjectionBodyV2, SignedAuthorityExchangeV1,
    SignedTargetDeviceProofV2,
};

use crate::{
    HostError, management_v2_handler::ManagementV2Handler,
    management_v2_identity::VerifiedManagementIdentity, management_v2_journal_update::EvidenceUse,
};

impl ManagementV2Handler {
    pub(crate) fn target_approve(
        &self,
        envelope: &EndpointManagementEnvelopeV2,
        verified: &VerifiedManagementIdentity<'_>,
        prepared: &EndpointPreparedOperationV2,
        finish: &SignedAuthorityExchangeV1,
        proof: &SignedTargetDeviceProofV2,
        now: u64,
    ) -> Result<Vec<u8>, HostError> {
        let (id, revision) = command(&envelope.browser_request.command)?;
        let mut record = self.current(
            verified,
            prepared,
            id,
            revision,
            ManagementOperationState::AwaitingTargetUv,
            now,
        )?;
        if record.operation.actor.required_actor_device_ref.as_deref()
            != Some(&verified.identity.assertion.device_id)
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
        record.authority_config_generation = crate::management_v2_config_generation::record(
            &self.journal,
            &record,
            &[finish, verified.identity_exchange],
        )?;
        crate::management_v2_evidence::target(
            &self.core.config,
            verified.identity,
            verified.owner,
            prepared,
            &fresh,
            proof,
            now,
        )?;
        record.target_identity_exchange = Some(verified.identity_exchange.clone());
        record.target_finish_uv_exchange = Some(finish.clone());
        record.target_proof = Some(proof.clone());
        crate::management_v2_transfer_state::arm(&mut record)?;
        record.operation.state_revision = next(revision)?;
        record.operation.webauthn_options = None;
        let phase_binding = crate::management_v2_journal_policy::envelope_digest(envelope)?;
        let finish_digest = crate::management_v2_journal_policy::exchange_digest(finish)?;
        let identity_digest =
            crate::management_v2_journal_policy::exchange_digest(verified.identity_exchange)?;
        let uses = [
            EvidenceUse {
                kind: "fresh_uv_proof",
                id: &fresh.proof_id,
                binding: &phase_binding,
                expires_at_epoch_s: fresh.expires_at_epoch_s,
            },
            EvidenceUse {
                kind: "identity_authority_exchange",
                id: &identity_digest,
                binding: &phase_binding,
                expires_at_epoch_s: verified.identity_exchange.response.expires_at_epoch_s,
            },
            EvidenceUse {
                kind: "identity_assertion_nonce",
                id: &verified.identity.assertion.nonce,
                binding: &phase_binding,
                expires_at_epoch_s: verified.identity.assertion.expires_at_epoch_s,
            },
            EvidenceUse {
                kind: "current_status_nonce",
                id: &verified.identity.current_status.nonce,
                binding: &phase_binding,
                expires_at_epoch_s: verified.identity.current_status.expires_at_epoch_s,
            },
            EvidenceUse {
                kind: "fresh_uv_finish_exchange",
                id: &finish_digest,
                binding: &phase_binding,
                expires_at_epoch_s: finish.response.expires_at_epoch_s,
            },
            EvidenceUse {
                kind: "target_device_proof_nonce",
                id: &proof.binding.nonce,
                binding: &phase_binding,
                expires_at_epoch_s: proof.binding.expires_at_epoch_s,
            },
        ];
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
        let _ = self.execute_transfer(stored, now)?;
        Ok(response)
    }
}

include!("management_v2_phase_target_command.rs");
