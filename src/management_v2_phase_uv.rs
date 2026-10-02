use crowsi_credential_authority_contracts::{
    EndpointManagementEnvelopeV2, EndpointPreparedOperationV2, ManagementCommandV2,
    ManagementOperationState, ManagementProjectionBodyV2, RequiredActorRole,
    SignedAuthorityExchangeV1,
};

use crate::{
    HostError, management_v2_handler::ManagementV2Handler,
    management_v2_identity::VerifiedManagementIdentity, management_v2_journal_update::EvidenceUse,
};

impl ManagementV2Handler {
    pub(crate) fn actor_options(
        &self,
        envelope: &EndpointManagementEnvelopeV2,
        verified: &VerifiedManagementIdentity<'_>,
        prepared: &EndpointPreparedOperationV2,
        exchange: &SignedAuthorityExchangeV1,
        now: u64,
    ) -> Result<Vec<u8>, HostError> {
        let (id, revision) = command(&envelope.browser_request.command)?;
        let (expected, lookup_phase) = actor_phase(&envelope.browser_request.command)?;
        let mut record = self.journal.record(&verified.owner.opaque_owner_ref, id)?;
        if record.owner_ref != verified.owner.opaque_owner_ref
            || record.prepared != *prepared
            || record.service_id != verified.identity.assertion.service_id
            || record.pairwise_subject != verified.identity.assertion.pairwise_subject
            || record.operation.state_revision != revision
            || record.operation.state != expected
            || now >= record.operation.expires_at_epoch_s
            || !crate::management_v2_lookup_policy::allowed(
                lookup_phase,
                &record,
                &verified.identity.assertion.device_id,
                &verified.identity.assertion.session_ref,
            )
        {
            return Err(HostError::StateInvalid);
        }
        let options = crate::management_v2_evidence::options(&self.core.config, exchange, now)?;
        record.authority_config_generation = crate::management_v2_config_generation::record(
            &self.journal,
            &record,
            &[verified.identity_exchange, exchange],
        )?;
        match envelope.browser_request.command {
            ManagementCommandV2::TargetOptions { .. } => {
                let target = crate::management_v2_phase_state::transfer_target(prepared)?;
                record.operation.state = ManagementOperationState::AwaitingTargetUv;
                record.operation.actor = crate::management_v2_phase_state::actor(
                    RequiredActorRole::TargetDevice,
                    Some(target),
                    None,
                    vec![prepared.source_device_ref.clone()],
                );
            }
            ManagementCommandV2::ApprovalOptions { .. } => {
                let requirements = prepared
                    .revocation
                    .as_ref()
                    .ok_or(HostError::OperationInvalid)?;
                record.operation.state = ManagementOperationState::AwaitingApprovalUv;
                record.operation.actor = crate::management_v2_phase_state::actor(
                    RequiredActorRole::IndependentApproval,
                    Some(&verified.identity.assertion.device_id),
                    None,
                    vec![
                        prepared.source_device_ref.clone(),
                        requirements.target_device_ref.clone(),
                    ],
                );
            }
            _ => return Err(HostError::RequestInvalid),
        }
        record.operation.webauthn_options = Some(options);
        record.actor_options_identity_exchange = Some(verified.identity_exchange.clone());
        record.actor_options_exchange = Some(exchange.clone());
        record.operation.state_revision = revision.checked_add(1).ok_or(HostError::StateInvalid)?;
        let identity_digest =
            crate::management_v2_journal_policy::exchange_digest(verified.identity_exchange)?;
        let options_digest = crate::management_v2_journal_policy::exchange_digest(exchange)?;
        let phase_binding = crate::management_v2_journal_policy::envelope_digest(envelope)?;
        let attempt_id = record
            .operation
            .webauthn_options
            .as_ref()
            .ok_or(HostError::StateInvalid)?
            .attempt_id
            .clone();
        let evidence = [
            EvidenceUse {
                kind: "identity_authority_exchange",
                id: &identity_digest,
                binding: &phase_binding,
                expires_at_epoch_s: verified
                    .identity_exchange
                    .response
                    .expires_at_epoch_s
                    .min(verified.identity.assertion.expires_at_epoch_s)
                    .min(verified.identity.current_status.expires_at_epoch_s),
            },
            EvidenceUse {
                kind: "fresh_uv_begin_exchange",
                id: &options_digest,
                binding: &phase_binding,
                expires_at_epoch_s: exchange.response.expires_at_epoch_s,
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
                kind: "fresh_uv_attempt",
                id: &attempt_id,
                binding: &phase_binding,
                expires_at_epoch_s: exchange.response.expires_at_epoch_s,
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
        let (_, response) = self
            .journal
            .replace_consuming_response(revision, record, &evidence, receipt, now, None)?;
        Ok(response)
    }
}

include!("management_v2_phase_uv_current.rs");
include!("management_v2_phase_uv_command.rs");
