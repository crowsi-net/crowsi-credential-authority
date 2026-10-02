use crowsi_credential_authority_contracts::{
    ActorRequirementV2, EndpointManagementEnvelopeV2, EndpointPreparedOperationV2,
    ManagementCommandV2, ManagementOperationState, ManagementProjectionBodyV2,
    ManagementReasonCode, RequiredActorRole,
};

use crate::{
    HostError, management_v2_handler::ManagementV2Handler,
    management_v2_identity::VerifiedManagementIdentity, management_v2_journal_update::EvidenceUse,
};

impl ManagementV2Handler {
    pub(crate) fn cancel_v2(
        &self,
        envelope: &EndpointManagementEnvelopeV2,
        verified: &VerifiedManagementIdentity<'_>,
        prepared: &EndpointPreparedOperationV2,
        now: u64,
    ) -> Result<Vec<u8>, HostError> {
        let (id, revision) = command(&envelope.browser_request.command)?;
        let mut record = self.journal.record(&verified.owner.opaque_owner_ref, id)?;
        if !crate::management_v2_lookup_policy::allowed(
            crowsi_credential_authority_contracts::EndpointPreparedLookupPhaseV1::Cancel,
            &record,
            &verified.identity.assertion.device_id,
            &verified.identity.assertion.session_ref,
        ) || record.prepared != *prepared
            || record.operation.state_revision != revision
        {
            return Err(HostError::StateInvalid);
        }
        record.authority_config_generation = crate::management_v2_config_generation::record(
            &self.journal,
            &record,
            &[verified.identity_exchange],
        )?;
        record.operation.state = ManagementOperationState::Cancelled;
        record.operation.state_revision = next(revision)?;
        record.operation.actor = none();
        record.operation.webauthn_options = None;
        record.operation.reason = Some(ManagementReasonCode::OperationCancelled);
        record.operation.reconcile_digest = None;
        let phase_binding = crate::management_v2_journal_policy::envelope_digest(envelope)?;
        let identity_digest =
            crate::management_v2_journal_policy::exchange_digest(verified.identity_exchange)?;
        let uses = identity_uses(verified, &identity_digest, &phase_binding);
        let (ledger_revision, _) = self.journal.view(&verified.owner.opaque_owner_ref)?;
        let mut receipt = crate::management_v2_receipt::projection(
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
        receipt.retain_until_epoch_s = u64::MAX;
        let (_, response) = self.journal.replace_consuming_response(
            revision,
            record,
            &uses,
            receipt,
            now,
            Some((&self.core.config, envelope)),
        )?;
        Ok(response)
    }
}

include!("management_v2_phase_reconcile.rs");

fn command(value: &ManagementCommandV2) -> Result<(&str, u64), HostError> {
    match value {
        ManagementCommandV2::Cancel {
            operation_id,
            expected_state_revision,
        }
        | ManagementCommandV2::Reconcile {
            operation_id,
            expected_state_revision,
            ..
        } => Ok((operation_id, *expected_state_revision)),
        _ => Err(HostError::RequestInvalid),
    }
}

fn next(value: u64) -> Result<u64, HostError> {
    value.checked_add(1).ok_or(HostError::StateInvalid)
}

fn none() -> ActorRequirementV2 {
    ActorRequirementV2 {
        role: RequiredActorRole::NoActor,
        required_actor_device_ref: None,
        required_approval_authority_ref: None,
        excluded_actor_device_refs: Vec::new(),
    }
}

fn identity_uses<'a>(
    verified: &'a VerifiedManagementIdentity<'a>,
    exchange_digest: &'a str,
    binding: &'a str,
) -> [EvidenceUse<'a>; 3] {
    [
        EvidenceUse {
            kind: "identity_authority_exchange",
            id: exchange_digest,
            binding,
            expires_at_epoch_s: verified.identity_exchange.response.expires_at_epoch_s,
        },
        EvidenceUse {
            kind: "identity_assertion_nonce",
            id: &verified.identity.assertion.nonce,
            binding,
            expires_at_epoch_s: verified.identity.assertion.expires_at_epoch_s,
        },
        EvidenceUse {
            kind: "current_status_nonce",
            id: &verified.identity.current_status.nonce,
            binding,
            expires_at_epoch_s: verified.identity.current_status.expires_at_epoch_s,
        },
    ]
}
