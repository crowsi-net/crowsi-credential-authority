use crowsi_authority_transport::SignedRequest;
use crowsi_credential_authority_contracts::{
    EndpointManagementEvidenceV2 as E, ManagementCommandV2 as C,
    decode_endpoint_management_envelope_strict,
};

use crate::{HostError, management_v2_handler::ManagementV2Handler};

impl ManagementV2Handler {
    pub(crate) fn handle(&self, request: &SignedRequest, now: u64) -> Result<Vec<u8>, HostError> {
        let envelope = decode_endpoint_management_envelope_strict(&request.payload)
            .map_err(|_| HostError::RequestInvalid)?;
        command_matches(&request.command, &envelope.browser_request.command)?;
        if let Some(response) =
            self.recover_revocation_pre_final(&envelope, &request.peer.device_id, now)?
        {
            return Ok(response);
        }
        if let Some(response) =
            self.recover_cancel_response(&envelope, &request.peer.device_id, now)?
        {
            return Ok(response);
        }
        if let Some(response) =
            self.recover_mutation_response(&envelope, &request.peer.device_id, now)?
        {
            return Ok(response);
        }
        let verified = crate::management_v2_identity::verify(
            &self.core.config,
            &envelope,
            &request.peer.device_id,
            now,
        )?;
        let request_digest = crate::management_v2_journal_policy::envelope_digest(&envelope)?;
        let identity_digest =
            crate::management_v2_journal_policy::exchange_digest(verified.identity_exchange)?;
        if let Some(response) = self.journal.exact_response(
            &verified.owner.opaque_owner_ref,
            &request_digest,
            &identity_digest,
            verified.identity_exchange.response.config_generation,
            now,
        )? {
            return Ok(response);
        }
        self.journal.expire_due(
            &verified.owner.opaque_owner_ref,
            verified.identity_exchange.response.config_generation,
            now,
        )?;
        if let E::SourceOptions { prepared, .. } = &envelope.evidence {
            crowsi_credential_authority_contracts::validate_endpoint_prepared_at(
                prepared,
                verified.identity,
                now,
            )
            .map_err(|_| HostError::EvidenceInvalid)?;
        }
        match (&envelope.browser_request.command, &envelope.evidence) {
            (C::Snapshot { .. }, E::Passive { .. }) => self.snapshot(&envelope, &verified, now),
            (C::PendingList { .. }, E::Passive { .. }) => self.pending(&envelope, &verified, now),
            (
                C::SourceOptions { .. },
                E::SourceOptions {
                    prepared,
                    uv_options,
                    ..
                },
            ) => self.source_options(&envelope, &verified, prepared, uv_options, now),
            (
                C::SourceApprove { .. },
                E::SourceApprove {
                    prepared,
                    finish_uv_exchange,
                    revocation_ceremony,
                    ..
                },
            ) => self.source_approve(
                &envelope,
                &verified,
                prepared,
                finish_uv_exchange,
                revocation_ceremony.as_ref(),
                now,
            ),
            (
                C::TargetOptions { .. } | C::ApprovalOptions { .. },
                E::ActorOptions {
                    prepared,
                    uv_options,
                    ..
                },
            ) => self.actor_options(&envelope, &verified, prepared, uv_options, now),
            (
                C::TargetApprove { .. },
                E::TargetApprove {
                    prepared,
                    finish_uv_exchange,
                    target_proof,
                    ..
                },
            ) => self.target_approve(
                &envelope,
                &verified,
                prepared,
                finish_uv_exchange,
                target_proof,
                now,
            ),
            (C::ApproveRevocation { .. }, E::IndependentApprove { .. }) => {
                Err(HostError::RequestInvalid)
            }
            (C::Cancel { .. }, E::Cancel { prepared, .. }) => {
                self.cancel_v2(&envelope, &verified, prepared, now)
            }
            (C::Reconcile { .. }, E::Reconcile { prepared, .. }) => {
                self.reconcile_v2(&envelope, &verified, prepared, now)
            }
            _ => Err(HostError::RequestInvalid),
        }
    }
}

pub(crate) fn command_matches(route: &str, command: &C) -> Result<(), HostError> {
    (route == crate::management_v2_command::route(command))
        .then_some(())
        .ok_or(HostError::RequestInvalid)
}
