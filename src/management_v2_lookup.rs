use crowsi_authority_transport::SignedRequest;
use crowsi_credential_authority_contracts::{
    ENDPOINT_PREPARED_LOOKUP_RESPONSE_SCHEMA, EndpointPreparedLookupResponseV1,
    canonical_endpoint_prepared_lookup_response, decode_endpoint_prepared_lookup_request_strict,
    endpoint_prepared_lookup_request_digest,
};

use crate::{HostError, host_crypto, management_v2_handler::ManagementV2Handler};

impl ManagementV2Handler {
    pub(crate) fn lookup_prepared(
        &self,
        request: &SignedRequest,
        now: u64,
    ) -> Result<Vec<u8>, HostError> {
        let lookup = decode_endpoint_prepared_lookup_request_strict(&request.payload)
            .map_err(|_| HostError::RequestInvalid)?;
        let verified = crate::management_v2_identity::verify_lookup(
            &self.core.config,
            &lookup.identity_exchange,
            &request.peer.device_id,
            now,
        )?;
        let response_request_digest = endpoint_prepared_lookup_request_digest(&lookup)
            .map_err(|_| HostError::RequestInvalid)?;
        let request_digest =
            crate::management_v2_receipt::lookup_request_digest(&response_request_digest);
        let identity_digest =
            crate::management_v2_journal_policy::exchange_digest(&lookup.identity_exchange)?;
        if let Some(response) = self.journal.exact_response(
            &verified.owner.opaque_owner_ref,
            &request_digest,
            &identity_digest,
            lookup.identity_exchange.response.config_generation,
            now,
        )? {
            return Ok(response);
        }
        self.journal.expire_due(
            &verified.owner.opaque_owner_ref,
            lookup.identity_exchange.response.config_generation,
            now,
        )?;
        let (revision, records) = self.journal.current_view(
            &verified.owner.opaque_owner_ref,
            lookup.identity_exchange.response.config_generation,
        )?;
        let record = records
            .iter()
            .find(|item| item.operation.operation_id == lookup.operation_id)
            .cloned()
            .ok_or(HostError::StateInvalid)?;
        let historic_phase = matches!(
            lookup.phase,
            crowsi_credential_authority_contracts::EndpointPreparedLookupPhaseV1::Cancel
                | crowsi_credential_authority_contracts::EndpointPreparedLookupPhaseV1::Reconcile
        );
        if record.owner_ref != verified.owner.opaque_owner_ref
            || record.service_id != verified.identity.assertion.service_id
            || record.pairwise_subject != verified.identity.assertion.pairwise_subject
            || record.operation.state_revision != lookup.expected_state_revision
            || (!historic_phase && now >= record.prepared.expires_at_epoch_s)
            || !crate::management_v2_lookup_policy::allowed(
                lookup.phase,
                &record,
                &request.peer.device_id,
                &verified.identity.assertion.session_ref,
            )
        {
            return Err(HostError::StateInvalid);
        }
        let pending = records
            .into_iter()
            .filter(|item| !crate::management_v2_quota::terminal(item))
            .map(|item| item.operation)
            .collect();
        let snapshot = self.authority_snapshot(&verified, pending, now)?;
        crate::management_v2_handler::current_records(&snapshot, &verified)?;
        let epochs = &verified.identity.assertion.revocation_epochs;
        let mut expires = now
            .saturating_add(30)
            .min(lookup.identity_exchange.response.expires_at_epoch_s)
            .min(verified.identity.assertion.expires_at_epoch_s)
            .min(verified.identity.current_status.expires_at_epoch_s);
        if !historic_phase {
            expires = expires.min(record.prepared.expires_at_epoch_s);
        }
        let (revocation_begin, pre_final_acceptance_request_sha256, expires) =
            revocation_context(lookup.phase, &record, expires)?;
        if expires <= now {
            return Err(HostError::EvidenceInvalid);
        }
        let mut response = EndpointPreparedLookupResponseV1 {
            schema: ENDPOINT_PREPARED_LOOKUP_RESPONSE_SCHEMA.into(),
            request_id: lookup.request_id.clone(),
            request_digest_sha256: response_request_digest,
            actor_device_ref: verified.identity.assertion.device_id.clone(),
            actor_session_ref: verified.identity.assertion.session_ref.clone(),
            subject_revocation_epoch: epochs.subject,
            service_revocation_epoch: epochs.service,
            device_revocation_epoch: epochs.device,
            session_revocation_epoch: epochs.session,
            operation: record.operation,
            prepared: record.prepared,
            revocation_begin_exchange: revocation_begin.map(|(exchange, _)| exchange),
            pre_final_acceptance_request_sha256,
            issued_at_epoch_s: now,
            expires_at_epoch_s: expires,
            key_id: self
                .core
                .config
                .document
                .management_projection_key_id
                .clone(),
            signature: String::new(),
        };
        let canonical = canonical_endpoint_prepared_lookup_response(&response)
            .map_err(|_| HostError::ResponseInvalid)?;
        response.signature = host_crypto::sign(
            &self.core.config.management_projection_signing_key,
            &canonical,
        );
        verify_response(&self.core.config, &response, &lookup, now)?;
        let uses = lookup_uses(
            &verified,
            &identity_digest,
            &request_digest,
            lookup.identity_exchange.response.expires_at_epoch_s,
        );
        let receipt = crate::management_v2_receipt::prepared_lookup(
            request_digest.clone(),
            identity_digest.clone(),
            verified.identity.assertion.device_id.clone(),
            lookup.operation_id.clone(),
            expires,
            response,
        )?;
        self.journal.commit_read_response(
            &verified.owner.opaque_owner_ref,
            revision,
            lookup.identity_exchange.response.config_generation,
            &uses,
            receipt,
            now,
        )
    }
}

include!("management_v2_lookup_modules.rs");
