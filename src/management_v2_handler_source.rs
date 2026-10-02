use crowsi_credential_authority_contracts::{
    EndpointManagementEnvelopeV2, EndpointPreparedOperationV2, ManagementProjectionBodyV2,
    SignedAuthorityExchangeV1,
};

use crate::{
    HostError,
    management_v2_handler::{ManagementV2Handler, current_records, terminal},
    management_v2_identity::VerifiedManagementIdentity,
    management_v2_journal_update::EvidenceUse,
    management_v2_record::ManagementRecordV2,
};

impl ManagementV2Handler {
    pub(crate) fn source_options(
        &self,
        envelope: &EndpointManagementEnvelopeV2,
        verified: &VerifiedManagementIdentity<'_>,
        prepared: &EndpointPreparedOperationV2,
        uv: &SignedAuthorityExchangeV1,
        now: u64,
    ) -> Result<Vec<u8>, HostError> {
        let (revision, records) = self.journal.view(&verified.owner.opaque_owner_ref)?;
        let snapshot = self.authority_snapshot(
            verified,
            records
                .into_iter()
                .filter(|item| !terminal(item.operation.state))
                .map(|item| item.operation)
                .collect(),
            now,
        )?;
        current_records(&snapshot, verified)?;
        let options = crate::management_v2_evidence::options(&self.core.config, uv, now)?;
        let attempt_id = options.attempt_id.clone();
        let operation = crate::management_v2_operation::initial(
            &self.core.config,
            prepared,
            &snapshot,
            options,
            revision,
            now,
        )?;
        let grant_action = crate::management_v2_operation::grant_action(prepared, &snapshot)?;
        let generation_floor = self
            .journal
            .generation_head(&verified.owner.opaque_owner_ref)?
            .max(self.core.config.document.minimum_identity_config_generation);
        let authority_config_generation = crate::management_v2_config_generation::advance(
            generation_floor,
            &[verified.identity_exchange, uv],
        )?;
        let mut revocation_saga = crate::management_v2_revocation_plan::plan(prepared, &snapshot);
        bind_revocation_target(
            self,
            verified,
            prepared,
            &snapshot,
            &mut revocation_saga,
            now,
        )?;
        let identity_digest =
            crate::management_v2_journal_policy::exchange_digest(verified.identity_exchange)?;
        let options_digest = crate::management_v2_journal_policy::exchange_digest(uv)?;
        let phase_binding = crate::management_v2_journal_policy::envelope_digest(envelope)?;
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
                expires_at_epoch_s: uv.response.expires_at_epoch_s,
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
                expires_at_epoch_s: uv.response.expires_at_epoch_s,
            },
        ];
        let record = source_record(
            operation,
            prepared,
            verified,
            authority_config_generation,
            uv,
            grant_action,
            revocation_saga,
        );
        let receipt = crate::management_v2_receipt::projection(
            &self.core.config,
            envelope,
            verified,
            ManagementProjectionBodyV2::Operation {
                operation: record.operation.clone(),
            },
            crate::management_v2_journal_policy::next(revision)?,
            now,
            prepared.expires_at_epoch_s.saturating_add(300),
            false,
        )?;
        let (_, response) = self
            .journal
            .insert_consuming_response(record, &evidence, receipt, now)?;
        Ok(response)
    }
}

include!("management_v2_handler_source_target.rs");
include!("management_v2_handler_source_record.rs");
