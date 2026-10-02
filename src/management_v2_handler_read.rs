use crowsi_credential_authority_contracts::{
    EndpointManagementEnvelopeV2, ManagementProjectionBodyV2,
};

use crate::{
    HostError, management_v2_handler::ManagementV2Handler,
    management_v2_identity::VerifiedManagementIdentity, management_v2_journal_update::EvidenceUse,
};

impl ManagementV2Handler {
    pub(crate) fn read_projection(
        &self,
        envelope: &EndpointManagementEnvelopeV2,
        verified: &VerifiedManagementIdentity<'_>,
        revision: u64,
        body: ManagementProjectionBodyV2,
        now: u64,
    ) -> Result<Vec<u8>, HostError> {
        let request_digest = crate::management_v2_journal_policy::envelope_digest(envelope)?;
        let identity_digest =
            crate::management_v2_journal_policy::exchange_digest(verified.identity_exchange)?;
        let retain_until = now
            .saturating_add(30)
            .min(verified.identity_exchange.response.expires_at_epoch_s)
            .min(verified.identity.assertion.expires_at_epoch_s)
            .min(verified.identity.current_status.expires_at_epoch_s);
        let uses = [
            EvidenceUse {
                kind: "identity_authority_exchange",
                id: &identity_digest,
                binding: &request_digest,
                expires_at_epoch_s: verified.identity_exchange.response.expires_at_epoch_s,
            },
            EvidenceUse {
                kind: "identity_assertion_nonce",
                id: &verified.identity.assertion.nonce,
                binding: &request_digest,
                expires_at_epoch_s: verified.identity.assertion.expires_at_epoch_s,
            },
            EvidenceUse {
                kind: "current_status_nonce",
                id: &verified.identity.current_status.nonce,
                binding: &request_digest,
                expires_at_epoch_s: verified.identity.current_status.expires_at_epoch_s,
            },
        ];
        let receipt = crate::management_v2_receipt::projection(
            &self.core.config,
            envelope,
            verified,
            body,
            crate::management_v2_journal_policy::next(revision)?,
            now,
            retain_until,
            true,
        )?;
        self.journal.commit_read_response(
            &verified.owner.opaque_owner_ref,
            revision,
            verified.identity_exchange.response.config_generation,
            &uses,
            receipt,
            now,
        )
    }
}
