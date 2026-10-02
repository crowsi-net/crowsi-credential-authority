use crowsi_credential_authority_contracts::{
    EndpointManagementEnvelopeV2, EndpointManagementEvidenceV2, ManagementCommandV2,
    ManagementOperationState, ManagementOperationV2, ManagementProjectionBodyV2,
    ManagementProjectionV2, SignedAuthorityExchangeV1, identity_evidence_from_exchange,
    management_command_digest,
};

use crate::{
    HostError,
    management_v2_journal::ManagementJournalV2,
    management_v2_record::{DurableResponseV1, ManagementLedgerV2},
};

pub(crate) struct CancelRecovery {
    pub(crate) owner_ref: String,
    pub(crate) accepted_snapshot_revision: u64,
    pub(crate) current_snapshot_revision: u64,
    pub(crate) operation: ManagementOperationV2,
    pub(crate) identity_exchange: SignedAuthorityExchangeV1,
    pub(crate) original_response: ManagementProjectionV2,
}

impl ManagementJournalV2 {
    pub(crate) fn cancel_recovery_view(
        &self,
        envelope: &EndpointManagementEnvelopeV2,
        peer: &str,
        now: u64,
    ) -> Result<Option<CancelRecovery>, HostError> {
        let (
            ManagementCommandV2::Cancel {
                operation_id,
                expected_state_revision,
            },
            EndpointManagementEvidenceV2::Cancel {
                identity_exchange,
                prepared,
            },
        ) = (&envelope.browser_request.command, &envelope.evidence)
        else {
            return Ok(None);
        };
        let owner = prepared.opaque_owner_ref.clone();
        let request_digest = crate::management_v2_journal_policy::envelope_digest(envelope)?;
        let identity_digest =
            crate::management_v2_journal_policy::exchange_digest(identity_exchange)?;
        self.locked(&owner, || {
            let ledger =
                crate::management_v2_journal_io::read(&self.root, &self.anchor_root, &owner)?;
            recover(
                &ledger,
                envelope,
                peer,
                now,
                operation_id,
                *expected_state_revision,
                &request_digest,
                &identity_digest,
            )
        })
    }
}

include!("management_v2_journal_cancel_recovery_validation.rs");
