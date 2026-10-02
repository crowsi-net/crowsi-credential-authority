use crowsi_credential_authority_contracts::{
    EndpointManagementEnvelopeV2, ManagementProjectionBodyV2,
};
use std::path::Path;

use crate::{
    HostError, management_v2_host_context::ManagementHostContext,
    management_v2_identity::VerifiedManagementIdentity, management_v2_journal::ManagementJournalV2,
};

pub(crate) use crate::management_v2_handler_projection::current_records;

pub(crate) struct ManagementV2Handler {
    pub(crate) core: ManagementHostContext,
    pub(crate) journal: ManagementJournalV2,
}

impl ManagementV2Handler {
    pub(crate) fn open(core: ManagementHostContext) -> Result<Self, HostError> {
        let journal = ManagementJournalV2::open(
            Path::new(&core.config.document.management_state_directory),
            Path::new(&core.config.document.management_anchor_directory),
            core.config.document.authority_epoch,
            crate::management_v2_journal::ReservationRootBinding::from_config(
                &core.config.document,
            ),
        )?;
        Ok(Self { core, journal })
    }

    pub(crate) fn snapshot(
        &self,
        envelope: &EndpointManagementEnvelopeV2,
        verified: &VerifiedManagementIdentity<'_>,
        now: u64,
    ) -> Result<Vec<u8>, HostError> {
        let (revision, records) = self.journal.current_view(
            &verified.owner.opaque_owner_ref,
            verified.identity_exchange.response.config_generation,
        )?;
        let pending = records
            .into_iter()
            .filter(|item| !terminal(item.operation.state))
            .map(|item| item.operation)
            .collect();
        let snapshot = self.authority_snapshot(verified, pending, now)?;
        current_records(&snapshot, verified)?;
        self.read_projection(
            envelope,
            verified,
            revision,
            ManagementProjectionBodyV2::Snapshot { snapshot },
            now,
        )
    }

    pub(crate) fn pending(
        &self,
        envelope: &EndpointManagementEnvelopeV2,
        verified: &VerifiedManagementIdentity<'_>,
        now: u64,
    ) -> Result<Vec<u8>, HostError> {
        let (revision, operations) = self.journal.current_operations(
            &verified.owner.opaque_owner_ref,
            &verified.identity.assertion.service_id,
            verified.identity_exchange.response.config_generation,
        )?;
        self.read_projection(
            envelope,
            verified,
            revision,
            ManagementProjectionBodyV2::Pending { operations },
            now,
        )
    }
}

pub(crate) fn terminal(
    value: crowsi_credential_authority_contracts::ManagementOperationState,
) -> bool {
    use crowsi_credential_authority_contracts::ManagementOperationState as S;
    matches!(
        value,
        S::Completed | S::Rejected | S::Cancelled | S::Expired
    )
}
