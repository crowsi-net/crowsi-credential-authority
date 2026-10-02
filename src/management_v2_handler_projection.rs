use crowsi_credential_authority_contracts::{ManagementOperationV2, ManagementSnapshotV2};

use crate::{
    CoelaAuthorityAdapter, GrantAudience, HostError,
    host_identity::{HostIdentityVerifier, HostOwnerMapper},
    host_proofs::HostProofVerifier,
    management_v2_handler::ManagementV2Handler,
    management_v2_identity::VerifiedManagementIdentity,
};

impl ManagementV2Handler {
    pub(crate) fn authority_snapshot(
        &self,
        verified: &VerifiedManagementIdentity<'_>,
        pending: Vec<ManagementOperationV2>,
        now: u64,
    ) -> Result<ManagementSnapshotV2, HostError> {
        let identity =
            HostIdentityVerifier::new(&self.core.config, verified.identity.current_status.clone());
        let mapper = HostOwnerMapper(self.core.config.document.owner_mappings.clone());
        // Passive authority reads consume identity evidence only. Historic
        // Cancel/Reconcile lookup must remain available after a signed config
        // rotation removes a provider route, so do not resolve one here.
        let proofs = HostProofVerifier::new(None, None, String::new());
        let adapter = CoelaAuthorityAdapter::open_anchored(
            &self.core.config.document.authority_store_directory,
            &self.core.config.document.authority_anchor_directory,
            now.saturating_mul(1_000),
            GrantAudience::parse(self.core.config.document.registration_audience.clone())?,
            GrantAudience::parse(self.core.config.document.management_audience.clone())?,
            identity,
            mapper,
            proofs,
        )?;
        let assertion = serde_json::to_vec(&verified.identity.assertion)
            .map_err(|_| HostError::EvidenceInvalid)?;
        let projection = adapter.list_account_passive(
            &assertion,
            crate::authority_limits::MANAGEMENT_PROJECTION_LIMIT,
        )?;
        crate::management_v2_snapshot::decode(&projection.encode_json()?, pending)
    }
}

pub(crate) fn current_records(
    snapshot: &ManagementSnapshotV2,
    verified: &VerifiedManagementIdentity<'_>,
) -> Result<(), HostError> {
    let assertion = &verified.identity.assertion;
    let device = snapshot
        .devices
        .iter()
        .find(|item| item.device_ref == assertion.device_id)
        .ok_or(HostError::EvidenceInvalid)?;
    let session = snapshot
        .sessions
        .iter()
        .find(|item| {
            item.session_ref == assertion.session_ref && item.device_ref == assertion.device_id
        })
        .ok_or(HostError::EvidenceInvalid)?;
    if device.status == crowsi_credential_authority_contracts::ManagementLifecycleV2::Active
        && session.status == crowsi_credential_authority_contracts::ManagementLifecycleV2::Active
        && device.device_revocation_epoch == assertion.revocation_epochs.device
        && device.posture_revision == assertion.device_posture.revision
        && session.session_revocation_epoch == assertion.revocation_epochs.session
    {
        Ok(())
    } else {
        Err(HostError::EvidenceInvalid)
    }
}
