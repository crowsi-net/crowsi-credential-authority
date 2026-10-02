use crate::{
    AuthorityError, AuthorityStore, CoelaAuthorityAdapter, IdentityAssertionVerifier,
    OperationProofVerifier, ProviderEvidenceVerifier, ProviderOperationOutcome,
    ServiceAccountOwnerMapper, SignedProviderReconciliation, TransferAcceptance, TransferId,
    TransferReceipt, TransferRequest,
};
#[cfg(feature = "test-support")]
use crate::{DeviceGrant, DeviceGrantRequest, TransferCancellation, TransferCancellationReceipt};

impl<S, I, M, P> CoelaAuthorityAdapter<S, I, M, P>
where
    S: AuthorityStore,
    I: IdentityAssertionVerifier,
    M: ServiceAccountOwnerMapper,
    P: ProviderEvidenceVerifier + OperationProofVerifier,
{
    #[cfg(feature = "test-support")]
    pub fn issue_grant(
        &mut self,
        request: DeviceGrantRequest,
        assertion: &[u8],
    ) -> Result<DeviceGrant, AuthorityError> {
        if !self.evidence_verifier.verify_step_up(&request.step_up) {
            return Err(AuthorityError::FreshStepUpRequired);
        }
        if !self
            .evidence_verifier
            .verify_target_key(&request.target_proof)
        {
            return Err(AuthorityError::TargetKeyProofInvalid);
        }
        self.authority.issue_device_grant_from_assertion(
            request,
            assertion,
            &self.identity_verifier,
            &self.owner_mapper,
        )
    }

    #[cfg(feature = "test-support")]
    pub fn prepare_transfer(
        &mut self,
        request: TransferRequest,
        assertion: &[u8],
    ) -> Result<TransferReceipt, AuthorityError> {
        if !self.evidence_verifier.verify_step_up(&request.step_up) {
            return Err(AuthorityError::FreshStepUpRequired);
        }
        if !self
            .evidence_verifier
            .verify_target_key(&request.target_proof)
        {
            return Err(AuthorityError::TargetKeyProofInvalid);
        }
        self.authority.prepare_transfer_from_assertion(
            request,
            assertion,
            &self.identity_verifier,
            &self.owner_mapper,
        )
    }

    pub(crate) fn prepare_management_transfer(
        &mut self,
        request: TransferRequest,
        authorization_digest: &str,
        source_binding: &crate::transfer::ManagementDeviceBinding,
        target_binding: &crate::transfer::ManagementDeviceBinding,
    ) -> Result<TransferReceipt, AuthorityError> {
        if !self
            .evidence_verifier
            .verify_target_key(&request.target_proof)
        {
            return Err(AuthorityError::TargetKeyProofInvalid);
        }
        self.authority.prepare_management_transfer(
            request,
            authorization_digest,
            source_binding,
            target_binding,
        )
    }

    #[cfg(feature = "test-support")]
    pub fn finish_transfer(
        &mut self,
        acceptance: TransferAcceptance,
    ) -> Result<TransferReceipt, AuthorityError> {
        if !self
            .evidence_verifier
            .verify_target_key(&acceptance.target_proof)
        {
            return Err(AuthorityError::TargetKeyProofInvalid);
        }
        self.authority
            .accept_transfer(acceptance, &self.evidence_verifier)
    }

    pub(crate) fn finish_management_transfer(
        &mut self,
        acceptance: TransferAcceptance,
        authorization_digest: &str,
    ) -> Result<TransferReceipt, AuthorityError> {
        self.authority.accept_management_transfer(
            acceptance,
            &self.evidence_verifier,
            authorization_digest,
        )
    }

    #[cfg(feature = "test-support")]
    pub fn cancel_transfer(
        &mut self,
        cancellation: TransferCancellation,
    ) -> Result<TransferCancellationReceipt, AuthorityError> {
        if !self.evidence_verifier.verify_step_up(&cancellation.step_up) {
            return Err(AuthorityError::FreshStepUpRequired);
        }
        self.authority.cancel_transfer(cancellation)
    }

    pub fn record_unknown_provider_outcome(
        &mut self,
        transfer: &TransferId,
        outcome: ProviderOperationOutcome,
    ) -> Result<(), AuthorityError> {
        self.authority
            .record_provider_outcome(transfer, outcome, &self.evidence_verifier)
    }
}

include!("coela_mutations_reconciliation.rs");
