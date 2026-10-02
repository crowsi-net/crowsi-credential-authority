use crate::identity::verify_device_identity_assertion;
use crate::{
    AuthorityError, AuthorityStore, CoelaAuthorityAdapter, CoelaDeviceRevocationRequest,
    DeviceRevocationReceipt, IdentityAssertionVerifier, OperationProofVerifier,
    ProviderEvidenceVerifier, ServiceAccountOwnerMapper,
};

impl<S, I, M, P> CoelaAuthorityAdapter<S, I, M, P>
where
    S: AuthorityStore,
    I: IdentityAssertionVerifier,
    M: ServiceAccountOwnerMapper,
    P: ProviderEvidenceVerifier + OperationProofVerifier,
{
    pub fn revoke_device(
        &mut self,
        request: CoelaDeviceRevocationRequest,
        assertion: &[u8],
    ) -> Result<DeviceRevocationReceipt, AuthorityError> {
        if !self.evidence_verifier.verify_step_up(&request.step_up) {
            return Err(AuthorityError::FreshStepUpRequired);
        }
        let binding = verify_device_identity_assertion(
            assertion,
            &self.management_audience,
            &self.identity_verifier,
            self.authority.now_ms()? / 1_000,
        )?;
        self.authority
            .validate_identity_binding(&binding, &self.management_audience)?;
        let owner = self.owner_mapper.map_owner(
            &binding.issuer,
            &binding.service_id,
            &binding.pairwise_subject,
        )?;
        if owner != request.owner || binding.device_id != request.step_up.device {
            return Err(AuthorityError::IdentityAssertionInvalid);
        }
        self.authority
            .revoke_device_from_identity(request, &binding)
    }
}
