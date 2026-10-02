use crate::{
    AuthorityError, AuthorityStore, CoelaAuthorityAdapter, DeviceId, DeviceRevocationReceipt,
    IdentityAssertionVerifier, OpaqueOwnerRef, OperationProofVerifier, ProviderEvidenceVerifier,
    ServiceAccountOwnerMapper,
};

impl<S, I, M, P> CoelaAuthorityAdapter<S, I, M, P>
where
    S: AuthorityStore,
    I: IdentityAssertionVerifier,
    M: ServiceAccountOwnerMapper,
    P: ProviderEvidenceVerifier + OperationProofVerifier,
{
    pub(crate) fn apply_host_device_revocation(
        &mut self,
        operation_id: &str,
        owner: &OpaqueOwnerRef,
        target: &DeviceId,
        previous: u64,
        current: u64,
    ) -> Result<DeviceRevocationReceipt, AuthorityError> {
        self.authority
            .apply_host_device_revocation(operation_id, owner, target, previous, current)
    }

    pub(crate) fn apply_host_session_revocation(
        &mut self,
        operation_id: &str,
        owner: &OpaqueOwnerRef,
        target_session: &str,
        previous: u64,
        current: u64,
    ) -> Result<(u64, u64), AuthorityError> {
        self.authority.apply_host_session_revocation(
            operation_id,
            owner,
            target_session,
            previous,
            current,
        )
    }
}
