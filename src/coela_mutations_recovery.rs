use crate::{
    AuthorityError, AuthorityStore, CoelaAuthorityAdapter, IdentityAssertionVerifier,
    OperationProofVerifier, ProviderEvidenceVerifier, ServiceAccountOwnerMapper,
};

impl<S, I, M, P> CoelaAuthorityAdapter<S, I, M, P>
where
    S: AuthorityStore,
    I: IdentityAssertionVerifier,
    M: ServiceAccountOwnerMapper,
    P: ProviderEvidenceVerifier + OperationProofVerifier,
{
    pub(crate) fn apply_host_revocation_rotation(
        &mut self,
        operation_id: &str,
        owner: &crate::OpaqueOwnerRef,
        credential: &crate::CredentialId,
        compromised: &crate::DeviceId,
        provider_nonce: &str,
        target_binding: &crate::management_v2_record::RevocationTargetBindingV1,
        receipt: crate::ProviderReissueReceipt,
    ) -> Result<crate::RevisionReceipt, AuthorityError> {
        self.authority.apply_host_revocation_rotation(
            operation_id,
            owner,
            credential,
            compromised,
            provider_nonce,
            target_binding,
            receipt,
            &self.evidence_verifier,
        )
    }
}
