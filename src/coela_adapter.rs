use crate::{
    AuthorityError, AuthorityStore, CredentialAuthority, FileAuthorityStore, GrantAudience,
    IdentityAssertionVerifier, OperationProofVerifier, ProviderEvidenceVerifier,
    ServiceAccountOwnerMapper,
};
use std::path::Path;

pub struct CoelaAuthorityAdapter<S, I, M, P>
where
    S: AuthorityStore,
    I: IdentityAssertionVerifier,
    M: ServiceAccountOwnerMapper,
    P: ProviderEvidenceVerifier + OperationProofVerifier,
{
    pub(crate) authority: CredentialAuthority<S>,
    pub(crate) identity_verifier: I,
    pub(crate) owner_mapper: M,
    pub(crate) evidence_verifier: P,
    #[cfg(feature = "test-support")]
    registration_audience: GrantAudience,
    pub(crate) management_audience: GrantAudience,
}

impl<I, M, P> CoelaAuthorityAdapter<FileAuthorityStore, I, M, P>
where
    I: IdentityAssertionVerifier,
    M: ServiceAccountOwnerMapper,
    P: ProviderEvidenceVerifier + OperationProofVerifier,
{
    pub fn open_anchored(
        state_directory: impl AsRef<Path>,
        anchor_directory: impl AsRef<Path>,
        now_ms: u64,
        registration_audience: GrantAudience,
        management_audience: GrantAudience,
        identity_verifier: I,
        owner_mapper: M,
        evidence_verifier: P,
    ) -> Result<Self, AuthorityError> {
        let store = FileAuthorityStore::open_anchored(state_directory, anchor_directory)?;
        Ok(Self::new(
            CredentialAuthority::with_store(store, now_ms),
            registration_audience,
            management_audience,
            identity_verifier,
            owner_mapper,
            evidence_verifier,
        ))
    }
}

impl<S, I, M, P> CoelaAuthorityAdapter<S, I, M, P>
where
    S: AuthorityStore,
    I: IdentityAssertionVerifier,
    M: ServiceAccountOwnerMapper,
    P: ProviderEvidenceVerifier + OperationProofVerifier,
{
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn new(
        authority: CredentialAuthority<S>,
        registration_audience: GrantAudience,
        management_audience: GrantAudience,
        identity_verifier: I,
        owner_mapper: M,
        evidence_verifier: P,
    ) -> Self {
        #[cfg(not(feature = "test-support"))]
        drop(registration_audience);
        Self {
            authority,
            identity_verifier,
            owner_mapper,
            evidence_verifier,
            #[cfg(feature = "test-support")]
            registration_audience,
            management_audience,
        }
    }

    #[cfg(feature = "test-support")]
    pub fn register_device(&mut self, assertion: &[u8]) -> Result<(), AuthorityError> {
        self.authority.register_device_from_assertion(
            assertion,
            &self.registration_audience,
            &self.identity_verifier,
            &self.owner_mapper,
        )
    }
}
