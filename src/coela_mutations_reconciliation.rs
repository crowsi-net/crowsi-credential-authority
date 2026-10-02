impl<S, I, M, P> CoelaAuthorityAdapter<S, I, M, P>
where
    S: AuthorityStore,
    I: IdentityAssertionVerifier,
    M: ServiceAccountOwnerMapper,
    P: ProviderEvidenceVerifier + OperationProofVerifier,
{
    #[cfg(feature = "test-support")]
    pub fn reconcile_provider_outcome(
        &mut self,
        transfer: &TransferId,
        reconciliation: SignedProviderReconciliation,
    ) -> Result<(), AuthorityError> {
        self.authority
            .reconcile_provider_outcome(transfer, reconciliation, &self.evidence_verifier)
    }

    pub fn reconcile_provider_not_issued(
        &mut self,
        transfer: &TransferId,
        reconciliation: SignedProviderReconciliation,
    ) -> Result<(), AuthorityError> {
        self.authority.reconcile_provider_not_issued(
            transfer,
            reconciliation,
            &self.evidence_verifier,
        )
    }
}
