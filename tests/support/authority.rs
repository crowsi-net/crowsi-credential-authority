use super::*;

pub struct TestAuthority(CredentialAuthority<MemoryStore>);

impl TestAuthority {
    pub fn at(now_ms: u64) -> Self {
        Self(CredentialAuthority::with_store(
            MemoryStore::new(now_ms),
            now_ms,
        ))
    }

    pub fn reopen_from_durable_store(&self) -> Self {
        Self(self.0.reopen_from_durable_store())
    }

    pub fn issue_device_grant(
        &mut self,
        request: DeviceGrantRequest,
    ) -> Result<DeviceGrant, AuthorityError> {
        let wire =
            signed_identity_assertion(&source_device(), &audience(), &next_identity_nonce("grant"));
        self.0.issue_device_grant_from_assertion(
            request,
            &wire,
            &TestIdentityVerifier,
            &TestOwnerMapper,
        )
    }

    pub fn prepare_transfer(
        &mut self,
        request: TransferRequest,
    ) -> Result<TransferReceipt, AuthorityError> {
        self.prepare_transfer_with_identity_nonce(request, &next_identity_nonce("transfer"))
    }

    pub fn prepare_transfer_with_identity_nonce(
        &mut self,
        request: TransferRequest,
        identity_nonce: &str,
    ) -> Result<TransferReceipt, AuthorityError> {
        let wire = signed_identity_assertion(&source_device(), &audience(), identity_nonce);
        self.0.prepare_transfer_from_assertion(
            request,
            &wire,
            &TestIdentityVerifier,
            &TestOwnerMapper,
        )
    }

    pub fn accept_transfer(
        &mut self,
        acceptance: TransferAcceptance,
    ) -> Result<TransferReceipt, AuthorityError> {
        self.0.accept_transfer(acceptance, &TestProviderVerifier)
    }

    pub fn record_provider_outcome(
        &mut self,
        transfer: &TransferId,
        outcome: ProviderOperationOutcome,
    ) -> Result<(), AuthorityError> {
        self.0
            .record_provider_outcome(transfer, outcome, &TestProviderVerifier)
    }

    pub fn reconcile_provider_outcome(
        &mut self,
        transfer: &TransferId,
        reconciliation: SignedProviderReconciliation,
    ) -> Result<(), AuthorityError> {
        self.0
            .reconcile_provider_outcome(transfer, reconciliation, &TestProviderVerifier)
    }

    pub fn reconcile_provider_not_issued(
        &mut self,
        transfer: &TransferId,
        reconciliation: SignedProviderReconciliation,
    ) -> Result<(), AuthorityError> {
        self.0
            .reconcile_provider_not_issued(transfer, reconciliation, &TestProviderVerifier)
    }

    pub fn record_provider_reissue(
        &mut self,
        owner: &OpaqueOwnerRef,
        credential: &CredentialId,
        receipt: ProviderReissueReceipt,
        proof: StepUpProof,
    ) -> Result<RevisionReceipt, AuthorityError> {
        self.0
            .record_provider_reissue(owner, credential, receipt, proof, &TestProviderVerifier)
    }
}

impl Deref for TestAuthority {
    type Target = CredentialAuthority<MemoryStore>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for TestAuthority {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
