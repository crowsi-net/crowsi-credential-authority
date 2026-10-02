#[cfg(feature = "test-support")]
use crate::StepUpProof;
use crate::{
    OperationProofVerifier, ProviderEvidenceKind, ProviderEvidenceVerifier, TargetKeyProof,
};

#[derive(Clone)]
pub(crate) struct HostProofVerifier {
    #[cfg(feature = "test-support")]
    step_up: Option<StepUpProof>,
    target: Option<TargetKeyProof>,
    provider_public_key: String,
}

impl HostProofVerifier {
    pub(crate) fn new(
        step_up: Option<crate::StepUpProof>,
        target: Option<TargetKeyProof>,
        provider_public_key: impl Into<String>,
    ) -> Self {
        #[cfg(not(feature = "test-support"))]
        drop(step_up);
        Self {
            #[cfg(feature = "test-support")]
            step_up,
            target,
            provider_public_key: provider_public_key.into(),
        }
    }
}

impl OperationProofVerifier for HostProofVerifier {
    #[cfg(feature = "test-support")]
    fn verify_step_up(&self, proof: &StepUpProof) -> bool {
        self.step_up.as_ref() == Some(proof)
    }
    fn verify_target_key(&self, proof: &TargetKeyProof) -> bool {
        self.target.as_ref() == Some(proof)
    }
}

impl ProviderEvidenceVerifier for HostProofVerifier {
    fn verify(&self, kind: ProviderEvidenceKind, payload: &[u8], signature: &str) -> bool {
        let name = match kind {
            ProviderEvidenceKind::ReissueReceipt => "reissue-receipt",
            ProviderEvidenceKind::UnknownOutcome => "unknown-outcome",
            ProviderEvidenceKind::Reconciliation => "not-issued-reconciliation",
        };
        crate::host_crypto::verify(
            &self.provider_public_key,
            signature,
            &crate::host_crypto::provider_payload(name, payload),
        )
    }
}
