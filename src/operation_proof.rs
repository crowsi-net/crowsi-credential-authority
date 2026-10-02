#[cfg(feature = "test-support")]
use crate::StepUpProof;
use crate::TargetKeyProof;

/// Production proof port. Implementations must consult or cryptographically
/// verify an authoritative step-up and device-key proof source.
pub trait OperationProofVerifier {
    #[cfg(feature = "test-support")]
    fn verify_step_up(&self, proof: &StepUpProof) -> bool;

    fn verify_target_key(&self, proof: &TargetKeyProof) -> bool;
}
