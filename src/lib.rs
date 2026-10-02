//! Metadata-only credential ownership, device grant, and transfer authority.

#![forbid(unsafe_code)]

#[cfg(all(feature = "authority-host-test-root", not(debug_assertions)))]
compile_error!("authority-host-test-root is forbidden in release builds");
#[cfg(all(feature = "test-support", not(debug_assertions)))]
compile_error!("test-support is forbidden in release builds");

include!("lib_modules.rs");
include!("lib_management_modules.rs");

pub use account::{AccountClosureReceipt, AccountClosureRequest, AccountState};
pub(crate) use authority::CredentialAuthority;
pub(crate) use coela_adapter::CoelaAuthorityAdapter;
pub use coela_revocation_request::CoelaDeviceRevocationRequest;
pub use credential::{CredentialClass, CredentialMetadata, CredentialRegistration};
pub use crowsi_credential_authority_contracts::{
    TargetDeviceProofBindingV2, target_device_proof_digest,
};
pub use error::AuthorityError;
pub(crate) use file_store::FileAuthorityStore;
pub use gateway::run_authority_gateway_cli;
pub use grant::{DeviceGrant, DeviceGrantRequest, GrantState};
pub use grant_use::{GrantUse, RevisionReceipt};
pub use host_cli::run_authority_host_cli;
pub use host_error::HostError;
pub use host_provider_contract::HostProviderEvidence as ProviderEvidenceDocumentV1;
pub use id::{
    CredentialId, DeviceId, GrantAction, GrantAudience, GrantId, OpaqueOwnerRef,
    ProviderAccountRef, ServiceId, TransferId,
};
pub use identity::DeviceIdentityBinding;
pub(crate) use identity::{IdentityAssertionVerifier, ServiceAccountOwnerMapper};
pub use ihat_identity_assertion_contracts::{
    AssertionVerifier, DEVICE_IDENTITY_ASSERTION_SCHEMA, DeviceIdentityAssertionV1,
    DevicePostureV1, RevocationEpochsV1, decode_assertion_strict, verify_assertion_at,
};
pub use management_projection::CoelaManagementProjection;
pub(crate) use operation_proof::OperationProofVerifier;
pub use projection::{MetadataProjection, MetadataProjectionQuery};
pub(crate) use proof::{StepUpProof, TargetKeyProof};
pub use provider::{
    ProviderOperationOutcome, ProviderReissueReceipt, SignedProviderReconciliation,
};
pub use provider_evidence::ProviderEvidenceKind;
pub(crate) use provider_evidence::ProviderEvidenceVerifier;
pub use state::DurableSnapshot;
pub use state::{CredentialRevocationReceipt, DeviceRevocationReceipt, RevocationCause};
pub(crate) use store::AuthorityStore;
pub use transfer::{CommitFailPoint, TransferMechanism, TransferRequest, TransferState};
pub use transfer_receipt::{
    GrantPairState, TransferAcceptance, TransferCancellation, TransferCancellationReceipt,
    TransferReceipt,
};

/// Non-production construction surface used only by integration tests.
#[cfg(feature = "test-support")]
pub mod test_support {
    use std::path::Path;

    pub use crate::authority::CredentialAuthority;
    pub use crate::coela_adapter::CoelaAuthorityAdapter;
    pub use crate::file_store::FileAuthorityStore;
    pub use crate::file_store_failpoint::{FileStoreFailpoint, set_file_store_failpoint};
    pub use crate::gateway_replay::GatewayReplayGuard;
    pub use crate::identity::{
        IdentityAssertionVerifier, ServiceAccountOwnerMapper, verify_device_identity_assertion,
    };
    pub use crate::operation_proof::OperationProofVerifier;
    pub use crate::proof::{StepUpProof, TargetKeyProof};
    pub use crate::provider_evidence::ProviderEvidenceVerifier;
    pub use crate::store::{AuthorityStore, MemoryStore};

    pub fn initialize_file_authority_store(
        state: impl AsRef<Path>,
        anchor: impl AsRef<Path>,
        initial_clock_ms: u64,
    ) -> Result<FileAuthorityStore, crate::AuthorityError> {
        FileAuthorityStore::initialize_anchored(state, anchor, initial_clock_ms)
    }
}
