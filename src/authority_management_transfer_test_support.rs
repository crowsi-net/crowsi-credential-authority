use crate::{
    AuthorityStore, CredentialAuthority, CredentialClass, CredentialId, CredentialRegistration,
    DeviceGrant, DeviceId, GrantAction, GrantAudience, GrantId, GrantState, OpaqueOwnerRef,
    ProviderAccountRef, ProviderEvidenceKind, ProviderEvidenceVerifier, ProviderReissueReceipt,
    ServiceId, StepUpProof, TargetKeyProof, TransferAcceptance, TransferMechanism, TransferRequest,
    state::DeviceRecord, store::MemoryStore, transfer::ManagementDeviceBinding,
};

pub(super) const NOW: u64 = 1_800_000_000_000;

pub(super) struct Fixture {
    pub authority: CredentialAuthority<MemoryStore>,
    pub owner: OpaqueOwnerRef,
    pub source: DeviceId,
    pub target: DeviceId,
    pub credential: CredentialId,
    pub audience: GrantAudience,
    pub action: GrantAction,
    pub authorization: String,
    pub transfer: crate::TransferReceipt,
    pub prior_grant: GrantId,
}

include!("authority_management_transfer_test_fixture.rs");
include!("authority_management_transfer_test_fixture_impl.rs");
include!("authority_management_transfer_test_helpers.rs");
