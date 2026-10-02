use crate::{
    AuthorityError, AuthorityStore, CoelaAuthorityAdapter, CredentialAuthority, DeviceId,
    DurableSnapshot, FileAuthorityStore, GrantAudience, IdentityAssertionVerifier, OpaqueOwnerRef,
    OperationProofVerifier, ProviderEvidenceKind, ProviderEvidenceVerifier,
    ServiceAccountOwnerMapper, StepUpProof, TargetKeyProof,
};
use ihat_identity_assertion_contracts::AssertionVerifier;
use std::path::Path;

pub use super::file_fixture::TemporaryStore;

pub const NOW_MS: u64 = 1_900_000_000_000;
pub const OPERATION_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
pub const OPERATION_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

pub fn owner_a() -> OpaqueOwnerRef {
    OpaqueOwnerRef::parse("psa_host_revocation_owner_a_0001").expect("owner A")
}

pub fn owner_b() -> OpaqueOwnerRef {
    OpaqueOwnerRef::parse("psa_host_revocation_owner_b_0002").expect("owner B")
}

pub fn device_a() -> DeviceId {
    DeviceId::parse("device-a-compromised").expect("device A")
}

pub fn device_b() -> DeviceId {
    DeviceId::parse("device-b-healthy").expect("device B")
}

pub fn memory_authority() -> CredentialAuthority<crate::store::MemoryStore> {
    CredentialAuthority::with_store(
        crate::store::MemoryStore::from_snapshot(super::state::fixture()),
        NOW_MS,
    )
}

pub fn seed_file_store(path: &Path, anchor: &Path) -> FileAuthorityStore {
    let store = FileAuthorityStore::initialize_anchored(path, anchor, NOW_MS)
        .expect("file authority store");
    store
        .transact(|snapshot| {
            *snapshot = super::state::fixture();
            Ok(())
        })
        .expect("fixture persisted");
    store
}

pub fn adapter<S: AuthorityStore>(
    authority: CredentialAuthority<S>,
) -> CoelaAuthorityAdapter<S, TestVerifier, TestVerifier, TestVerifier> {
    CoelaAuthorityAdapter::new(
        authority,
        GrantAudience::parse("crowsi://identity/register").expect("registration audience"),
        GrantAudience::parse("crowsi://management/v2").expect("management audience"),
        TestVerifier,
        TestVerifier,
        TestVerifier,
    )
}

pub fn snapshot<S: AuthorityStore>(authority: &CredentialAuthority<S>) -> DurableSnapshot {
    authority
        .store
        .read(|snapshot| Ok(snapshot.clone()))
        .expect("authority snapshot")
}

pub fn adapter_snapshot<S: AuthorityStore>(
    adapter: &CoelaAuthorityAdapter<S, TestVerifier, TestVerifier, TestVerifier>,
) -> DurableSnapshot {
    snapshot(&adapter.authority)
}

pub struct TestVerifier;

impl AssertionVerifier for TestVerifier {
    fn verify(&self, _key_id: &str, _payload: &[u8], _signature: &str) -> bool {
        false
    }
}

impl IdentityAssertionVerifier for TestVerifier {
    fn expected_issuer(&self) -> &'static str {
        "ihat://identity-authority"
    }

    fn revocation_epochs_are_current(&self, _binding: &crate::DeviceIdentityBinding) -> bool {
        false
    }
}

impl ServiceAccountOwnerMapper for TestVerifier {
    fn map_owner(
        &self,
        _issuer: &str,
        _service_id: &crate::ServiceId,
        _subject: &str,
    ) -> Result<OpaqueOwnerRef, AuthorityError> {
        Err(AuthorityError::WrongOwner)
    }
}

impl ProviderEvidenceVerifier for TestVerifier {
    fn verify(&self, _kind: ProviderEvidenceKind, _payload: &[u8], _signature: &str) -> bool {
        false
    }
}

impl OperationProofVerifier for TestVerifier {
    fn verify_step_up(&self, _proof: &StepUpProof) -> bool {
        false
    }

    fn verify_target_key(&self, _proof: &TargetKeyProof) -> bool {
        false
    }
}
