#[path = "support/mod.rs"]
mod support;

use crowsi_credential_authority::test_support::{
    AuthorityStore, CoelaAuthorityAdapter, CredentialAuthority, FileAuthorityStore,
    IdentityAssertionVerifier, OperationProofVerifier, ProviderEvidenceVerifier,
    ServiceAccountOwnerMapper, StepUpProof, TargetKeyProof, initialize_file_authority_store,
};
use crowsi_credential_authority::{
    AssertionVerifier, AuthorityError, CoelaDeviceRevocationRequest, CredentialClass,
    CredentialRegistration, DEVICE_IDENTITY_ASSERTION_SCHEMA, DeviceGrantRequest, GrantAudience,
    GrantUse, ProviderEvidenceKind, ProviderOperationOutcome, TransferAcceptance,
    TransferMechanism, TransferRequest,
};
use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};
use support::{
    GRANT_TTL_MS, NOW_MS, action, audience, credential_id, fresh_step_up, owner_a,
    provider_account, provider_operation_ref, service, source_device, target_device,
    target_key_proof,
};

#[path = "file_authority_store/adapter.rs"]
mod adapter;
#[path = "file_authority_store/ancestor_hardening.rs"]
mod ancestor_hardening;
#[path = "file_authority_store/anchored_hardening.rs"]
mod anchored_hardening;
#[path = "file_authority_store/crash_recovery.rs"]
mod crash_recovery;
#[path = "file_authority_store/environment.rs"]
mod environment;
#[path = "file_authority_store/fixtures.rs"]
mod fixtures;
#[path = "file_authority_store/integrity_paths.rs"]
mod integrity_paths;
#[path = "file_authority_store/persistence_concurrency.rs"]
mod persistence_concurrency;
#[path = "file_authority_store/retention_hardening.rs"]
mod retention_hardening;
#[path = "file_authority_store/rollback_boundary.rs"]
mod rollback_boundary;

use environment::*;
use fixtures::*;
