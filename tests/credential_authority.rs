#[path = "support/mod.rs"]
mod support;

use crowsi_credential_authority::test_support::{
    CredentialAuthority, IdentityAssertionVerifier, MemoryStore, ServiceAccountOwnerMapper,
    StepUpProof, TargetKeyProof,
};
use crowsi_credential_authority::{
    AccountClosureRequest, AccountState, AssertionVerifier, AuthorityError, CommitFailPoint,
    CredentialClass, CredentialRegistration, DEVICE_IDENTITY_ASSERTION_SCHEMA, DeviceGrantRequest,
    GrantAction, GrantAudience, GrantState, GrantUse, MetadataProjectionQuery, OpaqueOwnerRef,
    ProviderOperationOutcome, ProviderReissueReceipt, RevocationCause,
    SignedProviderReconciliation, TransferAcceptance, TransferCancellation, TransferMechanism,
    TransferRequest, TransferState,
};
use support::{
    GRANT_TTL_MS, NOW_MS, action, audience, authority, credential_id, fresh_step_up, owner_a,
    owner_b, provider_account, register_credential, register_device, service, source_device,
    target_device, target_key_proof, unique_grant_target_key_proof, unrelated_device,
};

#[path = "credential_authority/cr_01_02.rs"]
mod cr_01_02;
#[path = "credential_authority/cr_03.rs"]
mod cr_03;
#[path = "credential_authority/cr_04_06.rs"]
mod cr_04_06;
#[path = "credential_authority/cr_07_08.rs"]
mod cr_07_08;
#[path = "credential_authority/cr_09_10.rs"]
mod cr_09_10;
#[path = "credential_authority/identity_support.rs"]
mod identity_support;
#[path = "credential_authority/limits_grants.rs"]
mod limits_grants;
#[path = "credential_authority/limits_registration.rs"]
mod limits_registration;
#[path = "credential_authority/operation_support.rs"]
mod operation_support;
#[path = "credential_authority/tr_01_03.rs"]
mod tr_01_03;
#[path = "credential_authority/tr_04_07.rs"]
mod tr_04_07;
#[path = "credential_authority/tr_08_e2e.rs"]
mod tr_08_e2e;

use identity_support::*;
use operation_support::*;
