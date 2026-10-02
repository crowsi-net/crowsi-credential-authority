mod account;
mod authority;
#[cfg(feature = "test-support")]
mod authority_account;
#[cfg(feature = "test-support")]
mod authority_cancel;
mod authority_commit;
mod authority_commit_replay;
#[cfg(feature = "test-support")]
mod authority_device_revocation;
#[cfg(feature = "test-support")]
mod authority_grant;
mod authority_grant_limits;
#[cfg(feature = "test-support")]
mod authority_grant_use;
mod authority_host_revocation;
#[cfg(all(test, feature = "test-support"))]
mod authority_host_revocation_tests;
#[cfg(feature = "test-support")]
mod authority_identity;
mod authority_identity_validation;
#[cfg(feature = "test-support")]
mod authority_lifecycle;
mod authority_limits;
mod authority_management_rotation;
#[cfg(all(test, feature = "test-support"))]
mod authority_management_transfer_test_support;
#[cfg(all(test, feature = "test-support"))]
mod authority_management_transfer_tests;
#[cfg(feature = "test-support")]
mod authority_projection;
mod authority_provider;
mod authority_provider_receipt;
#[cfg(feature = "test-support")]
mod authority_registration;
mod authority_revocation_rotation;
#[cfg(all(test, feature = "test-support"))]
mod authority_revocation_rotation_tests;
#[cfg(feature = "test-support")]
mod authority_rotation;
mod authority_transfer;
mod authority_transfer_cancel;
#[cfg(feature = "test-support")]
mod authority_transfer_entry;
mod authority_transfer_recovery;
mod coela_adapter;
mod coela_adapter_projection;
mod coela_host_revocation;
mod coela_mutations;
mod coela_mutations_recovery;
#[cfg(feature = "test-support")]
mod coela_revocation;
mod coela_revocation_request;
mod credential;
mod error;
mod file_store;
mod file_store_ancestors;
mod file_store_anchor;
mod file_store_atomic;
mod file_store_chain;
mod file_store_codec;
mod file_store_envelope;
mod file_store_failpoint;
mod file_store_file;
mod file_store_head;
mod file_store_head_recovery;
mod file_store_init_head;
mod file_store_initialize;
mod file_store_inventory;
mod file_store_lock;
mod file_store_marker;
mod file_store_metadata;
mod file_store_path;
mod file_store_recovery;
mod file_store_scan;
mod file_store_validate;
mod file_store_wire;
include!("lib_gateway_modules.rs");
