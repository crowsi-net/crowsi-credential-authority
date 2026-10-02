mod management_projection;
mod management_projection_records;
mod management_v2_adapter;
mod management_v2_anchor;
mod management_v2_anchor_scan;
mod management_v2_atomic;
mod management_v2_cancel_recovery;
#[cfg(all(test, feature = "test-support"))]
mod management_v2_cancel_recovery_tests;
mod management_v2_command;
mod management_v2_commit;
#[cfg(all(test, feature = "test-support"))]
mod management_v2_commit_tests;
mod management_v2_config_generation;
#[cfg(all(test, feature = "test-support"))]
mod management_v2_config_generation_tests;
mod management_v2_dispatch;
#[cfg(all(test, feature = "test-support"))]
mod management_v2_dispatch_tests;
mod management_v2_evidence;
mod management_v2_evidence_ceremony;
#[cfg(all(test, feature = "test-support"))]
mod management_v2_evidence_ceremony_tests;
mod management_v2_evidence_use;
include!("lib_management_cancellation_modules.rs");
mod management_v2_execution_reservation;
mod management_v2_execution_reservation_build;
mod management_v2_execution_reservation_response;
mod management_v2_generation;
mod management_v2_handler;
mod management_v2_handler_projection;
mod management_v2_handler_read;
mod management_v2_handler_source;
mod management_v2_head;
mod management_v2_historic_mapping;
mod management_v2_host_adapter;
mod management_v2_host_context;
mod management_v2_identity;
mod management_v2_independent_finalization;
mod management_v2_independent_finalization_acceptance;
mod management_v2_independent_pre_final;
mod management_v2_independent_pre_final_mutation;
mod management_v2_independent_revocation_finalize;
mod management_v2_intent;
mod management_v2_journal;
mod management_v2_journal_cancel_recovery;
mod management_v2_journal_cancel_slot;
mod management_v2_journal_execution_reservation;
mod management_v2_journal_expiry;
mod management_v2_journal_finalization;
#[cfg(all(test, feature = "test-support"))]
mod management_v2_journal_fixture;
mod management_v2_journal_independent_finalization;
mod management_v2_journal_independent_pre_final;
mod management_v2_journal_io;
mod management_v2_journal_lock;
mod management_v2_journal_mutation_recovery;
mod management_v2_journal_policy;
#[cfg(all(test, feature = "test-support"))]
mod management_v2_journal_policy_tests;
mod management_v2_journal_pre_finalization;
mod management_v2_journal_receipt;
#[cfg(all(test, feature = "test-support"))]
mod management_v2_journal_test_environment;
#[cfg(all(test, feature = "test-support"))]
mod management_v2_journal_tests;
mod management_v2_journal_update;
mod management_v2_journal_view;
mod management_v2_lookup;
mod management_v2_lookup_policy;
mod management_v2_marker;
mod management_v2_mutation_recovery;
#[cfg(all(test, feature = "test-support"))]
mod management_v2_mutation_recovery_test_support;
#[cfg(all(test, feature = "test-support"))]
mod management_v2_mutation_recovery_tests;
mod management_v2_operation;
mod management_v2_operation_conflict;
#[cfg(all(test, feature = "test-support"))]
mod management_v2_operation_conflict_tests;
mod management_v2_operation_policy;
mod management_v2_operation_revocation;
mod management_v2_operation_scope;
mod management_v2_phase_finish;
mod management_v2_phase_source;
mod management_v2_phase_state;
mod management_v2_phase_target;
mod management_v2_phase_uv;
mod management_v2_projection;
mod management_v2_provider_acceptance;
#[cfg(all(test, feature = "test-support"))]
mod management_v2_provider_acceptance_tests;
mod management_v2_provider_progress;
mod management_v2_quota;
mod management_v2_receipt;
#[cfg(all(test, feature = "test-support"))]
mod management_v2_receipt_test_support;
#[cfg(all(test, feature = "test-support"))]
mod management_v2_receipt_tests;
mod management_v2_record;
mod management_v2_revocation;
mod management_v2_revocation_finalization;
mod management_v2_revocation_finalization_acceptance;
#[cfg(all(test, feature = "test-support"))]
mod management_v2_revocation_finalization_tests;
mod management_v2_revocation_finalize;
mod management_v2_revocation_plan;
mod management_v2_revocation_pre_final;
mod management_v2_revocation_rotation;
mod management_v2_revocation_rotation_io;
mod management_v2_revocation_state;
mod management_v2_revocation_target;
#[cfg(all(test, feature = "test-support"))]
mod management_v2_security_tests;
mod management_v2_snapshot;
mod management_v2_state;
mod management_v2_transfer;
mod management_v2_transfer_context;
mod management_v2_transfer_prepare;
mod management_v2_transfer_reconcile;
mod management_v2_transfer_state;
mod management_v2_transport_replay;
#[cfg(all(test, feature = "test-support"))]
mod management_v2_transport_replay_tests;
mod operation_proof;
mod projection;
mod proof;
mod provider;
mod provider_evidence;
mod session;
mod state;
mod store;
mod transfer;
mod transfer_receipt;
mod validation;
