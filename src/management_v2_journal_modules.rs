include!("management_v2_journal_views.rs");

#[cfg(all(test, feature = "test-support"))]
include!("management_v2_journal_test_api.rs");

include!("management_v2_journal_pristine.rs");
