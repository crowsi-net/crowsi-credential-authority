use crate::{AuthorityStore, GrantState, GrantUse, ServiceId, TransferState};

use super::authority_management_transfer_test_support::{NOW, Verifier, binding, fixture};

include!("authority_management_transfer_historic_tests.rs");
include!("authority_management_transfer_capacity_tests.rs");
include!("authority_management_transfer_recovery_tests.rs");
