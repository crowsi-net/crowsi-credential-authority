use crate::{
    AuthorityStore, GrantAction, GrantId, GrantState, ProviderAccountRef, ProviderReissueReceipt,
    ServiceId, management_v2_record::RevocationTargetBindingV1,
};

use super::authority_management_transfer_test_support::{NOW, Verifier, fixture};

include!("authority_revocation_rotation_replay_tests.rs");
include!("authority_revocation_rotation_historic_tests.rs");
