use crowsi_credential_authority_contracts::ManagementOperationState;

use crate::management_v2_journal_fixture::{Fixture, NOW, record, revocation};
use crate::management_v2_journal_update::EvidenceUse;

include!("management_v2_journal_evidence_policy_tests.rs");
include!("management_v2_journal_quota_policy_tests.rs");
include!("management_v2_journal_expiry_policy_tests.rs");

fn use_of(id: &str, expires: u64, binding: char) -> EvidenceUse<'_> {
    use_of_kind("current_status_nonce", id, expires, binding)
}

fn use_of_kind<'a>(kind: &'a str, id: &'a str, expires: u64, binding: char) -> EvidenceUse<'a> {
    let binding = match binding {
        'a' => "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        'b' => "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        _ => "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
    };
    EvidenceUse {
        kind,
        id,
        binding,
        expires_at_epoch_s: expires,
    }
}
