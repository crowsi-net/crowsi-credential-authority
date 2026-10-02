use ihat_identity_assertion_contracts::{
    AUTHORITY_REQUEST_SCHEMA, AUTHORITY_RESPONSE_SCHEMA, AuthorityCommand, AuthorityEvidence,
    AuthorityRequestV1, AuthorityResponseV1, AuthorityResult, CurrentDeviceStatusV1,
    DeviceIdentityAssertionV1, DevicePostureV1, IdentityEvidenceMetadata,
    IssueCurrentDeviceIdentityEvidenceCommand, ResponseOutcome, RevocationEpochsV1,
    SIGNED_EVIDENCE_SCHEMA, SignedEvidenceV1, VerificationRole, command_digest,
};
use std::{fs, os::unix::fs::PermissionsExt, path::PathBuf};

pub(crate) const NOW: u64 = 1_000;

pub(crate) struct Fixture {
    root: PathBuf,
    pub state: PathBuf,
    pub anchor: PathBuf,
}

impl Fixture {
    pub(crate) fn new() -> Self {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "crowsi-management-journal-{}-{nonce}",
            std::process::id()
        ));
        let state = root.join("state");
        let anchor = root.join("anchor");
        fs::create_dir_all(&state).expect("state");
        fs::create_dir(&anchor).expect("anchor");
        for path in [&root, &state, &anchor] {
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).expect("mode");
        }
        crate::management_v2_journal::ManagementJournalV2::initialize(
            &state,
            &anchor,
            1,
            crate::management_v2_journal::ReservationRootBinding::test(),
        )
        .expect("initialize journal");
        Self {
            root,
            state,
            anchor,
        }
    }

    pub(crate) fn journal(&self) -> crate::management_v2_journal::ManagementJournalV2 {
        crate::management_v2_journal::ManagementJournalV2::open(
            &self.state,
            &self.anchor,
            1,
            crate::management_v2_journal::ReservationRootBinding::test(),
        )
        .expect("journal")
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

pub(crate) fn identity(device: &str) -> IdentityEvidenceMetadata {
    let posture = DevicePostureV1 {
        state: "healthy".into(),
        revision: 1,
    };
    let epochs = RevocationEpochsV1 {
        subject: 1,
        service: 1,
        device: 1,
        session: 1,
    };
    let assertion = DeviceIdentityAssertionV1 {
        schema: "ihat://identity/device-identity-assertion/v1".into(),
        issuer: "ihat".into(),
        audience: "crowsi".into(),
        service_id: "service-a".into(),
        pairwise_subject: "psu_owner".into(),
        device_id: device.into(),
        device_proof_key_ref: format!("proof-{device}"),
        session_ref: sref('a'),
        device_posture: posture.clone(),
        revocation_epochs: epochs.clone(),
        issued_at_epoch_s: NOW - 1,
        expires_at_epoch_s: NOW + 30,
        nonce: format!("status-{device}"),
        key_id: "identity-key".into(),
        signature: "00".repeat(64),
    };
    let status = CurrentDeviceStatusV1 {
        schema: "ihat://identity/current-device-status/v1".into(),
        issuer: assertion.issuer.clone(),
        audience: assertion.audience.clone(),
        service_id: assertion.service_id.clone(),
        pairwise_subject: assertion.pairwise_subject.clone(),
        device_id: assertion.device_id.clone(),
        device_proof_key_ref: assertion.device_proof_key_ref.clone(),
        session_ref: assertion.session_ref.clone(),
        device_posture: posture,
        revocation_epochs: epochs,
        issued_at_epoch_s: NOW - 1,
        expires_at_epoch_s: NOW + 30,
        nonce: assertion.nonce.clone(),
        key_id: "status-key".into(),
        signature: "11".repeat(64),
    };
    IdentityEvidenceMetadata {
        assertion,
        current_status: status,
    }
}

include!("management_v2_journal_test_identity_exchange.rs");
