use std::fs;
use std::path::{Path, PathBuf};

#[test]
fn production_surface_has_no_current_fixture_or_verifier_bypass() {
    let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    collect_rust_sources(&source, &mut files);
    let forbidden = [
        "MemoryAuthority",
        "DeviceRegistration",
        "FixtureProviderVerifier",
        "test-fixture-",
        "#[doc(hidden)]",
        "identity_nonce: Option",
        "valid-provider-reissue-signature",
        "provider-signature-over-unknown-outcome",
        "valid-provider-signature",
    ];
    for file in files {
        let content = fs::read_to_string(&file).expect("read production source");
        for needle in forbidden {
            assert!(
                !content.contains(needle),
                "production bypass marker {needle:?} found in {}",
                file.display()
            );
        }
    }
}

#[test]
fn production_exports_only_the_finite_signed_host_boundary() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let library = fs::read_to_string(root.join("src/lib.rs")).expect("read library surface");
    for forbidden in [
        "pub use authority::CredentialAuthority;",
        "pub use coela_adapter::CoelaAuthorityAdapter;",
        "pub use file_store::FileAuthorityStore;",
        "pub use operation_proof::OperationProofVerifier;",
        "pub use proof::{StepUpProof, TargetKeyProof};",
        "pub use store::{AuthorityStore, MemoryStore};",
    ] {
        assert!(!library.lines().any(|line| line == forbidden));
    }
    assert!(library.contains("test-support is forbidden in release builds"));
    assert!(library.contains("pub mod test_support"));
}

#[test]
fn production_source_does_not_hide_or_retain_the_legacy_host_surface() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let source_root = root.join("src");
    let mut files = Vec::new();
    collect_rust_sources(&source_root, &mut files);
    let source = files
        .iter()
        .map(|path| fs::read_to_string(path).expect("production source"))
        .collect::<String>();
    for forbidden in [
        "allow(dead_code)",
        "struct HostRequest",
        "struct HostJournal",
        "AuthorityHostCore",
        "\"snapshot-once\"",
        "\"prepare-transfer-once\"",
        "\"finish-transfer-once\"",
        "\"cancel-transfer-once\"",
        "\"reconcile-transfer-once\"",
    ] {
        assert!(
            !source.contains(forbidden),
            "legacy production host surface remains: {forbidden}"
        );
    }
}

#[test]
fn every_production_source_file_has_a_bounded_responsibility() {
    let source_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    collect_rust_sources(&source_root, &mut files);
    for file in files {
        let content = fs::read_to_string(&file).expect("production source");
        let effective_lines = content
            .lines()
            .filter(|line| {
                let line = line.trim_start();
                !line.is_empty() && !line.starts_with("//")
            })
            .count();
        assert!(
            effective_lines <= 149,
            "{} has {effective_lines} effective lines; split the responsibility",
            file.display()
        );
    }
}

#[test]
fn production_surface_has_no_wrapped_material_transfer_variant_or_entry_point() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let source = [
        "src/lib.rs",
        "src/transfer.rs",
        "src/authority_transfer.rs",
        "src/credential.rs",
        "src/validation.rs",
    ]
    .iter()
    .map(|path| fs::read_to_string(root.join(path)).expect("source"))
    .collect::<String>();
    for forbidden in [
        "TargetKeyWrappedEnvelope",
        "ExclusiveExportable",
        "RawTransferForbidden",
        "envelope_ref",
        "envelope_digest",
    ] {
        assert!(
            !source.contains(forbidden),
            "forbidden production transfer: {forbidden}"
        );
    }
}

#[test]
fn production_file_store_has_only_current_anchored_open_and_private_initialization() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let store = fs::read_to_string(root.join("src/file_store.rs")).expect("file store source");
    let adapter = fs::read_to_string(root.join("src/coela_adapter.rs")).expect("adapter source");
    assert!(store.contains("pub fn open_anchored("));
    assert!(store.contains("pub(crate) fn initialize_anchored("));
    assert!(!store.contains("pub fn initialize_anchored("));
    assert!(!store.contains("pub fn open("));
    assert!(!adapter.contains("CoelaAuthorityAdapter::open("));
    assert!(adapter.contains("FileAuthorityStore::open_anchored("));
}

include!("production_surface_support.rs");
include!("production_surface_config.rs");
