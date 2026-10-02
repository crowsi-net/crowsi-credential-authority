use std::{
    fs,
    os::unix::fs::{PermissionsExt, symlink},
    path::{Path, PathBuf},
};

use crate::management_v2_record::ManagementLedgerV2;

#[test]
fn cr_11_anchor_rejects_ledger_anchor_rollback_tamper_and_broken_symlinks() {
    // CR-11: the independently provisioned monotonic anchor binds the complete owner ledger.
    let fixture = Fixture::new();
    let owner = "psa_owner_0000000000000001";
    let mut ledger = ManagementLedgerV2::empty();
    ledger.revision = 2;
    crate::management_v2_journal_io::write(&fixture.state, &fixture.anchor, owner, &ledger)
        .expect("revision two");
    let old_anchor = files(&fixture.anchor, "management-v5-anchor-")[0].clone();
    let old_anchor_wire = fs::read(&old_anchor).expect("old anchor");
    ledger.revision = 3;
    crate::management_v2_journal_io::write(&fixture.state, &fixture.anchor, owner, &ledger)
        .expect("revision three");
    assert_eq!(
        crate::management_v2_journal_io::read(&fixture.state, &fixture.anchor, owner)
            .expect("current")
            .revision,
        3
    );

    let latest_ledger = ledger_at(&fixture.state, 3);
    let held = fixture.state.join("held-generation");
    fs::rename(&latest_ledger, &held).expect("hide current ledger");
    assert!(crate::management_v2_journal_io::read(&fixture.state, &fixture.anchor, owner).is_err());
    fs::rename(&held, &latest_ledger).expect("restore current ledger");

    let latest_anchor = files(&fixture.anchor, "management-v5-anchor-")
        .pop()
        .expect("anchor");
    let latest_anchor_wire = fs::read(&latest_anchor).expect("latest anchor");
    fs::write(&latest_anchor, &old_anchor_wire).expect("substitute old anchor");
    assert!(crate::management_v2_journal_io::read(&fixture.state, &fixture.anchor, owner).is_err());
    fs::write(&latest_anchor, &latest_anchor_wire).expect("restore anchor");

    fs::write(&latest_ledger, b"{}").expect("tamper ledger");
    assert!(crate::management_v2_journal_io::read(&fixture.state, &fixture.anchor, owner).is_err());

    let empty = Fixture::new();
    let broken = empty.anchor.join(format!(
        "management-v5-anchor-{}-{:020}-{}.json",
        crate::host_crypto::digest(owner.as_bytes()).trim_start_matches("sha256:"),
        2,
        "a".repeat(64)
    ));
    symlink(empty.anchor.join("missing"), broken).expect("broken symlink");
    assert!(crate::management_v2_journal_io::read(&empty.state, &empty.anchor, owner).is_err());
}

struct Fixture {
    root: PathBuf,
    state: PathBuf,
    anchor: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "crowsi-management-anchor-{}-{nonce}",
            std::process::id()
        ));
        let state = root.join("state");
        let anchor = root.join("anchor");
        fs::create_dir_all(&state).expect("state");
        fs::create_dir(&anchor).expect("anchor");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("root mode");
        fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).expect("state mode");
        fs::set_permissions(&anchor, fs::Permissions::from_mode(0o700)).expect("anchor mode");
        Self {
            root,
            state,
            anchor,
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn files(root: &Path, prefix: &str) -> Vec<PathBuf> {
    let mut values = fs::read_dir(root)
        .expect("read directory")
        .map(|item| item.expect("entry"))
        .filter(|item| item.file_name().to_string_lossy().starts_with(prefix))
        .map(|item| item.path())
        .collect::<Vec<_>>();
    values.sort();
    values
}

fn ledger_at(root: &Path, revision: u64) -> PathBuf {
    files(root, "management-v5-ledger-")
        .into_iter()
        .find(|path| {
            serde_json::from_slice::<ManagementLedgerV2>(&fs::read(path).expect("ledger wire"))
                .is_ok_and(|value| value.revision == revision)
        })
        .expect("ledger revision")
}
