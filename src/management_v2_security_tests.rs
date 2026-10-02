use std::{fs, os::unix::fs::PermissionsExt};

use crate::management_v2_journal::ManagementJournalV2;

// CR-11: management state is explicitly initialized and every owner transaction is FD-pinned.
#[test]
fn missing_marker_unknown_file_and_directory_mode_change_fail_closed() {
    let (root, state, anchor) = directories("shape");
    assert!(ManagementJournalV2::open(&state, &anchor, 1, binding()).is_err());
    ManagementJournalV2::initialize(&state, &anchor, 1, binding()).expect("initialize");
    let journal = ManagementJournalV2::open(&state, &anchor, 1, binding()).expect("open");
    journal
        .view("psa_owner_0000000000000001")
        .expect("first view");
    owner_file(&state.join("unexpected"), b"{}\n");
    assert!(journal.view("psa_owner_0000000000000001").is_err());
    fs::remove_file(state.join("unexpected")).expect("repair");
    fs::set_permissions(&state, fs::Permissions::from_mode(0o777)).expect("chmod");
    assert!(journal.view("psa_owner_0000000000000001").is_err());
    fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).expect("restore");
    fs::remove_dir_all(root).expect("cleanup");
}

#[test]
fn lock_hardlink_and_marker_loss_never_reset_owner_ledger() {
    let (root, state, anchor) = directories("lock");
    ManagementJournalV2::initialize(&state, &anchor, 1, binding()).expect("initialize");
    let journal = ManagementJournalV2::open(&state, &anchor, 1, binding()).expect("open");
    let owner = "psa_owner_0000000000000001";
    journal.view(owner).expect("create owner lock");
    let lock = state.join(format!(
        "management-v5-{}.lock",
        crate::host_crypto::digest(owner.as_bytes())
    ));
    fs::hard_link(&lock, root.join("lock-alias")).expect("hardlink");
    assert!(journal.view(owner).is_err());
    fs::remove_file(root.join("lock-alias")).expect("repair link");
    fs::remove_file(state.join(crate::management_v2_marker::filename("state")))
        .expect("remove marker");
    assert!(ManagementJournalV2::open(&state, &anchor, 1, binding()).is_err());
    assert!(ManagementJournalV2::initialize(&state, &anchor, 1, binding()).is_err());
    fs::remove_dir_all(root).expect("cleanup");
}

fn binding() -> crate::management_v2_journal::ReservationRootBinding {
    crate::management_v2_journal::ReservationRootBinding::test()
}

fn directories(label: &str) -> (std::path::PathBuf, std::path::PathBuf, std::path::PathBuf) {
    let root = std::env::temp_dir().join(format!(
        "crowsi-management-security-{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time")
            .as_nanos()
    ));
    let state = root.join("state");
    let anchor = root.join("anchor");
    fs::create_dir_all(&state).expect("state");
    fs::create_dir(&anchor).expect("anchor");
    for path in [&root, &state, &anchor] {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).expect("mode");
    }
    (root, state, anchor)
}

fn owner_file(path: &std::path::Path, wire: &[u8]) {
    use std::{io::Write, os::unix::fs::OpenOptionsExt};
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .expect("owner file");
    file.write_all(wire).expect("wire");
}
