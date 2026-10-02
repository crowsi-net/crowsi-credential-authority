use std::{fs, os::unix::fs::PermissionsExt};

use crate::gateway_directory::PinnedDirectory;

#[test]
fn pinned_directory_rejects_same_inode_mode_change() {
    let root = directory("mode");
    let pin = PinnedDirectory::open(&root).expect("pin");
    fs::set_permissions(&root, fs::Permissions::from_mode(0o777)).expect("chmod");
    assert!(pin.validate_source().is_err());
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("restore mode");
    fs::remove_dir(root).expect("cleanup");
}

#[test]
fn pinned_operations_never_follow_swap_and_restore() {
    let root = directory("swap");
    let moved = root.with_extension("moved");
    let pin = PinnedDirectory::open(&root).expect("pin");
    fs::rename(&root, &moved).expect("move protected directory");
    fs::create_dir(&root).expect("replacement");
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("replacement mode");
    assert!(pin.validate_source().is_err());
    fs::write(pin.path().join("pinned"), b"original").expect("fd-relative write");
    assert!(!root.join("pinned").exists());
    assert_eq!(
        fs::read(moved.join("pinned")).expect("original"),
        b"original"
    );
    fs::remove_dir(&root).expect("remove replacement");
    fs::rename(&moved, &root).expect("restore source");
    pin.validate_source().expect("same original restored");
    fs::remove_dir_all(root).expect("cleanup");
}

fn directory(label: &str) -> std::path::PathBuf {
    let root = std::env::temp_dir().join(format!(
        "crowsi-pinned-directory-{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time")
            .as_nanos()
    ));
    fs::create_dir(&root).expect("directory");
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("mode");
    root
}
