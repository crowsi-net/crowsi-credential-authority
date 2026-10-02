use super::*;
use sha2::{Digest, Sha256};

#[test]
fn over_bound_and_nonconsecutive_retention_fail_closed() {
    let store = TemporaryStore::new("retention-count");
    let authority =
        initialize_file_authority_store(store.path(), store.anchor(), NOW_MS).expect("initialize");
    let state_history = store.root_path().join("state-history");
    let anchor_history = store.root_path().join("anchor-history");
    fs::create_dir(&state_history).expect("state history");
    fs::create_dir(&anchor_history).expect("anchor history");
    capture(store.path(), "authority-generation-", &state_history);
    capture(store.anchor(), "authority-anchor-", &anchor_history);
    for _ in 0..4 {
        authority.transact(|_| Ok(())).expect("advance store");
        capture(store.path(), "authority-generation-", &state_history);
        capture(store.anchor(), "authority-anchor-", &anchor_history);
    }
    drop(authority);
    restore(&state_history, store.path());
    restore(&anchor_history, store.anchor());
    assert!(FileAuthorityStore::open_anchored(store.path(), store.anchor()).is_err());

    let store = TemporaryStore::new("nonconsecutive");
    let authority =
        initialize_file_authority_store(store.path(), store.anchor(), NOW_MS).expect("initialize");
    for _ in 0..3 {
        authority.transact(|_| Ok(())).expect("advance store");
    }
    drop(authority);
    remove_revision(store.path(), "authority-generation-", 2);
    remove_revision(store.anchor(), "authority-anchor-", 2);
    assert!(FileAuthorityStore::open_anchored(store.path(), store.anchor()).is_err());
}

#[test]
fn duplicate_revision_with_a_distinct_content_digest_fails_closed() {
    let store = TemporaryStore::new("duplicate-revision");
    initialize_file_authority_store(store.path(), store.anchor(), NOW_MS).expect("initialize");
    let original = retained(store.path(), "authority-generation-");
    let mut wire = fs::read(original).expect("generation");
    wire.push(b'\n');
    let digest = hex::encode(Sha256::digest(&wire));
    let duplicate = store
        .path()
        .join(format!("authority-generation-{digest}.json"));
    fs::write(&duplicate, wire).expect("duplicate generation");
    fs::set_permissions(duplicate, fs::Permissions::from_mode(0o600)).expect("duplicate mode");
    assert!(FileAuthorityStore::open_anchored(store.path(), store.anchor()).is_err());
}

fn capture(directory: &Path, prefix: &str, history: &Path) {
    for entry in fs::read_dir(directory).expect("directory") {
        let entry = entry.expect("entry");
        if entry.file_name().to_string_lossy().starts_with(prefix) {
            let target = history.join(entry.file_name());
            fs::copy(entry.path(), &target).expect("capture record");
            fs::set_permissions(target, fs::Permissions::from_mode(0o600)).expect("history mode");
        }
    }
}

fn restore(history: &Path, directory: &Path) {
    for entry in fs::read_dir(history).expect("history") {
        let entry = entry.expect("entry");
        let target = directory.join(entry.file_name());
        if !target.exists() {
            fs::copy(entry.path(), &target).expect("restore record");
            fs::set_permissions(target, fs::Permissions::from_mode(0o600)).expect("record mode");
        }
    }
}

fn remove_revision(directory: &Path, prefix: &str, revision: u64) {
    let path = fs::read_dir(directory)
        .expect("directory")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .find(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with(prefix))
                && serde_json::from_slice::<serde_json::Value>(&fs::read(path).expect("record"))
                    .is_ok_and(|value| value["generation"] == revision)
        })
        .expect("retained revision");
    fs::remove_file(path).expect("remove retained revision");
}

fn retained(directory: &Path, prefix: &str) -> PathBuf {
    fs::read_dir(directory)
        .expect("directory")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .find(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with(prefix))
        })
        .expect("retained file")
}
