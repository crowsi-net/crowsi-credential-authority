use super::*;

#[test]
fn partial_pair_anchor_tamper_unknown_and_all_missing_fail_closed() {
    for attack in [
        "partial",
        "anchor-tamper",
        "unknown",
        "lock-missing",
        "all-missing",
    ] {
        let store = TemporaryStore::new(attack);
        initialize_file_authority_store(store.path(), store.anchor(), NOW_MS).expect("initialize");
        match attack {
            "partial" => fs::remove_file(retained(store.anchor(), "authority-anchor-"))
                .expect("remove anchor"),
            "anchor-tamper" => {
                let anchor = retained(store.anchor(), "authority-anchor-");
                let mut wire = fs::read(&anchor).expect("anchor");
                wire.push(b'\n');
                fs::write(anchor, wire).expect("raw-byte anchor tamper");
            }
            "unknown" => {
                fs::write(store.path().join("unexpected.json"), b"{}").expect("unknown file");
            }
            "lock-missing" => {
                fs::remove_file(store.path().join("authority.lock")).expect("remove lock");
            }
            "all-missing" => {
                clear(store.path());
                clear(store.anchor());
            }
            _ => unreachable!(),
        }
        assert!(FileAuthorityStore::open_anchored(store.path(), store.anchor()).is_err());
        if attack == "lock-missing" {
            assert!(!store.path().join("authority.lock").exists());
        }
    }
}

#[test]
fn coherent_dual_directory_rollback_is_an_external_witness_boundary() {
    let store = TemporaryStore::new("coherent-boundary");
    let authority =
        initialize_file_authority_store(store.path(), store.anchor(), NOW_MS).expect("initialize");
    authority.transact(|_| Ok(())).expect("old committed state");
    drop(authority);
    let old_head = fs::read(store.path().join("authority.head.json")).expect("old head");
    let old_state = store.root_path().join("old-state");
    let old_anchor = store.root_path().join("old-anchor");
    copy_directory(store.path(), &old_state);
    copy_directory(store.anchor(), &old_anchor);

    let current = FileAuthorityStore::open_anchored(store.path(), store.anchor()).expect("open");
    current.transact(|_| Ok(())).expect("new generation one");
    current.transact(|_| Ok(())).expect("new generation two");
    drop(current);
    fs::remove_dir_all(store.path()).expect("remove current state");
    fs::remove_dir_all(store.anchor()).expect("remove current anchor");
    fs::rename(old_state, store.path()).expect("restore old state");
    fs::rename(old_anchor, store.anchor()).expect("restore old anchor");

    FileAuthorityStore::open_anchored(store.path(), store.anchor())
        .expect("local pair is internally coherent");
    assert_eq!(
        fs::read(store.path().join("authority.head.json")).expect("restored head"),
        old_head,
        "gateway peer-head/ledger composition must reject this older authority revision"
    );
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

fn clear(directory: &Path) {
    for entry in fs::read_dir(directory).expect("directory") {
        fs::remove_file(entry.expect("entry").path()).expect("remove store file");
    }
}

fn copy_directory(source: &Path, destination: &Path) {
    fs::create_dir(destination).expect("backup directory");
    fs::set_permissions(destination, fs::Permissions::from_mode(0o700)).expect("backup mode");
    for entry in fs::read_dir(source).expect("source") {
        let entry = entry.expect("entry");
        let target = destination.join(entry.file_name());
        fs::copy(entry.path(), &target).expect("copy file");
        fs::set_permissions(target, fs::Permissions::from_mode(0o600)).expect("copy mode");
    }
}
