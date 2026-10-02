use super::*;

#[test]
fn writable_or_symlinked_ancestor_is_rejected() {
    let store = TemporaryStore::new("ancestor");
    let writable = store.root_path().join("writable-parent");
    let writable_state = writable.join("state");
    let writable_anchor = writable.join("anchor");
    fs::create_dir(&writable).expect("writable parent");
    fs::set_permissions(&writable, fs::Permissions::from_mode(0o770)).expect("writable mode");
    for path in [&writable_state, &writable_anchor] {
        fs::create_dir(path).expect("leaf");
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).expect("leaf mode");
    }
    assert!(initialize_file_authority_store(&writable_state, &writable_anchor, NOW_MS).is_err());

    let real = store.root_path().join("real-parent");
    let linked = store.root_path().join("linked-parent");
    fs::create_dir(&real).expect("real parent");
    fs::set_permissions(&real, fs::Permissions::from_mode(0o700)).expect("real mode");
    for name in ["state", "anchor"] {
        let path = real.join(name);
        fs::create_dir(&path).expect("real leaf");
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).expect("real leaf mode");
    }
    symlink(&real, &linked).expect("ancestor symlink");
    assert!(
        initialize_file_authority_store(linked.join("state"), linked.join("anchor"), NOW_MS)
            .is_err()
    );
}
