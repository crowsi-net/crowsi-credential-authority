use super::*;

#[test]
fn file_store_detects_generation_tampering_and_one_sided_head_rollback() {
    let tampered = TemporaryStore::new("tamper");
    let _authority = provision(&tampered);
    let generation = newest(tampered.path(), "authority-generation-");
    let text = fs::read_to_string(&generation).expect("generation");
    let changed = text.replacen("github-api", "github-apx", 1);
    assert_ne!(changed, text);
    fs::write(&generation, changed).expect("tamper fixture");
    assert!(FileAuthorityStore::open_anchored(tampered.path(), tampered.anchor()).is_err());

    let rolled_back = TemporaryStore::new("one-sided-head");
    let mut authority = provision(&rolled_back);
    let old_head = fs::read(rolled_back.path().join("authority.head.json")).expect("old head");
    let (request, wire) = grant_request("rollback-generation");
    authority
        .issue_device_grant_from_assertion(request, &wire, &Verifier, &OwnerMapper)
        .expect("advance generation");
    let committed_head =
        fs::read(rolled_back.anchor().join("authority.head.json")).expect("committed head");
    fs::write(rolled_back.path().join("authority.head.json"), old_head)
        .expect("rollback state head");
    FileAuthorityStore::open_anchored(rolled_back.path(), rolled_back.anchor())
        .expect("forward-repair one stale head");
    assert_eq!(
        fs::read(rolled_back.path().join("authority.head.json")).expect("repaired head"),
        committed_head
    );
}

#[test]
fn file_store_rejects_relative_symlink_and_non_owner_only_paths() {
    let valid = TemporaryStore::new("valid-anchor");
    assert!(matches!(
        FileAuthorityStore::open_anchored(Path::new("relative-authority-store"), valid.anchor()),
        Err(AuthorityError::StorePathInvalid)
    ));

    let real = TemporaryStore::new("real-path");
    let link = real.root_path().join("state-link");
    symlink(real.path(), &link).expect("symlink fixture");
    assert!(matches!(
        FileAuthorityStore::open_anchored(&link, real.anchor()),
        Err(AuthorityError::StorePathInvalid)
    ));

    let permissive = TemporaryStore::new("permissive-path");
    fs::set_permissions(permissive.path(), fs::Permissions::from_mode(0o755))
        .expect("permissive mode");
    assert!(matches!(
        FileAuthorityStore::open_anchored(permissive.path(), permissive.anchor()),
        Err(AuthorityError::StorePathInvalid)
    ));
}

fn newest(directory: &Path, prefix: &str) -> PathBuf {
    fs::read_dir(directory)
        .expect("directory")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with(prefix))
        })
        .max_by_key(|path| {
            fs::metadata(path)
                .expect("metadata")
                .modified()
                .expect("mtime")
        })
        .expect("retained file")
}
