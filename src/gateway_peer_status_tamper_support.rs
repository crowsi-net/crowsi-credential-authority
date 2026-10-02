fn directories() -> (PathBuf, PathBuf, PathBuf) {
    let root = std::env::temp_dir().join(format!(
        "crowsi-peer-tamper-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let state = root.join("state");
    let anchor = root.join("anchor");
    for path in [&root, &state, &anchor] {
        fs::create_dir(path).expect("directory");
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).expect("mode");
    }
    (root, state, anchor)
}

fn owner_file(path: &Path, wire: &[u8]) {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .expect("owner file");
    file.write_all(wire).expect("wire");
}

fn entries(root: &Path) -> Vec<PathBuf> {
    let mut values = fs::read_dir(root)
        .expect("read directory")
        .map(|item| item.expect("entry").path())
        .filter(|item| {
            let not_initialized = item
                .file_name()
                .and_then(|value| value.to_str())
                .is_some_and(|value| !value.contains("initialized"));
            let not_lock = item
                .extension()
                .is_none_or(|extension| !extension.eq_ignore_ascii_case("lock"));
            not_initialized && not_lock
        })
        .collect::<Vec<_>>();
    values.sort();
    values
}

fn peers() -> Vec<GatewayPeerDocument> {
    vec![GatewayPeerDocument {
        device_id: "device-a".into(),
        certificate_der_hex: "00".into(),
        certificate_sha256: format!("sha256:{}", "a".repeat(64)),
        request_key_id: "request-a".into(),
        request_public_key_hex: "b".repeat(64),
    }]
}
