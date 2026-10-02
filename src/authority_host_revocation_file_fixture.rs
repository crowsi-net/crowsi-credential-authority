use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

pub struct TemporaryStore {
    root: PathBuf,
    state: PathBuf,
    anchor: PathBuf,
}

impl TemporaryStore {
    pub fn new() -> Self {
        let parent = fs::canonicalize(std::env::temp_dir()).expect("canonical temp root");
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        let root = parent.join(format!(
            "crowsi-host-revocation-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir(&root).expect("root");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("root mode");
        let state = root.join("state");
        let anchor = root.join("anchor");
        for value in [&state, &anchor] {
            fs::create_dir(value).expect("store directory");
            fs::set_permissions(value, fs::Permissions::from_mode(0o700)).expect("store mode");
        }
        Self {
            root,
            state,
            anchor,
        }
    }

    pub fn path(&self) -> &Path {
        &self.state
    }

    pub fn anchor(&self) -> &Path {
        &self.anchor
    }
}

impl Default for TemporaryStore {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for TemporaryStore {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}
