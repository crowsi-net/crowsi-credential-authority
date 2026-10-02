use ed25519_dalek::{Signer, SigningKey};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

pub(crate) struct Fixture {
    pub(crate) root: PathBuf,
    pub(crate) store: PathBuf,
    pub(crate) authority_anchor: PathBuf,
    pub(crate) operations: PathBuf,
    pub(crate) management_state: PathBuf,
    pub(crate) provider_state: PathBuf,
    pub(crate) anchors: PathBuf,
    pub(crate) peer_state: PathBuf,
    pub(crate) peer_anchor: PathBuf,
    pub(crate) replay: PathBuf,
    pub(crate) replay_anchor: PathBuf,
    pub(crate) now: u64,
}

impl Fixture {
    pub(crate) fn new() -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let root = std::env::current_dir()
            .expect("current directory")
            .join("target")
            .join(format!("crowsi-real-host-{}-{nonce}", std::process::id()));
        directory(&root);
        let value = Self {
            store: root.join("store"),
            authority_anchor: root.join("authority-anchor"),
            operations: root.join("operations"),
            management_state: root.join("management-state"),
            provider_state: root.join("provider-state"),
            anchors: root.join("anchors"),
            peer_state: root.join("peer-state"),
            peer_anchor: root.join("peer-anchor"),
            replay: root.join("replay"),
            replay_anchor: root.join("replay-anchor"),
            root,
            now: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("time")
                .as_secs(),
        };
        for path in [
            &value.store,
            &value.authority_anchor,
            &value.operations,
            &value.management_state,
            &value.provider_state,
            &value.anchors,
            &value.peer_state,
            &value.peer_anchor,
            &value.replay,
            &value.replay_anchor,
        ] {
            directory(path);
        }
        value
    }

    pub(crate) fn path(&self, name: &str) -> PathBuf {
        self.root.join(name)
    }

    pub(crate) fn write(&self, name: &str, wire: &[u8]) -> PathBuf {
        let path = self.path(name);
        fs::write(&path, wire).expect("write");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("mode");
        path
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

pub(crate) fn key(value: u8) -> SigningKey {
    SigningKey::from_bytes(&[value; 32])
}

pub(crate) fn public(value: u8) -> String {
    hex::encode(key(value).verifying_key().to_bytes())
}

pub(crate) fn digest(value: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(value))
}

pub(crate) fn sign(domain: &str, value: &mut Value, key: &SigningKey) -> Vec<u8> {
    value["signature"] = Value::String(String::new());
    let mut unsigned = value.clone();
    unsigned
        .as_object_mut()
        .expect("object")
        .remove("signature");
    let body = serde_json::to_vec(&unsigned).expect("body");
    let payload = [
        domain.as_bytes(),
        b"\n",
        body.len().to_string().as_bytes(),
        b"\n",
        &body,
    ]
    .concat();
    value["signature"] = hex::encode(key.sign(&payload).to_bytes()).into();
    serde_json::to_vec(value).expect("signed wire")
}

fn directory(path: &Path) {
    fs::create_dir(path).expect("directory");
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).expect("mode");
}
