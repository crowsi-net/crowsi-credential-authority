use super::*;

pub(super) struct Verifier;
impl AssertionVerifier for Verifier {
    fn verify(&self, key_id: &str, payload: &[u8], signature: &str) -> bool {
        key_id == "ihat-key-01" && !payload.is_empty() && signature == "opaque-signature"
    }
}
impl IdentityAssertionVerifier for Verifier {
    fn expected_issuer(&self) -> &'static str {
        "ihat://identity-authority"
    }

    fn revocation_epochs_are_current(
        &self,
        _binding: &crowsi_credential_authority::DeviceIdentityBinding,
    ) -> bool {
        true
    }
}

impl ProviderEvidenceVerifier for Verifier {
    fn verify(&self, kind: ProviderEvidenceKind, payload: &[u8], signature: &str) -> bool {
        !payload.is_empty()
            && matches!(kind, ProviderEvidenceKind::UnknownOutcome)
            && signature == "provider-signature-over-unknown-outcome"
    }
}

impl OperationProofVerifier for Verifier {
    fn verify_step_up(&self, proof: &StepUpProof) -> bool {
        proof.authenticated_at_ms() <= NOW_MS && proof.expires_at_ms() >= NOW_MS
    }

    fn verify_target_key(&self, proof: &TargetKeyProof) -> bool {
        proof.issued_at_ms() <= NOW_MS
            && !proof.key_reference().is_empty()
            && !proof.nonce().is_empty()
    }
}

pub(super) struct OwnerMapper;
impl ServiceAccountOwnerMapper for OwnerMapper {
    fn map_owner(
        &self,
        _issuer: &str,
        _service_id: &crowsi_credential_authority::ServiceId,
        subject: &str,
    ) -> Result<crowsi_credential_authority::OpaqueOwnerRef, AuthorityError> {
        if subject.ends_with("0001") {
            Ok(owner_a())
        } else {
            Err(AuthorityError::WrongOwner)
        }
    }
}

pub(super) struct TemporaryStore {
    root: PathBuf,
    state: PathBuf,
    anchor: PathBuf,
}
impl TemporaryStore {
    pub(super) fn new(label: &str) -> Self {
        let parent = fs::canonicalize(std::env::temp_dir()).expect("canonical temp root");
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        let root = parent.join(format!(
            "crowsi-authority-{label}-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir(&root).expect("store root");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("root mode");
        let state = root.join("state");
        let anchor = root.join("anchor");
        for path in [&state, &anchor] {
            fs::create_dir(path).expect("store directory");
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).expect("store mode");
        }
        Self {
            root,
            state,
            anchor,
        }
    }
    pub(super) fn path(&self) -> &Path {
        &self.state
    }
    pub(super) fn anchor(&self) -> &Path {
        &self.anchor
    }
    pub(super) fn root_path(&self) -> &Path {
        &self.root
    }
}
impl Drop for TemporaryStore {
    fn drop(&mut self) {
        match fs::symlink_metadata(&self.root) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                let _ = fs::remove_file(&self.root);
            }
            Ok(_) => {
                let _ = fs::remove_dir_all(&self.root);
            }
            Err(_) => {}
        }
    }
}
