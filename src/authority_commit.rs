use crate::grant_promotion::promote_to_target_identity;
use crate::validation::target_proof;
use crate::{
    AuthorityError, AuthorityStore, CommitFailPoint, CredentialAuthority, GrantState,
    ProviderEvidenceVerifier, TransferAcceptance, TransferReceipt, TransferState,
};

impl<S: AuthorityStore> CredentialAuthority<S> {
    #[cfg(feature = "test-support")]
    pub fn accept_transfer<V: ProviderEvidenceVerifier>(
        &mut self,
        acceptance: TransferAcceptance,
        verifier: &V,
    ) -> Result<TransferReceipt, AuthorityError> {
        self.accept_transfer_internal(acceptance, verifier, None)
    }

    pub(crate) fn accept_management_transfer<V: ProviderEvidenceVerifier>(
        &mut self,
        acceptance: TransferAcceptance,
        verifier: &V,
        authorization_digest: &str,
    ) -> Result<TransferReceipt, AuthorityError> {
        if !management_digest(authorization_digest) {
            return Err(AuthorityError::IdentityAssertionInvalid);
        }
        self.accept_transfer_internal(acceptance, verifier, Some(authorization_digest))
    }

    fn accept_transfer_internal<V: ProviderEvidenceVerifier>(
        &mut self,
        mut acceptance: TransferAcceptance,
        verifier: &V,
        management_authorization: Option<&str>,
    ) -> Result<TransferReceipt, AuthorityError> {
        let now = self.now_ms()?;
        if management_authorization.is_some() {
            acceptance.target_proof = crate::TargetKeyProof::verified(
                acceptance.owner.clone(),
                acceptance.target_device.clone(),
                acceptance.target_proof.key_thumbprint.clone(),
                acceptance.target_proof.nonce.clone(),
                now,
            );
        }
        let fail_point = self.fail_point.take();
        self.store.transact(|snapshot| {
            Self::accept_transfer_snapshot(
                snapshot,
                acceptance,
                verifier,
                management_authorization,
                now,
                fail_point,
            )
        })
    }
}

include!("authority_commit_validation.rs");
include!("authority_commit_apply.rs");

fn management_digest(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}
