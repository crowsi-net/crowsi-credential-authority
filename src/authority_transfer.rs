use crate::state::TransferRecord;
use crate::validation::{active_account, step_up, target_proof, ttl};
use crate::{
    AuthorityError, AuthorityStore, CredentialAuthority, DeviceGrant, GrantId, GrantState,
    TransferId, TransferReceipt, TransferRequest, TransferState,
};

impl<S: AuthorityStore> CredentialAuthority<S> {
    pub(crate) fn prepare_management_transfer(
        &self,
        mut request: TransferRequest,
        authorization_digest: &str,
        source_binding: &crate::transfer::ManagementDeviceBinding,
        target_binding: &crate::transfer::ManagementDeviceBinding,
    ) -> Result<TransferReceipt, AuthorityError> {
        if !management_digest(authorization_digest) {
            return Err(AuthorityError::IdentityAssertionInvalid);
        }
        let now = self.now_ms()?;
        request.step_up = crate::StepUpProof::verified(
            request.owner.clone(),
            request.source_device.clone(),
            now,
            now.saturating_add(request.ttl_ms),
        );
        request.target_proof = crate::TargetKeyProof::verified(
            request.owner.clone(),
            request.target_device.clone(),
            request.target_proof.key_thumbprint.clone(),
            request.target_proof.nonce.clone(),
            now,
        );
        self.prepare_transfer_internal(
            request,
            format!("management-source-approval:{authorization_digest}"),
            Some((source_binding, target_binding)),
        )
    }

    pub(crate) fn prepare_transfer_internal(
        &self,
        request: TransferRequest,
        identity_nonce: String,
        management_bindings: Option<(
            &crate::transfer::ManagementDeviceBinding,
            &crate::transfer::ManagementDeviceBinding,
        )>,
    ) -> Result<TransferReceipt, AuthorityError> {
        let now = self.now_ms()?;
        ttl(request.ttl_ms)?;
        self.store.transact(|snapshot| {
            prepare_transfer_snapshot(snapshot, request, identity_nonce, management_bindings, now)
        })
    }
}

include!("authority_transfer_snapshot.rs");
include!("authority_transfer_validation.rs");
include!("authority_transfer_insert.rs");

pub(crate) fn management_binding_current(
    snapshot: &crate::state::DurableSnapshot,
    owner: &crate::OpaqueOwnerRef,
    binding: &crate::transfer::ManagementDeviceBinding,
) -> bool {
    snapshot
        .devices
        .get(&(owner.clone(), binding.device_id.clone()))
        .is_some_and(|value| {
            !value.revoked
                && value.issuer == binding.issuer
                && value.service_id == binding.service_id
                && value.pairwise_subject_ref == binding.pairwise_subject
                && value.key_thumbprint == binding.device_proof_key_ref
                && value.posture_state == binding.posture_state
                && value.posture_revision == binding.posture_revision
                && value.subject_revocation_epoch == binding.subject_revocation_epoch
                && value.service_revocation_epoch == binding.service_revocation_epoch
                && value.epoch == binding.device_revocation_epoch
                && value.session_revocation_epoch == binding.session_revocation_epoch
                && value.key_id == binding.identity_key_id
        })
}

fn management_digest(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}
