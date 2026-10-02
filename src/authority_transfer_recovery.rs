use crate::{
    AuthorityError, AuthorityStore, CredentialAuthority, CredentialId, DeviceId, OpaqueOwnerRef,
    ServiceId, TransferMechanism, TransferReceipt, transfer::ManagementDeviceBinding,
};

impl<S: AuthorityStore> CredentialAuthority<S> {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn recover_management_transfer(
        &self,
        owner: &OpaqueOwnerRef,
        credential: &CredentialId,
        service: &ServiceId,
        source: &DeviceId,
        target: &DeviceId,
        target_nonce: &str,
        authorization_digest: &str,
        source_binding: &ManagementDeviceBinding,
        target_binding: &ManagementDeviceBinding,
    ) -> Result<Option<TransferReceipt>, AuthorityError> {
        self.store.read(|snapshot| {
            let Some(value) = snapshot
                .transfers
                .values()
                .find(|item| item.target_nonce == target_nonce)
            else {
                return Ok(None);
            };
            if value.owner != *owner
                || value.credential_id != *credential
                || value.source_device != *source
                || value.target_device != *target
                || value.mechanism != TransferMechanism::ProviderReissue
                || value.identity_nonce
                    != format!("management-source-approval:{authorization_digest}")
                || value.management_source_binding.as_ref() != Some(source_binding)
                || value.management_target_binding.as_ref() != Some(target_binding)
            {
                return Err(AuthorityError::TargetKeyProofInvalid);
            }
            let credential_service = value
                .management_source_binding
                .as_ref()
                .is_some_and(|binding| binding.service_id == *service);
            if !credential_service {
                return Err(AuthorityError::TargetKeyProofInvalid);
            }
            Ok(Some(TransferReceipt {
                id: value.id.clone(),
                source_grant: value.source_grant.clone(),
                target_grant: value.target_grant.clone(),
                state: value.state,
                provider_revision: value.provider_revision,
            }))
        })
    }
}
