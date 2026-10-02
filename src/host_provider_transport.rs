use crate::{
    HostError, ProviderEvidenceDocumentV1, host_config_types::HostProviderRoute,
    host_provider_process, host_provider_request::ProviderOperationRequest,
};

pub(crate) struct ProviderOperationTransport<'a> {
    route: &'a HostProviderRoute,
}

impl<'a> ProviderOperationTransport<'a> {
    pub(crate) const fn new(route: &'a HostProviderRoute) -> Self {
        Self { route }
    }

    pub(crate) fn reissue(
        &self,
        operation: &str,
        owner: &str,
        credential: &str,
        target: &str,
        nonce: &str,
    ) -> Result<ProviderEvidenceDocumentV1, HostError> {
        let request = ProviderOperationRequest::reissue(
            operation,
            owner,
            &self.route.service_id,
            credential,
            target,
            nonce,
        );
        self.exchange("reissue", &request)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn reconcile(
        &self,
        operation: &str,
        owner: &str,
        credential: &str,
        target: &str,
        nonce: &str,
        prior_operation: &str,
        prior_nonce: &str,
    ) -> Result<ProviderEvidenceDocumentV1, HostError> {
        let request = ProviderOperationRequest::reconcile(
            operation,
            owner,
            &self.route.service_id,
            credential,
            target,
            nonce,
            prior_operation,
            prior_nonce,
        );
        self.exchange("reconcile", &request)
    }

    fn exchange(
        &self,
        command: &str,
        request: &ProviderOperationRequest<'_>,
    ) -> Result<ProviderEvidenceDocumentV1, HostError> {
        let wire = serde_json::to_vec(request).map_err(|_| HostError::EvidenceInvalid)?;
        if wire.len() > 16_384 {
            return Err(HostError::EvidenceInvalid);
        }
        let response = host_provider_process::exchange(self.route, command, &wire)?;
        let value: ProviderEvidenceDocumentV1 =
            serde_json::from_slice(&response).map_err(|_| HostError::EvidenceInvalid)?;
        if value.key_id != self.route.response_key_id {
            return Err(HostError::EvidenceInvalid);
        }
        Ok(value)
    }
}
