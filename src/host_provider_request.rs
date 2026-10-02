use serde::Serialize;

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProviderOperationRequest<'a> {
    pub schema: &'static str,
    pub command: &'a str,
    pub operation_id: &'a str,
    pub owner_ref: &'a str,
    pub service_id: &'a str,
    pub credential_ref: &'a str,
    pub target_device_ref: &'a str,
    pub target_nonce: &'a str,
    pub prior_operation_ref: Option<&'a str>,
    pub prior_nonce: Option<&'a str>,
    pub contains_secret_values: bool,
}

impl<'a> ProviderOperationRequest<'a> {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn reissue(
        operation: &'a str,
        owner: &'a str,
        service: &'a str,
        credential: &'a str,
        target: &'a str,
        nonce: &'a str,
    ) -> Self {
        Self {
            schema: schema(),
            command: "reissue",
            operation_id: operation,
            owner_ref: owner,
            service_id: service,
            credential_ref: credential,
            target_device_ref: target,
            target_nonce: nonce,
            prior_operation_ref: None,
            prior_nonce: None,
            contains_secret_values: false,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn reconcile(
        operation: &'a str,
        owner: &'a str,
        service: &'a str,
        credential: &'a str,
        target: &'a str,
        nonce: &'a str,
        prior_operation: &'a str,
        prior_nonce: &'a str,
    ) -> Self {
        Self {
            schema: schema(),
            command: "reconcile",
            operation_id: operation,
            owner_ref: owner,
            service_id: service,
            credential_ref: credential,
            target_device_ref: target,
            target_nonce: nonce,
            prior_operation_ref: Some(prior_operation),
            prior_nonce: Some(prior_nonce),
            contains_secret_values: false,
        }
    }
}

fn schema() -> &'static str {
    "crowsi://credential-authority/provider-operation-request/v1"
}
