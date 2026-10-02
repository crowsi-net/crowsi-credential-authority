fn verify_response(
    config: &crate::host_config::VerifiedHostConfig,
    response: &crowsi_credential_authority_contracts::EndpointPreparedLookupResponseV1,
    request: &crowsi_credential_authority_contracts::EndpointPreparedLookupRequestV1,
    now: u64,
) -> Result<(), HostError> {
    crowsi_credential_authority_contracts::verify_endpoint_prepared_lookup_response_at(
        response,
        request,
        &config.document.management_projection_key_id,
        &config.document.management_projection_public_key_hex,
        now,
    )
    .map_err(|_| HostError::ResponseInvalid)
}
