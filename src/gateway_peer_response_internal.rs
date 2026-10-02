use crate::host_config_types::HostConfigDocument;

pub(crate) fn current_mapping(
    trust: &HostConfigDocument,
    exchange: &crowsi_credential_authority_contracts::SignedAuthorityExchangeV1,
    owner_ref: &str,
    peer: &str,
) -> bool {
    let Ok(identity) =
        crowsi_credential_authority_contracts::identity_evidence_from_exchange(exchange)
    else {
        return false;
    };
    let assertion = &identity.assertion;
    assertion.device_id == peer
        && trust.owner_mappings.iter().any(|item| {
            item.issuer == assertion.issuer
                && item.service_id == assertion.service_id
                && item.pairwise_subject == assertion.pairwise_subject
                && item.opaque_owner_ref == owner_ref
        })
        && trust.device_proof_keys.iter().any(|item| {
            item.opaque_owner_ref == owner_ref
                && item.device_id == peer
                && item.device_proof_key_ref == assertion.device_proof_key_ref
        })
}
