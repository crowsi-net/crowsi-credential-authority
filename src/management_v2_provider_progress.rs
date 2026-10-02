use crate::{HostError, management_v2_provider_acceptance::ProviderEvidenceAcceptanceV1};

const RETAINED: usize = 8;

pub(crate) fn empty_digest(kind: &str) -> String {
    crate::host_crypto::digest(format!("CROWSI-PROVIDER-HISTORY-V1\0{kind}\0empty").as_bytes())
}

pub(crate) fn append(
    kind: &str,
    values: &mut Vec<ProviderEvidenceAcceptanceV1>,
    count: &mut u64,
    digest: &mut String,
    value: ProviderEvidenceAcceptanceV1,
) -> Result<(), HostError> {
    let wire = serde_json::to_vec(&value).map_err(|_| HostError::StateInvalid)?;
    let mut payload = format!("CROWSI-PROVIDER-HISTORY-V1\0{kind}\0{digest}\0").into_bytes();
    payload.extend_from_slice(&wire);
    *digest = crate::host_crypto::digest(&payload);
    *count = count.checked_add(1).ok_or(HostError::StateInvalid)?;
    if values.len() == RETAINED {
        values.remove(0);
    }
    values.push(value);
    Ok(())
}

pub(crate) fn valid(
    kind: &str,
    values: &[ProviderEvidenceAcceptanceV1],
    count: u64,
    digest: &str,
) -> bool {
    if values.len() > RETAINED || count < values.len() as u64 {
        return false;
    }
    if count == 0 {
        return values.is_empty() && digest == empty_digest(kind);
    }
    valid_digest(digest) && digest != empty_digest(kind)
}

pub(crate) fn transfer_reconcile_request(operation_id: &str, sequence: u64) -> String {
    let digest = crate::host_crypto::digest(
        format!("CROWSI-TRANSFER-RECONCILE-V1\0{operation_id}\0{sequence}").as_bytes(),
    );
    format!("request-{}", digest.trim_start_matches("sha256:"))
}

fn valid_digest(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
