use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::HostError;

pub(crate) fn canonical(domain: &str, value: &Value) -> Result<Vec<u8>, HostError> {
    let mut unsigned = value.clone();
    unsigned
        .as_object_mut()
        .ok_or(HostError::ConfigInvalid)?
        .remove("signature");
    let body = serde_json::to_vec(&unsigned).map_err(|_| HostError::ConfigInvalid)?;
    Ok([
        domain.as_bytes(),
        b"\n",
        body.len().to_string().as_bytes(),
        b"\n",
        &body,
    ]
    .concat())
}

pub(crate) fn verify(public_hex: &str, signature_hex: &str, payload: &[u8]) -> bool {
    let Ok(public): Result<[u8; 32], _> = hex::decode(public_hex).and_then(|value| {
        value
            .try_into()
            .map_err(|_| hex::FromHexError::InvalidStringLength)
    }) else {
        return false;
    };
    let Ok(signature) = hex::decode(signature_hex) else {
        return false;
    };
    let Ok(key) = VerifyingKey::from_bytes(&public) else {
        return false;
    };
    let Ok(signature) = Signature::try_from(signature.as_slice()) else {
        return false;
    };
    key.verify(payload, &signature).is_ok()
}

pub(crate) fn signing_key(value: &str) -> Result<SigningKey, HostError> {
    let bytes: [u8; 32] = hex::decode(value)
        .map_err(|_| HostError::ConfigInvalid)?
        .try_into()
        .map_err(|_| HostError::ConfigInvalid)?;
    Ok(SigningKey::from_bytes(&bytes))
}

pub(crate) fn sign(key: &SigningKey, payload: &[u8]) -> String {
    hex::encode(key.sign(payload).to_bytes())
}

pub(crate) fn digest(value: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(value))
}

pub(crate) fn provider_payload(kind: &str, payload: &[u8]) -> Vec<u8> {
    [
        b"CROWSI-PROVIDER-EVIDENCE-V1\n".as_slice(),
        kind.as_bytes(),
        b"\n",
        payload.len().to_string().as_bytes(),
        b"\n",
        payload,
    ]
    .concat()
}
