use crate::{AuthorityError, file_store_envelope::valid_digest};
use serde::{Deserialize, Serialize};

pub(crate) const ANCHOR_SCHEMA: &str = "crowsi-credential-authority-anchor-v2";
pub(crate) const MAX_ANCHOR_BYTES: usize = 4_096;

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StoreAnchor {
    schema: String,
    store_id: String,
    generation: u64,
    state_digest: String,
    previous_anchor_digest: String,
}

impl StoreAnchor {
    pub(crate) fn new(
        store_id: &str,
        generation: u64,
        state_digest: &str,
        previous_anchor_digest: &str,
    ) -> Result<Self, AuthorityError> {
        if !valid_store_id(store_id)
            || !valid_digest(state_digest)
            || !valid_digest(previous_anchor_digest)
        {
            return Err(AuthorityError::IntegrityViolation);
        }
        Ok(Self {
            schema: ANCHOR_SCHEMA.to_owned(),
            store_id: store_id.to_owned(),
            generation,
            state_digest: state_digest.to_owned(),
            previous_anchor_digest: previous_anchor_digest.to_owned(),
        })
    }

    pub(crate) fn decode(bytes: &[u8], store_id: &str) -> Result<Self, AuthorityError> {
        let value: Self =
            serde_json::from_slice(bytes).map_err(|_| AuthorityError::IntegrityViolation)?;
        if value.schema != ANCHOR_SCHEMA
            || value.store_id != store_id
            || !valid_store_id(&value.store_id)
            || !valid_digest(&value.state_digest)
            || !valid_digest(&value.previous_anchor_digest)
        {
            return Err(AuthorityError::IntegrityViolation);
        }
        Ok(value)
    }

    pub(crate) fn encode(&self) -> Result<Vec<u8>, AuthorityError> {
        serde_json::to_vec(self).map_err(|_| AuthorityError::StoreUnavailable)
    }

    pub(crate) const fn generation(&self) -> u64 {
        self.generation
    }

    pub(crate) fn state_digest(&self) -> &str {
        &self.state_digest
    }

    pub(crate) fn previous_anchor_digest(&self) -> &str {
        &self.previous_anchor_digest
    }
}

pub(crate) fn valid_store_id(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}
