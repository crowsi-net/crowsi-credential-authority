use crate::{
    AuthorityError,
    file_store_envelope::{digest_bytes, valid_digest},
};
use serde::{Deserialize, Serialize};

pub(crate) const HEAD_NAME: &str = "authority.head.json";
const HEAD_SCHEMA: &str = "crowsi-credential-authority-head-v2";
pub(crate) const MAX_HEAD_BYTES: usize = 4_096;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StoreHead {
    schema: String,
    store_id: String,
    generation: u64,
    state_digest: String,
    anchor_digest: String,
    previous_head_digest: String,
    digest: String,
}

#[derive(Serialize)]
struct HeadPayload<'a> {
    schema: &'a str,
    store_id: &'a str,
    generation: u64,
    state_digest: &'a str,
    anchor_digest: &'a str,
    previous_head_digest: &'a str,
}

impl StoreHead {
    pub(crate) fn seal(
        store_id: &str,
        generation: u64,
        state_digest: &str,
        anchor_digest: &str,
        previous_head_digest: &str,
    ) -> Result<Self, AuthorityError> {
        let digest = calculate(
            store_id,
            generation,
            state_digest,
            anchor_digest,
            previous_head_digest,
        )?;
        Ok(Self {
            schema: HEAD_SCHEMA.to_owned(),
            store_id: store_id.to_owned(),
            generation,
            state_digest: state_digest.to_owned(),
            anchor_digest: anchor_digest.to_owned(),
            previous_head_digest: previous_head_digest.to_owned(),
            digest,
        })
    }

    pub(crate) fn decode(bytes: &[u8], store_id: &str) -> Result<Self, AuthorityError> {
        let value: Self =
            serde_json::from_slice(bytes).map_err(|_| AuthorityError::IntegrityViolation)?;
        let expected = calculate(
            &value.store_id,
            value.generation,
            &value.state_digest,
            &value.anchor_digest,
            &value.previous_head_digest,
        )?;
        let valid = value.schema == HEAD_SCHEMA
            && value.store_id == store_id
            && valid_digest(&value.digest)
            && value.digest == expected;
        valid
            .then_some(value)
            .ok_or(AuthorityError::IntegrityViolation)
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
    pub(crate) fn anchor_digest(&self) -> &str {
        &self.anchor_digest
    }
    pub(crate) fn previous_head_digest(&self) -> &str {
        &self.previous_head_digest
    }
    pub(crate) fn digest(&self) -> &str {
        &self.digest
    }
}

fn calculate(
    store_id: &str,
    generation: u64,
    state_digest: &str,
    anchor_digest: &str,
    previous_head_digest: &str,
) -> Result<String, AuthorityError> {
    if !crate::file_store_anchor::valid_store_id(store_id)
        || !valid_digest(state_digest)
        || !valid_digest(anchor_digest)
        || !valid_digest(previous_head_digest)
    {
        return Err(AuthorityError::IntegrityViolation);
    }
    let bytes = serde_json::to_vec(&HeadPayload {
        schema: HEAD_SCHEMA,
        store_id,
        generation,
        state_digest,
        anchor_digest,
        previous_head_digest,
    })
    .map_err(|_| AuthorityError::StoreUnavailable)?;
    Ok(digest_bytes(&bytes))
}
