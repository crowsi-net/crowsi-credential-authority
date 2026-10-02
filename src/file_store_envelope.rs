use crate::file_store_wire::SnapshotWire;
use crate::{AuthorityError, DurableSnapshot};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub(crate) const STORE_SCHEMA: &str = "crowsi-credential-authority-store-v2";
pub(crate) const MAX_STORE_BYTES: usize = 4 * 1024 * 1024;
pub(crate) const ZERO_DIGEST: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StoreEnvelope {
    schema: String,
    generation: u64,
    previous_digest: String,
    snapshot: SnapshotWire,
    digest: String,
}

#[derive(Serialize)]
struct IntegrityPayload<'a> {
    schema: &'a str,
    generation: u64,
    previous_digest: &'a str,
    snapshot: &'a SnapshotWire,
}

impl StoreEnvelope {
    pub(crate) fn seal(
        snapshot: &DurableSnapshot,
        previous_digest: &str,
    ) -> Result<Self, AuthorityError> {
        if !valid_digest(previous_digest) {
            return Err(AuthorityError::IntegrityViolation);
        }
        let snapshot = SnapshotWire::from(snapshot);
        let digest = calculate(snapshot.version, previous_digest, &snapshot)?;
        Ok(Self {
            schema: STORE_SCHEMA.to_owned(),
            generation: snapshot.version,
            previous_digest: previous_digest.to_owned(),
            snapshot,
            digest,
        })
    }

    pub(crate) fn verify(self) -> Result<VerifiedEnvelope, AuthorityError> {
        if self.schema != STORE_SCHEMA
            || self.generation != self.snapshot.version
            || !valid_digest(&self.previous_digest)
            || !valid_digest(&self.digest)
        {
            return Err(AuthorityError::IntegrityViolation);
        }
        let expected = calculate(self.generation, &self.previous_digest, &self.snapshot)?;
        if !constant_time_eq(expected.as_bytes(), self.digest.as_bytes()) {
            return Err(AuthorityError::IntegrityViolation);
        }
        Ok(VerifiedEnvelope {
            generation: self.generation,
            previous_digest: self.previous_digest,
            snapshot: self.snapshot.into_snapshot()?,
        })
    }
}

pub(crate) struct VerifiedEnvelope {
    pub generation: u64,
    pub previous_digest: String,
    pub snapshot: DurableSnapshot,
}

pub(crate) fn digest_bytes(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

pub(crate) fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn calculate(
    generation: u64,
    previous: &str,
    snapshot: &SnapshotWire,
) -> Result<String, AuthorityError> {
    let bytes = serde_json::to_vec(&IntegrityPayload {
        schema: STORE_SCHEMA,
        generation,
        previous_digest: previous,
        snapshot,
    })
    .map_err(|_| AuthorityError::StoreUnavailable)?;
    Ok(digest_bytes(&bytes))
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0_u8, |diff, (a, b)| diff | (a ^ b))
        == 0
}
