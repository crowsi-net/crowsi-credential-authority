use crate::{AuthorityError, file_store_path::StorePaths};
use serde::{Deserialize, Serialize};

pub(crate) const STATE_MARKER: &str = "authority.state.marker.json";
pub(crate) const ANCHOR_MARKER: &str = "authority.anchor.marker.json";
const MARKER_SCHEMA: &str = "crowsi-credential-authority-store-binding-v2";
const MAX_MARKER_BYTES: usize = 1_024;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StoreMarker {
    schema: String,
    store_id: String,
    initial_clock_ms: u64,
    role: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct StoreBinding {
    pub store_id: String,
    pub initial_clock_ms: u64,
}

pub(crate) fn initialize_state(
    paths: &StorePaths,
    initial_clock_ms: u64,
) -> Result<StoreBinding, AuthorityError> {
    if initial_clock_ms == 0 {
        return Err(AuthorityError::IntegrityViolation);
    }
    let binding = StoreBinding {
        store_id: random_id()?,
        initial_clock_ms,
    };
    write_state(paths, &binding)?;
    Ok(binding)
}

pub(crate) fn write_state(
    paths: &StorePaths,
    binding: &StoreBinding,
) -> Result<(), AuthorityError> {
    paths.validate()?;
    write(&paths.state, STATE_MARKER, binding, "state")?;
    crate::file_store_file::sync(&paths.state)
}

pub(crate) fn write_anchor(
    paths: &StorePaths,
    binding: &StoreBinding,
) -> Result<(), AuthorityError> {
    paths.validate()?;
    write(&paths.anchor, ANCHOR_MARKER, binding, "anchor")?;
    crate::file_store_file::sync(&paths.anchor)
}

pub(crate) fn state(paths: &StorePaths) -> Result<Option<StoreBinding>, AuthorityError> {
    optional(&paths.state, STATE_MARKER, "state")
}

pub(crate) fn anchor(paths: &StorePaths) -> Result<Option<StoreBinding>, AuthorityError> {
    optional(&paths.anchor, ANCHOR_MARKER, "anchor")
}

pub(crate) fn verify(paths: &StorePaths) -> Result<StoreBinding, AuthorityError> {
    paths.validate()?;
    let state = read(&paths.state, STATE_MARKER, "state")?;
    let anchor = read(&paths.anchor, ANCHOR_MARKER, "anchor")?;
    if state == anchor {
        Ok(state)
    } else {
        Err(AuthorityError::RollbackDetected)
    }
}

fn write(
    root: &crate::file_store_path::PinnedDirectory,
    name: &str,
    binding: &StoreBinding,
    role: &str,
) -> Result<(), AuthorityError> {
    let bytes = serde_json::to_vec(&StoreMarker {
        schema: MARKER_SCHEMA.to_owned(),
        store_id: binding.store_id.clone(),
        initial_clock_ms: binding.initial_clock_ms,
        role: role.to_owned(),
    })
    .map_err(|_| AuthorityError::StoreUnavailable)?;
    crate::file_store_file::write_immutable(root, name, "marker", &bytes)
}

fn read(
    root: &crate::file_store_path::PinnedDirectory,
    name: &str,
    role: &str,
) -> Result<StoreBinding, AuthorityError> {
    let bytes = crate::file_store_file::read(root, name, MAX_MARKER_BYTES)
        .map_err(|_| AuthorityError::IntegrityViolation)?;
    let value: StoreMarker =
        serde_json::from_slice(&bytes).map_err(|_| AuthorityError::IntegrityViolation)?;
    if value.schema != MARKER_SCHEMA
        || value.role != role
        || !crate::file_store_anchor::valid_store_id(&value.store_id)
        || value.initial_clock_ms == 0
    {
        return Err(AuthorityError::IntegrityViolation);
    }
    Ok(StoreBinding {
        store_id: value.store_id,
        initial_clock_ms: value.initial_clock_ms,
    })
}

fn optional(
    root: &crate::file_store_path::PinnedDirectory,
    name: &str,
    role: &str,
) -> Result<Option<StoreBinding>, AuthorityError> {
    match std::fs::symlink_metadata(root.path().join(name)) {
        Ok(_) => read(root, name, role).map(Some),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(AuthorityError::StoreUnavailable),
    }
}

fn random_id() -> Result<String, AuthorityError> {
    let mut bytes = [0_u8; 32];
    getrandom::fill(&mut bytes).map_err(|_| AuthorityError::StoreUnavailable)?;
    Ok(hex::encode(bytes))
}
