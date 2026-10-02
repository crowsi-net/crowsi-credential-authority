use crate::{
    AuthorityError, DurableSnapshot,
    file_store_anchor::{MAX_ANCHOR_BYTES, StoreAnchor},
    file_store_envelope::{MAX_STORE_BYTES, StoreEnvelope},
    file_store_head::{HEAD_NAME, MAX_HEAD_BYTES, StoreHead},
    file_store_path::StorePaths,
    file_store_validate::LoadedStore,
};

pub(crate) fn initialize(paths: &StorePaths, initial_clock_ms: u64) -> Result<(), AuthorityError> {
    crate::file_store_initialize::initialize(paths, initial_clock_ms)
}

pub(crate) fn load(paths: &StorePaths) -> Result<LoadedStore, AuthorityError> {
    crate::file_store_validate::committed(crate::file_store_scan::raw(paths)?)
}

pub(crate) fn recover(paths: &StorePaths) -> Result<LoadedStore, AuthorityError> {
    crate::file_store_recovery::load(paths)
}

pub(crate) fn persist(
    paths: &StorePaths,
    snapshot: &DurableSnapshot,
    previous_digest: &str,
) -> Result<String, AuthorityError> {
    let current = load(paths)?;
    if current.state_digest != previous_digest
        || snapshot.version != current.snapshot.version.saturating_add(1)
    {
        return Err(AuthorityError::RollbackDetected);
    }
    let envelope = StoreEnvelope::seal(snapshot, previous_digest)?;
    let envelope_wire = encode_bounded(&envelope, MAX_STORE_BYTES)?;
    let state_digest = crate::file_store_envelope::digest_bytes(&envelope_wire);
    crate::file_store_file::write_immutable(
        &paths.state,
        &generation_name(&state_digest),
        "generation",
        &envelope_wire,
    )?;
    crate::file_store_failpoint::hit(
        crate::file_store_failpoint::FileStoreFailpoint::GenerationWritten,
    )?;
    crate::file_store_file::sync(&paths.state)?;
    crate::file_store_failpoint::hit(
        crate::file_store_failpoint::FileStoreFailpoint::GenerationSynced,
    )?;
    let anchor = StoreAnchor::new(
        &current.store_id,
        snapshot.version,
        &state_digest,
        &current.anchor_digest,
    )?;
    let anchor_wire = anchor.encode()?;
    bounded(&anchor_wire, MAX_ANCHOR_BYTES)?;
    let anchor_digest = crate::file_store_envelope::digest_bytes(&anchor_wire);
    crate::file_store_file::write_immutable(
        &paths.anchor,
        &anchor_name(&anchor_digest),
        "anchor",
        &anchor_wire,
    )?;
    crate::file_store_failpoint::hit(
        crate::file_store_failpoint::FileStoreFailpoint::AnchorWritten,
    )?;
    crate::file_store_file::sync(&paths.anchor)?;
    crate::file_store_failpoint::hit(
        crate::file_store_failpoint::FileStoreFailpoint::AnchorSynced,
    )?;
    let head = StoreHead::seal(
        &current.store_id,
        snapshot.version,
        &state_digest,
        &anchor_digest,
        current.head.digest(),
    )?;
    let head_wire = head.encode()?;
    bounded(&head_wire, MAX_HEAD_BYTES)?;
    crate::file_store_atomic::replace(
        &paths.state,
        HEAD_NAME,
        "state-head",
        Some(&current.head_wire),
        &head_wire,
    )?;
    crate::file_store_failpoint::hit(
        crate::file_store_failpoint::FileStoreFailpoint::StateHeadWritten,
    )?;
    crate::file_store_atomic::replace(
        &paths.anchor,
        HEAD_NAME,
        "anchor-head",
        Some(&current.head_wire),
        &head_wire,
    )?;
    crate::file_store_failpoint::hit(
        crate::file_store_failpoint::FileStoreFailpoint::AnchorHeadWritten,
    )?;
    let loaded = recover(paths)?;
    if loaded.state_digest == state_digest {
        Ok(state_digest)
    } else {
        Err(AuthorityError::RollbackDetected)
    }
}

pub(crate) fn generation_name(digest: &str) -> String {
    format!("authority-generation-{digest}.json")
}

pub(crate) fn anchor_name(digest: &str) -> String {
    format!("authority-anchor-{digest}.json")
}

fn encode_bounded<T: serde::Serialize>(
    value: &T,
    maximum: usize,
) -> Result<Vec<u8>, AuthorityError> {
    let bytes = serde_json::to_vec(value).map_err(|_| AuthorityError::StoreUnavailable)?;
    bounded(&bytes, maximum)?;
    Ok(bytes)
}

fn bounded(bytes: &[u8], maximum: usize) -> Result<(), AuthorityError> {
    if bytes.is_empty() || bytes.len() > maximum {
        Err(AuthorityError::SnapshotTooLarge)
    } else {
        Ok(())
    }
}
