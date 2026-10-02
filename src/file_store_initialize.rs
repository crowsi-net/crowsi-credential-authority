use crate::{
    AuthorityError, DurableSnapshot,
    file_store_anchor::{MAX_ANCHOR_BYTES, StoreAnchor},
    file_store_envelope::{MAX_STORE_BYTES, StoreEnvelope, ZERO_DIGEST},
    file_store_failpoint::{FileStoreFailpoint, hit},
    file_store_head::{HEAD_NAME, MAX_HEAD_BYTES, StoreHead},
    file_store_lock::LOCK_NAME,
    file_store_marker::{ANCHOR_MARKER, STATE_MARKER},
    file_store_path::StorePaths,
};

pub(crate) fn initialize(paths: &StorePaths, initial_clock_ms: u64) -> Result<(), AuthorityError> {
    let binding = binding(paths, initial_clock_ms)?;
    if crate::file_store_init_head::both_present(paths)? {
        return crate::file_store_recovery::load(paths).map(|_| ());
    }
    let snapshot = DurableSnapshot::empty(initial_clock_ms);
    let envelope = StoreEnvelope::seal(&snapshot, ZERO_DIGEST)?;
    let generation_wire =
        serde_json::to_vec(&envelope).map_err(|_| AuthorityError::StoreUnavailable)?;
    bounded(&generation_wire, MAX_STORE_BYTES)?;
    let state_digest = crate::file_store_envelope::digest_bytes(&generation_wire);
    let generation_name = crate::file_store_codec::generation_name(&state_digest);
    let anchor = StoreAnchor::new(&binding.store_id, 0, &state_digest, ZERO_DIGEST)?;
    let anchor_wire = anchor.encode()?;
    bounded(&anchor_wire, MAX_ANCHOR_BYTES)?;
    let anchor_digest = crate::file_store_envelope::digest_bytes(&anchor_wire);
    let anchor_name = crate::file_store_codec::anchor_name(&anchor_digest);
    allowed(paths, &generation_name, &anchor_name)?;
    let generation_present = crate::file_store_init_head::present(&paths.state, &generation_name)?;
    let anchor_present = crate::file_store_init_head::present(&paths.anchor, &anchor_name)?;
    if anchor_present && !generation_present {
        return Err(AuthorityError::IntegrityViolation);
    }
    write_generation(paths, &generation_name, &generation_wire)?;
    write_anchor(paths, &anchor_name, &anchor_wire)?;
    let head = StoreHead::seal(
        &binding.store_id,
        0,
        &state_digest,
        &anchor_digest,
        ZERO_DIGEST,
    )?;
    let head_wire = head.encode()?;
    bounded(&head_wire, MAX_HEAD_BYTES)?;
    crate::file_store_init_head::write(paths, &head_wire)?;
    crate::file_store_recovery::load(paths).map(|_| ())
}

fn binding(
    paths: &StorePaths,
    initial_clock_ms: u64,
) -> Result<crate::file_store_marker::StoreBinding, AuthorityError> {
    let state = crate::file_store_marker::state(paths)?;
    let anchor = crate::file_store_marker::anchor(paths)?;
    match (state, anchor) {
        (None, None) if crate::file_store_scan::pristine(paths)? => {
            let binding = crate::file_store_marker::initialize_state(paths, initial_clock_ms)?;
            hit(FileStoreFailpoint::StateMarkerWritten)?;
            crate::file_store_marker::write_anchor(paths, &binding)?;
            hit(FileStoreFailpoint::AnchorMarkerWritten)?;
            Ok(binding)
        }
        (Some(binding), None)
            if marker_only(paths)? && binding.initial_clock_ms == initial_clock_ms =>
        {
            crate::file_store_marker::write_anchor(paths, &binding)?;
            hit(FileStoreFailpoint::AnchorMarkerWritten)?;
            Ok(binding)
        }
        (Some(state), Some(anchor))
            if state == anchor && state.initial_clock_ms == initial_clock_ms =>
        {
            Ok(state)
        }
        _ => Err(AuthorityError::IntegrityViolation),
    }
}

fn marker_only(paths: &StorePaths) -> Result<bool, AuthorityError> {
    Ok(
        crate::file_store_inventory::names(&paths.state)? == [LOCK_NAME, STATE_MARKER]
            && crate::file_store_inventory::names(&paths.anchor)?.is_empty(),
    )
}

fn allowed(paths: &StorePaths, generation: &str, anchor: &str) -> Result<(), AuthorityError> {
    let state_allowed = [LOCK_NAME, STATE_MARKER, HEAD_NAME, generation];
    let anchor_allowed = [ANCHOR_MARKER, HEAD_NAME, anchor];
    let valid = crate::file_store_inventory::names(&paths.state)?
        .iter()
        .all(|name| state_allowed.contains(&name.as_str()))
        && crate::file_store_inventory::names(&paths.anchor)?
            .iter()
            .all(|name| anchor_allowed.contains(&name.as_str()));
    valid
        .then_some(())
        .ok_or(AuthorityError::IntegrityViolation)
}

fn write_generation(paths: &StorePaths, name: &str, wire: &[u8]) -> Result<(), AuthorityError> {
    if crate::file_store_init_head::head_present(paths)?
        && !crate::file_store_init_head::present(&paths.state, name)?
    {
        return Err(AuthorityError::IntegrityViolation);
    }
    crate::file_store_file::write_immutable(&paths.state, name, "generation", wire)?;
    hit(FileStoreFailpoint::GenerationWritten)?;
    crate::file_store_file::sync(&paths.state)?;
    hit(FileStoreFailpoint::GenerationSynced)
}

fn write_anchor(paths: &StorePaths, name: &str, wire: &[u8]) -> Result<(), AuthorityError> {
    if crate::file_store_init_head::head_present(paths)?
        && !crate::file_store_init_head::present(&paths.anchor, name)?
    {
        return Err(AuthorityError::IntegrityViolation);
    }
    crate::file_store_file::write_immutable(&paths.anchor, name, "anchor", wire)?;
    hit(FileStoreFailpoint::AnchorWritten)?;
    crate::file_store_file::sync(&paths.anchor)?;
    hit(FileStoreFailpoint::AnchorSynced)
}

fn bounded(bytes: &[u8], maximum: usize) -> Result<(), AuthorityError> {
    (!bytes.is_empty() && bytes.len() <= maximum)
        .then_some(())
        .ok_or(AuthorityError::SnapshotTooLarge)
}
