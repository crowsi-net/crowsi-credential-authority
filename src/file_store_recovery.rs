use crate::{
    AuthorityError,
    file_store_path::{PinnedDirectory, StorePaths},
    file_store_scan::{AnchorRecord, GenerationRecord, RawStore},
    file_store_validate::{self, LoadedStore},
};

pub(crate) fn load(paths: &StorePaths) -> Result<LoadedStore, AuthorityError> {
    for _ in 0..4 {
        let raw = crate::file_store_scan::raw(paths)?;
        if crate::file_store_head_recovery::repair(paths, &raw)?
            || discard_uncommitted(paths, &raw)?
        {
            continue;
        }
        if prune_obsolete(paths, &raw)? {
            continue;
        }
        return file_store_validate::committed(raw);
    }
    Err(AuthorityError::RollbackDetected)
}

fn discard_uncommitted(paths: &StorePaths, raw: &RawStore) -> Result<bool, AuthorityError> {
    if raw.state_head_wire != raw.anchor_head_wire {
        return Ok(false);
    }
    let next = raw.state_head.generation().saturating_add(1);
    if raw
        .generations
        .iter()
        .any(|record| record.envelope.generation > next)
        || raw
            .anchors
            .iter()
            .any(|record| record.anchor.generation() > next)
    {
        return Err(AuthorityError::RollbackDetected);
    }
    let generation = file_store_validate::generation(raw, next);
    let anchor = file_store_validate::anchor(raw, next);
    if generation.is_none() && anchor.is_none() {
        return Ok(false);
    }
    validate_extra(raw, generation, anchor)?;
    if let Some(record) = generation {
        remove(&paths.state, &record.name, None)?;
    }
    if let Some(record) = anchor {
        remove(&paths.anchor, &record.name, None)?;
    }
    Ok(true)
}

fn prune_obsolete(paths: &StorePaths, raw: &RawStore) -> Result<bool, AuthorityError> {
    if raw.state_head_wire != raw.anchor_head_wire {
        return Ok(false);
    }
    let retained = raw.state_head.generation().saturating_sub(2);
    let old_generation = raw
        .generations
        .iter()
        .find(|record| record.envelope.generation < retained);
    let old_anchor = raw
        .anchors
        .iter()
        .find(|record| record.anchor.generation() < retained);
    if old_generation.is_none() && old_anchor.is_none() {
        return Ok(false);
    }
    let obsolete = retained.saturating_sub(1);
    if old_generation.is_some_and(|record| record.envelope.generation != obsolete)
        || old_anchor.is_some_and(|record| record.anchor.generation() != obsolete)
    {
        return Err(AuthorityError::RollbackDetected);
    }
    if let (Some(generation), Some(anchor)) = (old_generation, old_anchor) {
        file_store_validate::pair(generation, anchor)?;
    }
    if let Some(record) = old_generation {
        remove(
            &paths.state,
            &record.name,
            Some(crate::file_store_failpoint::FileStoreFailpoint::StatePruned),
        )?;
    }
    if let Some(record) = old_anchor {
        remove(
            &paths.anchor,
            &record.name,
            Some(crate::file_store_failpoint::FileStoreFailpoint::AnchorPruned),
        )?;
    }
    Ok(true)
}

fn validate_extra(
    raw: &RawStore,
    generation: Option<&GenerationRecord>,
    anchor: Option<&AnchorRecord>,
) -> Result<(), AuthorityError> {
    if let Some(value) = generation
        && value.envelope.previous_digest != raw.state_head.state_digest()
    {
        return Err(AuthorityError::RollbackDetected);
    }
    if let Some(value) = anchor
        && value.anchor.previous_anchor_digest() != raw.state_head.anchor_digest()
    {
        return Err(AuthorityError::RollbackDetected);
    }
    if let (Some(generation), Some(anchor)) = (generation, anchor) {
        file_store_validate::pair(generation, anchor)?;
    }
    Ok(())
}

fn remove(
    root: &PinnedDirectory,
    name: &str,
    failpoint: Option<crate::file_store_failpoint::FileStoreFailpoint>,
) -> Result<(), AuthorityError> {
    crate::file_store_file::remove(root, name)?;
    if let Some(value) = failpoint {
        crate::file_store_failpoint::hit(value)?;
    }
    crate::file_store_file::sync(root)
}
