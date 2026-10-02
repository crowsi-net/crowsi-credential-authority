use crate::{
    AuthorityError,
    file_store_head::{HEAD_NAME, StoreHead},
    file_store_path::StorePaths,
    file_store_scan::RawStore,
};

pub(crate) fn repair(paths: &StorePaths, raw: &RawStore) -> Result<bool, AuthorityError> {
    if raw.state_head_wire == raw.anchor_head_wire {
        return Ok(false);
    }
    let (forward, old, root, expected, wire) =
        if raw.state_head.generation() > raw.anchor_head.generation() {
            (
                &raw.state_head,
                &raw.anchor_head,
                &paths.anchor,
                &raw.anchor_head_wire,
                &raw.state_head_wire,
            )
        } else {
            (
                &raw.anchor_head,
                &raw.state_head,
                &paths.state,
                &raw.state_head_wire,
                &raw.anchor_head_wire,
            )
        };
    if forward.generation() == 0
        || forward.generation() != old.generation().saturating_add(1)
        || forward.previous_head_digest() != old.digest()
    {
        return Err(AuthorityError::RollbackDetected);
    }
    verify_pair(raw, forward)?;
    crate::file_store_atomic::replace(root, HEAD_NAME, "head-recovery", Some(expected), wire)?;
    Ok(true)
}

fn verify_pair(raw: &RawStore, head: &StoreHead) -> Result<(), AuthorityError> {
    let generation = crate::file_store_validate::generation(raw, head.generation())
        .ok_or(AuthorityError::RollbackDetected)?;
    let anchor = crate::file_store_validate::anchor(raw, head.generation())
        .ok_or(AuthorityError::RollbackDetected)?;
    crate::file_store_validate::pair(generation, anchor)?;
    if generation.digest == head.state_digest() && anchor.digest == head.anchor_digest() {
        Ok(())
    } else {
        Err(AuthorityError::RollbackDetected)
    }
}
