use crate::{
    AuthorityError,
    file_store_envelope::ZERO_DIGEST,
    file_store_scan::{AnchorRecord, GenerationRecord},
};
use std::collections::BTreeMap;

pub(crate) fn validate(
    generations: &BTreeMap<u64, &GenerationRecord>,
    anchors: &BTreeMap<u64, &AnchorRecord>,
    first: u64,
    last: u64,
) -> Result<(), AuthorityError> {
    if first == 0 {
        let generation = generations
            .get(&first)
            .ok_or(AuthorityError::RollbackDetected)?;
        let anchor = anchors
            .get(&first)
            .ok_or(AuthorityError::RollbackDetected)?;
        if generation.envelope.previous_digest != ZERO_DIGEST
            || anchor.anchor.previous_anchor_digest() != ZERO_DIGEST
        {
            return Err(AuthorityError::IntegrityViolation);
        }
    }
    for revision in first.saturating_add(1)..=last {
        let prior = revision - 1;
        let generation = generations
            .get(&revision)
            .ok_or(AuthorityError::RollbackDetected)?;
        let prior_generation = generations
            .get(&prior)
            .ok_or(AuthorityError::RollbackDetected)?;
        let anchor = anchors
            .get(&revision)
            .ok_or(AuthorityError::RollbackDetected)?;
        let prior_anchor = anchors
            .get(&prior)
            .ok_or(AuthorityError::RollbackDetected)?;
        if generation.envelope.previous_digest != prior_generation.digest
            || anchor.anchor.previous_anchor_digest() != prior_anchor.digest
        {
            return Err(AuthorityError::RollbackDetected);
        }
    }
    Ok(())
}
