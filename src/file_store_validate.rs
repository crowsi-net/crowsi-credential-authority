use crate::{
    AuthorityError, DurableSnapshot,
    file_store_envelope::ZERO_DIGEST,
    file_store_head::StoreHead,
    file_store_scan::{AnchorRecord, GenerationRecord, MAX_RETAINED, RawStore},
};
use std::collections::{BTreeMap, BTreeSet};

pub(crate) struct LoadedStore {
    pub snapshot: DurableSnapshot,
    pub state_digest: String,
    pub anchor_digest: String,
    pub head: StoreHead,
    pub head_wire: Vec<u8>,
    pub store_id: String,
}

pub(crate) fn committed(raw: RawStore) -> Result<LoadedStore, AuthorityError> {
    if raw.state_head_wire != raw.anchor_head_wire
        || raw.state_head.digest() != raw.anchor_head.digest()
    {
        return Err(AuthorityError::RollbackDetected);
    }
    let generations = generation_map(&raw.generations)?;
    let anchors = anchor_map(&raw.anchors)?;
    let head = &raw.state_head;
    if head.generation() == 0 && head.previous_head_digest() != ZERO_DIGEST {
        return Err(AuthorityError::IntegrityViolation);
    }
    let expected_count = usize::try_from(head.generation().saturating_add(1))
        .unwrap_or(usize::MAX)
        .min(MAX_RETAINED);
    if generations.len() != expected_count || anchors.len() != expected_count {
        return Err(AuthorityError::RollbackDetected);
    }
    let first = head
        .generation()
        .saturating_sub(u64::try_from(expected_count - 1).unwrap_or(u64::MAX));
    for revision in first..=head.generation() {
        pair(
            generations
                .get(&revision)
                .ok_or(AuthorityError::RollbackDetected)?,
            anchors
                .get(&revision)
                .ok_or(AuthorityError::RollbackDetected)?,
        )?;
    }
    crate::file_store_chain::validate(&generations, &anchors, first, head.generation())?;
    let latest_generation = generations
        .get(&head.generation())
        .ok_or(AuthorityError::RollbackDetected)?;
    let latest_anchor = anchors
        .get(&head.generation())
        .ok_or(AuthorityError::RollbackDetected)?;
    if head.state_digest() != latest_generation.digest
        || head.anchor_digest() != latest_anchor.digest
    {
        return Err(AuthorityError::RollbackDetected);
    }
    Ok(LoadedStore {
        snapshot: latest_generation.envelope.snapshot.clone(),
        state_digest: latest_generation.digest.clone(),
        anchor_digest: latest_anchor.digest.clone(),
        head: raw.state_head,
        head_wire: raw.state_head_wire,
        store_id: raw.store_id,
    })
}

pub(crate) fn pair(
    generation: &GenerationRecord,
    anchor: &AnchorRecord,
) -> Result<(), AuthorityError> {
    if generation.envelope.generation == anchor.anchor.generation()
        && generation.digest == anchor.anchor.state_digest()
    {
        Ok(())
    } else {
        Err(AuthorityError::RollbackDetected)
    }
}

pub(crate) fn generation(raw: &RawStore, revision: u64) -> Option<&GenerationRecord> {
    raw.generations
        .iter()
        .find(|record| record.envelope.generation == revision)
}

pub(crate) fn anchor(raw: &RawStore, revision: u64) -> Option<&AnchorRecord> {
    raw.anchors
        .iter()
        .find(|record| record.anchor.generation() == revision)
}

fn generation_map(
    records: &[GenerationRecord],
) -> Result<BTreeMap<u64, &GenerationRecord>, AuthorityError> {
    let mut revisions = BTreeMap::new();
    let mut digests = BTreeSet::new();
    for record in records {
        if revisions
            .insert(record.envelope.generation, record)
            .is_some()
            || !digests.insert(&record.digest)
        {
            return Err(AuthorityError::IntegrityViolation);
        }
    }
    Ok(revisions)
}

fn anchor_map(records: &[AnchorRecord]) -> Result<BTreeMap<u64, &AnchorRecord>, AuthorityError> {
    let mut revisions = BTreeMap::new();
    let mut digests = BTreeSet::new();
    for record in records {
        if revisions
            .insert(record.anchor.generation(), record)
            .is_some()
            || !digests.insert(&record.digest)
        {
            return Err(AuthorityError::IntegrityViolation);
        }
    }
    Ok(revisions)
}
