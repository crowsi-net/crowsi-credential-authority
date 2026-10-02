use crate::{
    AuthorityError,
    file_store_anchor::{MAX_ANCHOR_BYTES, StoreAnchor},
    file_store_envelope::{MAX_STORE_BYTES, StoreEnvelope, VerifiedEnvelope, valid_digest},
    file_store_head::{HEAD_NAME, MAX_HEAD_BYTES, StoreHead},
    file_store_lock::LOCK_NAME,
    file_store_marker::{ANCHOR_MARKER, STATE_MARKER},
    file_store_path::{PinnedDirectory, StorePaths},
};
use std::collections::BTreeSet;

pub(crate) const MAX_RETAINED: usize = 3;
const MAX_RECOVERY: usize = MAX_RETAINED + 1;

pub(crate) struct RawStore {
    pub store_id: String,
    pub state_head: StoreHead,
    pub state_head_wire: Vec<u8>,
    pub anchor_head: StoreHead,
    pub anchor_head_wire: Vec<u8>,
    pub generations: Vec<GenerationRecord>,
    pub anchors: Vec<AnchorRecord>,
}

pub(crate) struct GenerationRecord {
    pub name: String,
    pub digest: String,
    pub envelope: VerifiedEnvelope,
}

pub(crate) struct AnchorRecord {
    pub name: String,
    pub digest: String,
    pub anchor: StoreAnchor,
}

pub(crate) fn pristine(paths: &StorePaths) -> Result<bool, AuthorityError> {
    paths.validate()?;
    let state = crate::file_store_inventory::names(&paths.state)?;
    let anchor = crate::file_store_inventory::names(&paths.anchor)?;
    Ok(state == [LOCK_NAME] && anchor.is_empty())
}

pub(crate) fn raw(paths: &StorePaths) -> Result<RawStore, AuthorityError> {
    let binding = crate::file_store_marker::verify(paths)?;
    let store_id = binding.store_id;
    let state_names = crate::file_store_inventory::names(&paths.state)?;
    let anchor_names = crate::file_store_inventory::names(&paths.anchor)?;
    let generations = generations(&paths.state, &state_names)?;
    let anchors = anchors(&paths.anchor, &anchor_names, &store_id)?;
    let state_head_wire = crate::file_store_file::read(&paths.state, HEAD_NAME, MAX_HEAD_BYTES)?;
    let anchor_head_wire = crate::file_store_file::read(&paths.anchor, HEAD_NAME, MAX_HEAD_BYTES)?;
    Ok(RawStore {
        state_head: StoreHead::decode(&state_head_wire, &store_id)?,
        anchor_head: StoreHead::decode(&anchor_head_wire, &store_id)?,
        state_head_wire,
        anchor_head_wire,
        store_id,
        generations,
        anchors,
    })
}

fn generations(
    root: &PinnedDirectory,
    names: &[String],
) -> Result<Vec<GenerationRecord>, AuthorityError> {
    let mut records = Vec::new();
    let mut revisions = BTreeSet::new();
    let mut digests = BTreeSet::new();
    for name in names {
        if matches!(name.as_str(), LOCK_NAME | STATE_MARKER | HEAD_NAME) {
            continue;
        }
        let digest = parse_name(name, "authority-generation-")?;
        let wire = crate::file_store_file::read(root, name, MAX_STORE_BYTES)?;
        let envelope: StoreEnvelope =
            serde_json::from_slice(&wire).map_err(|_| AuthorityError::IntegrityViolation)?;
        let envelope = envelope.verify()?;
        if crate::file_store_envelope::digest_bytes(&wire) != digest {
            return Err(AuthorityError::IntegrityViolation);
        }
        if !revisions.insert(envelope.generation) || !digests.insert(digest.clone()) {
            return Err(AuthorityError::IntegrityViolation);
        }
        records.push(GenerationRecord {
            name: name.clone(),
            digest,
            envelope,
        });
        if records.len() > MAX_RECOVERY {
            return Err(AuthorityError::RollbackDetected);
        }
    }
    Ok(records)
}

fn anchors(
    root: &PinnedDirectory,
    names: &[String],
    store_id: &str,
) -> Result<Vec<AnchorRecord>, AuthorityError> {
    let mut records = Vec::new();
    let mut revisions = BTreeSet::new();
    let mut digests = BTreeSet::new();
    for name in names {
        if matches!(name.as_str(), ANCHOR_MARKER | HEAD_NAME) {
            continue;
        }
        let digest = parse_name(name, "authority-anchor-")?;
        let wire = crate::file_store_file::read(root, name, MAX_ANCHOR_BYTES)?;
        let anchor = StoreAnchor::decode(&wire, store_id)?;
        if crate::file_store_envelope::digest_bytes(&wire) != digest {
            return Err(AuthorityError::IntegrityViolation);
        }
        if !revisions.insert(anchor.generation()) || !digests.insert(digest.clone()) {
            return Err(AuthorityError::IntegrityViolation);
        }
        records.push(AnchorRecord {
            name: name.clone(),
            digest,
            anchor,
        });
        if records.len() > MAX_RECOVERY {
            return Err(AuthorityError::RollbackDetected);
        }
    }
    Ok(records)
}

fn parse_name(name: &str, prefix: &str) -> Result<String, AuthorityError> {
    let value = name
        .strip_prefix(prefix)
        .and_then(|item| item.strip_suffix(".json"))
        .ok_or(AuthorityError::IntegrityViolation)?;
    if valid_digest(value) {
        Ok(value.to_owned())
    } else {
        Err(AuthorityError::IntegrityViolation)
    }
}
