use std::{collections::BTreeMap, path::Path};

use crate::{
    HostError, management_v2_generation::Generation, management_v2_record::ManagementLedgerV2,
};

type Pair = (u64, String);

pub(super) fn read(
    root: &Path,
    anchor: &Path,
    owner: &str,
) -> Result<ManagementLedgerV2, HostError> {
    recover(root, anchor, owner)?;
    committed(root, anchor, owner)
}

pub(super) fn write(
    root: &Path,
    anchor: &Path,
    owner: &str,
    next: &ManagementLedgerV2,
) -> Result<(), HostError> {
    recover(root, anchor, owner)?;
    let prior = committed(root, anchor, owner)?;
    if next.revision != prior.revision.saturating_add(1) {
        return Err(HostError::StateInvalid);
    }
    let wire = serde_json::to_vec(next).map_err(|_| HostError::StateInvalid)?;
    let digest = crate::host_crypto::digest(&wire);
    crate::management_v2_intent::begin(root, owner, &prior, next, &digest)?;
    crate::management_v2_generation::append(root, owner, next, &digest)?;
    crate::management_v2_anchor::append(anchor, owner, next.revision, &digest)?;
    crate::management_v2_head::append(root, owner, next.revision, &digest)?;
    crate::management_v2_intent::remove(root, owner)?;
    normalize(root, anchor, owner)?;
    let stored = committed(root, anchor, owner)?;
    (stored.revision == next.revision && ledger_digest(&stored)? == digest)
        .then_some(())
        .ok_or(HostError::StateInvalid)
}

fn recover(root: &Path, anchor: &Path, owner: &str) -> Result<(), HostError> {
    let Some(intent) = crate::management_v2_intent::read(root, owner)? else {
        return normalize(root, anchor, owner);
    };
    let generations = crate::management_v2_generation::retained(root, owner, 3)?;
    let anchors = crate::management_v2_anchor::retained_owner(anchor, owner, 3)?;
    let heads = crate::management_v2_head::retained(root, owner, 3)?;
    prior_exact(&intent, &generations, &anchors, &heads)?;
    let has_generation = contains(
        &generations_pairs(&generations),
        intent.revision,
        &intent.ledger_sha256,
    );
    let has_anchor = contains(&anchors, intent.revision, &intent.ledger_sha256);
    let has_head = contains(&heads, intent.revision, &intent.ledger_sha256);
    if !has_generation {
        if has_anchor || has_head {
            return Err(HostError::StateInvalid);
        }
        crate::management_v2_intent::remove(root, owner)?;
        return normalize(root, anchor, owner);
    }
    if !has_anchor {
        crate::management_v2_anchor::append(anchor, owner, intent.revision, &intent.ledger_sha256)?;
    }
    if !has_head {
        crate::management_v2_head::append(root, owner, intent.revision, &intent.ledger_sha256)?;
    }
    crate::management_v2_intent::remove(root, owner)?;
    normalize(root, anchor, owner)
}

fn committed(root: &Path, anchor: &Path, owner: &str) -> Result<ManagementLedgerV2, HostError> {
    let generations = crate::management_v2_generation::retained(root, owner, 2)?;
    let generation_pairs = generations_pairs(&generations);
    let anchors = crate::management_v2_anchor::retained_owner(anchor, owner, 2)?;
    let heads = crate::management_v2_head::retained(root, owner, 2)?;
    if generation_pairs.is_empty() && anchors.is_empty() && heads.is_empty() {
        return Ok(ManagementLedgerV2::empty());
    }
    if generation_pairs != anchors || anchors != heads {
        return Err(HostError::StateInvalid);
    }
    generations
        .last()
        .map(|item| item.ledger.clone())
        .ok_or(HostError::StateInvalid)
}

fn normalize(root: &Path, anchor: &Path, owner: &str) -> Result<(), HostError> {
    let generations = crate::management_v2_generation::retained(root, owner, 3)?;
    let sets = [
        generations_pairs(&generations),
        crate::management_v2_anchor::retained_owner(anchor, owner, 3)?,
        crate::management_v2_head::retained(root, owner, 3)?,
    ];
    if sets.iter().all(Vec::is_empty) {
        return Ok(());
    }
    let retained = retained_digests(&sets)?;
    crate::management_v2_generation::prune(root, owner, &retained)?;
    crate::management_v2_anchor::prune(anchor, owner, &retained)?;
    crate::management_v2_head::prune(root, owner, &retained)
}

include!("management_v2_commit_validation.rs");
