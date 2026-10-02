fn retained_digests(sets: &[Vec<Pair>; 3]) -> Result<Vec<String>, HostError> {
    let mut revisions = BTreeMap::<u64, String>::new();
    for set in sets {
        for (revision, digest) in set {
            if revisions
                .insert(*revision, digest.clone())
                .is_some_and(|old| old != *digest)
            {
                return Err(HostError::StateInvalid);
            }
        }
    }
    let latest = *revisions.keys().last().ok_or(HostError::StateInvalid)?;
    let keep = if revisions.contains_key(&latest.saturating_sub(1)) {
        vec![latest.saturating_sub(1), latest]
    } else {
        vec![latest]
    };
    if latest < 2
        || sets.iter().any(|set| {
            !keep
                .iter()
                .all(|revision| set.iter().any(|item| item.0 == *revision))
                || set
                    .iter()
                    .any(|item| item.0 + 2 < latest || item.0 > latest)
        })
    {
        return Err(HostError::StateInvalid);
    }
    keep.iter()
        .map(|revision| {
            revisions
                .get(revision)
                .cloned()
                .ok_or(HostError::StateInvalid)
        })
        .collect()
}

fn prior_exact(
    intent: &crate::management_v2_intent::CommitIntentV1,
    generations: &[Generation],
    anchors: &[Pair],
    heads: &[Pair],
) -> Result<(), HostError> {
    let old_generations = generations
        .iter()
        .filter(|item| item.revision != intent.revision)
        .cloned()
        .collect::<Vec<_>>();
    let old_pairs = generations_pairs(&old_generations);
    let old_anchors = without(anchors, intent.revision);
    let old_heads = without(heads, intent.revision);
    let prior = old_generations
        .last()
        .map(|item| (&item.ledger, item.digest.as_str()));
    let logical_empty = intent.prior_revision == 1
        && old_pairs.is_empty()
        && ledger_digest(&ManagementLedgerV2::empty())? == intent.prior_ledger_sha256;
    let exact = prior.is_some_and(|(ledger, digest)| {
        ledger.revision == intent.prior_revision && digest == intent.prior_ledger_sha256
    });
    (old_pairs == old_anchors && old_anchors == old_heads && (logical_empty || exact))
        .then_some(())
        .ok_or(HostError::StateInvalid)
}

fn generations_pairs(values: &[Generation]) -> Vec<Pair> {
    values
        .iter()
        .map(|item| (item.revision, item.digest.clone()))
        .collect()
}

fn without(values: &[Pair], revision: u64) -> Vec<Pair> {
    values
        .iter()
        .filter(|item| item.0 != revision)
        .cloned()
        .collect()
}

fn contains(values: &[Pair], revision: u64, digest: &str) -> bool {
    values
        .iter()
        .any(|item| item.0 == revision && item.1 == digest)
}

fn ledger_digest(value: &ManagementLedgerV2) -> Result<String, HostError> {
    serde_json::to_vec(value)
        .map(|wire| crate::host_crypto::digest(&wire))
        .map_err(|_| HostError::StateInvalid)
}
