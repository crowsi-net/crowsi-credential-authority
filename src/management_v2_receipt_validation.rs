pub(crate) fn valid_set(values: &[Receipt]) -> bool {
    let mut digests = BTreeSet::new();
    let mut read_per_actor = BTreeMap::<&str, usize>::new();
    let mut mutation_per_actor = BTreeMap::<&str, usize>::new();
    values.iter().all(|value| {
        let read_only = value.read_only;
        let count = if read_only {
            read_per_actor.entry(&value.actor_device_ref).or_default()
        } else {
            mutation_per_actor
                .entry(&value.actor_device_ref)
                .or_default()
        };
        *count += 1;
        valid_digest(&value.request_digest_sha256)
            && valid_digest(&value.identity_exchange_sha256)
            && valid_id(&value.actor_device_ref)
            && phase(value)
            && value.operation_id.as_deref().is_none_or(valid_id)
            && value.retain_until_epoch_s > 0
            && value.accepted_ledger_revision > 0
            && value.accepted_generation_head > 0
            && wire(value).is_ok()
            && (if read_only {
                *count <= 4
            } else {
                *count <= 256
            })
            && digests.insert(&value.request_digest_sha256)
    })
}

fn valid_digest(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|item| item.is_ascii_digit() || matches!(item, b'a'..=b'f'))
}

fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

fn phase(value: &Receipt) -> bool {
    if value.read_only {
        return value.phase.is_none();
    }
    value.phase.as_deref().is_none_or(|phase| {
        matches!(
            phase,
            "source-options"
                | "source-approve"
                | "target-options"
                | "target-approve"
                | "approval-options"
                | "approve-revocation"
                | "cancel"
                | "reconcile"
        )
    })
}
