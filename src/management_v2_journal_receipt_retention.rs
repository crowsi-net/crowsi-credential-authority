fn make_room(
    values: &mut Vec<Receipt>,
    incoming: &Receipt,
    terminal: &std::collections::BTreeSet<String>,
) {
    while values.len() >= 512 {
        if !remove_oldest(values, None, terminal) {
            return;
        }
    }
    if incoming.read_only {
        return;
    }
    while values
        .iter()
        .filter(|item| !item.read_only && item.actor_device_ref == incoming.actor_device_ref)
        .count()
        >= 256
    {
        if !remove_oldest(values, Some(&incoming.actor_device_ref), terminal) {
            return;
        }
    }
}

fn remove_oldest(
    values: &mut Vec<Receipt>,
    actor: Option<&str>,
    terminal: &std::collections::BTreeSet<String>,
) -> bool {
    let candidate = values
        .iter()
        .enumerate()
        .filter(|(_, item)| actor.is_none_or(|actor| item.actor_device_ref == actor))
        .filter(|(_, item)| actor.is_none() || !item.read_only)
        .filter(|(_, item)| {
            item.read_only
                || item
                    .operation_id
                    .as_ref()
                    .is_some_and(|operation| terminal.contains(operation))
        })
        .min_by_key(|(_, item)| (!item.read_only, item.accepted_ledger_revision))
        .map(|(index, _)| index);
    candidate.is_some_and(|index| {
        values.remove(index);
        true
    })
}
