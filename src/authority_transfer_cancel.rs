use crate::{AuthorityError, GrantState, state::TransferRecord};

pub(crate) fn grants(
    snapshot: &mut crate::DurableSnapshot,
    transfer: &TransferRecord,
    now: u64,
) -> Result<(), AuthorityError> {
    crate::authority_grant_limits::expire(snapshot, now);
    if transfer.management_source_binding.is_some() {
        let target = snapshot.grants.remove(&transfer.target_grant);
        let source = snapshot.grants.remove(&transfer.source_grant);
        if target.is_none() || source.is_none() {
            return Err(AuthorityError::IntegrityViolation);
        }
        return Ok(());
    }
    snapshot
        .grants
        .get_mut(&transfer.target_grant)
        .ok_or(AuthorityError::NotFound)?
        .state = GrantState::Revoked;
    Ok(())
}
