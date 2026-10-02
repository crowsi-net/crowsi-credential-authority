use crate::state::DurableSnapshot;
use crate::{AuthorityError, DeviceId, OpaqueOwnerRef, StepUpProof, TargetKeyProof};

pub(crate) const MAX_TTL_MS: u64 = 300_000;
const MAX_PROOF_AGE_MS: u64 = 300_000;

pub(crate) fn active_account(
    snapshot: &DurableSnapshot,
    owner: &OpaqueOwnerRef,
) -> Result<(), AuthorityError> {
    if snapshot.accounts.get(owner) == Some(&crate::AccountState::Active) {
        Ok(())
    } else {
        Err(AuthorityError::AccountUnavailable)
    }
}

pub(crate) fn step_up(
    snapshot: &DurableSnapshot,
    owner: &OpaqueOwnerRef,
    device: &DeviceId,
    proof: &StepUpProof,
    now_ms: u64,
) -> Result<(), AuthorityError> {
    if &proof.owner != owner {
        return Err(AuthorityError::WrongOwner);
    }
    if &proof.device != device {
        return Err(AuthorityError::StepUpDeviceMismatch);
    }
    if !proof.verified
        || proof.authenticated_at_ms > now_ms
        || proof.expires_at_ms < now_ms
        || now_ms.saturating_sub(proof.authenticated_at_ms) > MAX_PROOF_AGE_MS
    {
        return Err(AuthorityError::FreshStepUpRequired);
    }
    if snapshot
        .devices
        .get(&(owner.clone(), device.clone()))
        .is_none_or(|record| record.revoked)
    {
        return Err(AuthorityError::WrongDevice);
    }
    Ok(())
}

pub(crate) fn target_proof(
    snapshot: &DurableSnapshot,
    owner: &OpaqueOwnerRef,
    device: &DeviceId,
    proof: &TargetKeyProof,
    now_ms: u64,
) -> Result<(), AuthorityError> {
    if &proof.owner != owner {
        return Err(AuthorityError::WrongOwner);
    }
    if &proof.device != device {
        return Err(AuthorityError::TargetDeviceMismatch);
    }
    let record = snapshot
        .devices
        .get(&(owner.clone(), device.clone()))
        .ok_or(AuthorityError::TargetDeviceMismatch)?;
    if !proof.verified
        || record.revoked
        || proof.key_thumbprint != record.key_thumbprint
        || proof.nonce.is_empty()
        || proof.nonce.len() > 128
        || proof.issued_at_ms > now_ms
        || now_ms.saturating_sub(proof.issued_at_ms) > MAX_PROOF_AGE_MS
        || snapshot
            .used_nonces
            .contains(&format!("target:{}", proof.nonce))
    {
        return Err(AuthorityError::TargetKeyProofInvalid);
    }
    Ok(())
}

pub(crate) fn ttl(ttl_ms: u64) -> Result<(), AuthorityError> {
    if (1..=MAX_TTL_MS).contains(&ttl_ms) {
        Ok(())
    } else {
        Err(AuthorityError::InvalidValue("ttl_ms"))
    }
}
