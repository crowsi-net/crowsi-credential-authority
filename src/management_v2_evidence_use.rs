use crate::{
    HostError,
    management_v2_journal_update::EvidenceUse,
    management_v2_record::{ConsumedEvidenceV2, ManagementLedgerV2},
};

pub(crate) fn consume(
    ledger: &mut ManagementLedgerV2,
    evidence: &[EvidenceUse<'_>],
    now: u64,
) -> Result<(), HostError> {
    ledger
        .consumed_evidence
        .retain(|item| now < item.expires_at_epoch_s);
    if evidence.iter().any(|item| {
        now >= item.expires_at_epoch_s || item.expires_at_epoch_s.saturating_sub(now) > 120
    }) {
        return Err(HostError::EvidenceInvalid);
    }
    let additions = evidence
        .iter()
        .map(crate::management_v2_journal_policy::evidence_digest)
        .collect::<Result<Vec<_>, _>>()?;
    let conflicting_batch = additions.iter().enumerate().any(|(index, digest)| {
        additions[..index]
            .iter()
            .zip(&evidence[..index])
            .any(|(prior, use_)| prior == digest && use_.binding != evidence[index].binding)
    });
    let replay = additions.iter().zip(evidence).any(|(digest, use_)| {
        ledger
            .consumed_evidence
            .iter()
            .find(|item| &item.digest == digest)
            .is_some_and(|item| item.binding_sha256 != use_.binding)
    });
    if replay || conflicting_batch {
        return Err(HostError::StateInvalid);
    }
    for (index, item) in evidence.iter().enumerate() {
        let digest = &additions[index];
        if additions[..index].contains(digest) {
            continue;
        }
        let expiry = additions
            .iter()
            .zip(evidence)
            .filter_map(|(candidate, value)| {
                (candidate == digest).then_some(value.expires_at_epoch_s)
            })
            .max()
            .ok_or(HostError::EvidenceInvalid)?;
        if let Some(existing) = ledger
            .consumed_evidence
            .iter_mut()
            .find(|value| &value.digest == digest)
        {
            existing.expires_at_epoch_s = existing.expires_at_epoch_s.max(expiry);
        } else {
            ledger.consumed_evidence.push(ConsumedEvidenceV2 {
                digest: digest.clone(),
                binding_sha256: item.binding.into(),
                expires_at_epoch_s: expiry,
            });
        }
    }
    (ledger.consumed_evidence.len() <= 1024)
        .then_some(())
        .ok_or(HostError::StateInvalid)
}
