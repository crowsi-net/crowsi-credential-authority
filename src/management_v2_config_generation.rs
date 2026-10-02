use crowsi_credential_authority_contracts::SignedAuthorityExchangeV1;

use crate::{HostError, management_v2_record::ManagementRecordV2};

pub(crate) fn advance(floor: u64, values: &[&SignedAuthorityExchangeV1]) -> Result<u64, HostError> {
    if floor == 0 || values.is_empty() {
        return Err(HostError::EvidenceInvalid);
    }
    values.iter().try_fold(floor, |current, value| {
        let next = value.response.config_generation;
        (next >= current)
            .then_some(next)
            .ok_or(HostError::EvidenceInvalid)
    })
}

pub(crate) fn record(
    journal: &crate::management_v2_journal::ManagementJournalV2,
    value: &ManagementRecordV2,
    incoming: &[&SignedAuthorityExchangeV1],
) -> Result<u64, HostError> {
    let floor = journal
        .generation_head(&value.owner_ref)?
        .max(value.authority_config_generation);
    advance(floor, incoming)
}
