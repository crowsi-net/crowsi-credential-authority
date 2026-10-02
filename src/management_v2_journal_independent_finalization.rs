use crowsi_credential_authority_contracts::{
    EndpointIndependentRevocationFinalizeRequestV1, ManagementOperationState, ManagementReasonCode,
};

use crate::{
    HostError,
    management_v2_journal::ManagementJournalV2,
    management_v2_record::{ManagementRecordV2, ManagementTombstoneV2},
};

pub(crate) enum IndependentFinalizationEntry {
    Record(Box<ManagementRecordV2>),
    Tombstone(Box<ManagementTombstoneV2>),
}

impl ManagementJournalV2 {
    pub(crate) fn accept_independent_final(
        &self,
        request: &EndpointIndependentRevocationFinalizeRequestV1,
        peer: &str,
    ) -> Result<IndependentFinalizationEntry, HostError> {
        let owner = &request.prepared.opaque_owner_ref;
        self.locked(owner, || {
            let mut ledger =
                crate::management_v2_journal_io::read(&self.root, &self.anchor_root, owner)?;
            if let Some(index) = ledger
                .records
                .iter()
                .position(|item| item.operation.operation_id == request.operation_id)
            {
                let changed = accept(
                    &mut ledger.records[index],
                    request,
                    peer,
                    ledger.authority_config_generation_head,
                )?;
                let result = ledger.records[index].clone();
                if changed {
                    ledger.authority_config_generation_head = ledger
                        .authority_config_generation_head
                        .max(result.authority_config_generation);
                    ledger.revision = crate::management_v2_journal_policy::next(ledger.revision)?;
                    crate::management_v2_journal_io::write(
                        &self.root,
                        &self.anchor_root,
                        owner,
                        &ledger,
                    )?;
                }
                return Ok(IndependentFinalizationEntry::Record(Box::new(result)));
            }
            let tombstone = ledger
                .tombstones
                .iter()
                .find(|item| item.operation.operation_id == request.operation_id)
                .ok_or(HostError::StateInvalid)?;
            exact_tombstone(tombstone, request, peer)?;
            Ok(IndependentFinalizationEntry::Tombstone(Box::new(
                tombstone.clone(),
            )))
        })
    }

    pub(crate) fn independent_finalization_view(
        &self,
        request: &EndpointIndependentRevocationFinalizeRequestV1,
        peer: &str,
    ) -> Result<(u64, IndependentFinalizationEntry), HostError> {
        let owner = &request.prepared.opaque_owner_ref;
        self.locked(owner, || {
            let ledger =
                crate::management_v2_journal_io::read(&self.root, &self.anchor_root, owner)?;
            if let Some(record) = ledger
                .records
                .iter()
                .find(|item| item.operation.operation_id == request.operation_id)
            {
                exact_record(record, request, peer)?;
                return Ok((
                    ledger.revision,
                    IndependentFinalizationEntry::Record(Box::new(record.clone())),
                ));
            }
            let tombstone = ledger
                .tombstones
                .iter()
                .find(|item| item.operation.operation_id == request.operation_id)
                .ok_or(HostError::StateInvalid)?;
            exact_tombstone(tombstone, request, peer)?;
            Ok((
                ledger.revision,
                IndependentFinalizationEntry::Tombstone(Box::new(tombstone.clone())),
            ))
        })
    }
}

include!("management_v2_journal_independent_finalization_accept.rs");
