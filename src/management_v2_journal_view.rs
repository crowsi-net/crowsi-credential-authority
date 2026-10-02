use crowsi_credential_authority_contracts::ManagementOperationV2;

use crate::{HostError, management_v2_journal::ManagementJournalV2};

impl ManagementJournalV2 {
    pub(crate) fn current_operations(
        &self,
        owner: &str,
        service: &str,
        identity_config_generation: u64,
    ) -> Result<(u64, Vec<ManagementOperationV2>), HostError> {
        self.locked(owner, || {
            let ledger =
                crate::management_v2_journal_io::read(&self.root, &self.anchor_root, owner)?;
            if identity_config_generation < ledger.authority_config_generation_head {
                return Err(HostError::EvidenceInvalid);
            }
            let mut active = ledger
                .records
                .iter()
                .filter(|item| {
                    item.service_id == service && !crate::management_v2_quota::terminal(item)
                })
                .map(|item| item.operation.clone())
                .collect::<Vec<_>>();
            let mut terminal = ledger
                .records
                .iter()
                .filter(|item| {
                    item.service_id == service && crate::management_v2_quota::terminal(item)
                })
                .map(|item| item.operation.clone())
                .chain(
                    ledger
                        .tombstones
                        .iter()
                        .filter(|item| item.service_id == service)
                        .map(|item| item.operation.clone()),
                )
                .collect::<Vec<_>>();
            terminal.sort_by_key(|item| std::cmp::Reverse(item.created_at_epoch_s));
            terminal.truncate(100_usize.saturating_sub(active.len()));
            active.extend(terminal);
            Ok((ledger.revision, active))
        })
    }
}
