use crowsi_credential_authority_contracts::{
    EndpointRevocationExecutionCancelFinalizeRequestV1,
    EndpointRevocationExecutionCancellationCleanupV1,
};

use crate::{
    HostError, host_config::VerifiedHostConfig, management_v2_journal::ManagementJournalV2,
};

impl ManagementJournalV2 {
    pub(crate) fn acknowledge_execution_cancellation(
        &self,
        request: &EndpointRevocationExecutionCancelFinalizeRequestV1,
        peer: &str,
        config: &VerifiedHostConfig,
        now: u64,
    ) -> Result<(u64, EndpointRevocationExecutionCancellationCleanupV1), HostError> {
        let owner = &request.cancellation_request.prepared.opaque_owner_ref;
        self.locked(owner, || {
            let mut ledger =
                crate::management_v2_journal_io::read(&self.root, &self.anchor_root, owner)?;
            let location = location(&ledger, &request.operation_id)?;
            let context = context(&ledger, location, request, peer, now)?;
            if let Some(stored) = context.stored {
                return Ok((ledger.revision, stored));
            }
            let prior_high_water =
                crate::management_v2_journal_cancel_capacity::high_water(&ledger)?;
            let next = crate::management_v2_journal_policy::next(ledger.revision)?;
            let cleanup = crate::management_v2_execution_cancellation_cleanup_build::build(
                config,
                request,
                context.operation,
                next,
                now,
            )?;
            store(&mut ledger, location, request, &cleanup, config, now)?;
            ledger.revision = next;
            crate::management_v2_journal_cancel_capacity::actualize_cleanup(
                &mut ledger,
                &request.operation_id,
                config,
                prior_high_water,
            )?;
            crate::management_v2_journal_io::write(&self.root, &self.anchor_root, owner, &ledger)?;
            Ok((next, cleanup))
        })
    }
}

#[derive(Clone, Copy)]
enum Location {
    Record(usize),
    Tombstone(usize),
}

struct Context {
    operation: crowsi_credential_authority_contracts::ManagementOperationV2,
    stored: Option<EndpointRevocationExecutionCancellationCleanupV1>,
}

include!("management_v2_journal_execution_cancellation_cleanup_validation.rs");
include!("management_v2_journal_execution_cancellation_cleanup_store.rs");
