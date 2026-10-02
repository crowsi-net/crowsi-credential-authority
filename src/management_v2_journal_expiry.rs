use crowsi_credential_authority_contracts::{
    ActorRequirementV2, ManagementOperationState as State, ManagementReasonCode, RequiredActorRole,
};

use crate::{HostError, management_v2_journal::ManagementJournalV2};

impl ManagementJournalV2 {
    pub(crate) fn expire_due(
        &self,
        owner: &str,
        identity_config_generation: u64,
        now: u64,
    ) -> Result<(), HostError> {
        self.locked(owner, || {
            let mut ledger =
                crate::management_v2_journal_io::read(&self.root, &self.anchor_root, owner)?;
            if identity_config_generation < ledger.authority_config_generation_head {
                return Err(HostError::EvidenceInvalid);
            }
            let mut changed = false;
            for record in &mut ledger.records {
                if expirable(record.operation.state) && now >= record.operation.expires_at_epoch_s {
                    record.operation.state_revision =
                        crate::management_v2_journal_policy::next(record.operation.state_revision)?;
                    record.operation.state = State::Expired;
                    record.operation.actor = no_actor();
                    record.operation.webauthn_options = None;
                    record.operation.reason = Some(ManagementReasonCode::OperationExpired);
                    record.operation.reconcile_digest = None;
                    record.authority_config_generation = record
                        .authority_config_generation
                        .max(identity_config_generation);
                    changed = true;
                }
            }
            if changed {
                ledger.authority_config_generation_head = ledger
                    .authority_config_generation_head
                    .max(identity_config_generation);
                ledger.revision = crate::management_v2_journal_policy::next(ledger.revision)?;
                crate::management_v2_journal_io::write(
                    &self.root,
                    &self.anchor_root,
                    owner,
                    &ledger,
                )?;
            }
            Ok(())
        })
    }
}

fn expirable(value: State) -> bool {
    matches!(
        value,
        State::AwaitingSourceUv
            | State::AwaitingTarget
            | State::AwaitingTargetUv
            | State::AwaitingIndependentApproval
            | State::AwaitingApprovalUv
    )
}

fn no_actor() -> ActorRequirementV2 {
    ActorRequirementV2 {
        role: RequiredActorRole::NoActor,
        required_actor_device_ref: None,
        required_approval_authority_ref: None,
        excluded_actor_device_refs: Vec::new(),
    }
}
