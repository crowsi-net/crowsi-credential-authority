use crate::{
    DeviceId, GrantId, OpaqueOwnerRef, ProviderReissueReceipt, StepUpProof, TargetKeyProof,
    TransferId, TransferState,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransferReceipt {
    pub(crate) id: TransferId,
    pub(crate) source_grant: GrantId,
    pub(crate) target_grant: GrantId,
    pub(crate) state: TransferState,
    pub(crate) provider_revision: Option<u64>,
}

impl TransferReceipt {
    pub fn id(&self) -> &TransferId {
        &self.id
    }
    pub fn source_grant_id(&self) -> &GrantId {
        &self.source_grant
    }
    pub fn target_grant_id(&self) -> &GrantId {
        &self.target_grant
    }
    pub const fn state(&self) -> TransferState {
        self.state
    }
    pub const fn provider_revision(&self) -> Option<u64> {
        self.provider_revision
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransferAcceptance {
    pub(crate) transfer_id: TransferId,
    pub(crate) owner: OpaqueOwnerRef,
    pub(crate) target_device: DeviceId,
    pub(crate) target_proof: TargetKeyProof,
    pub(crate) provider_receipt: Option<ProviderReissueReceipt>,
}

impl TransferAcceptance {
    #[must_use]
    pub const fn new(
        transfer_id: TransferId,
        owner: OpaqueOwnerRef,
        target_device: DeviceId,
        target_proof: TargetKeyProof,
    ) -> Self {
        Self {
            transfer_id,
            owner,
            target_device,
            target_proof,
            provider_receipt: None,
        }
    }

    pub fn with_provider_receipt(mut self, receipt: ProviderReissueReceipt) -> Self {
        self.provider_receipt = Some(receipt);
        self
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransferCancellation {
    pub(crate) transfer_id: TransferId,
    pub(crate) owner: OpaqueOwnerRef,
    pub(crate) source_device: DeviceId,
    pub(crate) step_up: StepUpProof,
}

impl TransferCancellation {
    #[must_use]
    pub const fn new(
        transfer_id: TransferId,
        owner: OpaqueOwnerRef,
        source_device: DeviceId,
        step_up: StepUpProof,
    ) -> Self {
        Self {
            transfer_id,
            owner,
            source_device,
            step_up,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransferCancellationReceipt {
    pub(crate) state: TransferState,
}
impl TransferCancellationReceipt {
    pub const fn state(&self) -> TransferState {
        self.state
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GrantPairState {
    pub(crate) source: crate::GrantState,
    pub(crate) target: crate::GrantState,
}
impl GrantPairState {
    pub const fn source(&self) -> crate::GrantState {
        self.source
    }
    pub const fn target(&self) -> crate::GrantState {
        self.target
    }
    pub const fn source_and_target_are_both_authoritative(&self) -> bool {
        matches!(self.source, crate::GrantState::Active)
            && matches!(self.target, crate::GrantState::Active)
    }
}
