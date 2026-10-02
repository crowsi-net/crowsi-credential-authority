use crate::{DeviceId, OpaqueOwnerRef, StepUpProof};

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub enum AccountState {
    Active,
    Unlinked,
    Closed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccountClosureRequest {
    pub(crate) owner: OpaqueOwnerRef,
    pub(crate) requested_by: DeviceId,
    pub(crate) step_up: StepUpProof,
    pub(crate) state: AccountState,
}

impl AccountClosureRequest {
    #[must_use]
    pub fn unlink(owner: OpaqueOwnerRef, step_up: StepUpProof) -> Self {
        Self {
            requested_by: step_up.device.clone(),
            owner,
            step_up,
            state: AccountState::Unlinked,
        }
    }

    #[must_use]
    pub fn close(owner: OpaqueOwnerRef, step_up: StepUpProof) -> Self {
        Self {
            requested_by: step_up.device.clone(),
            owner,
            step_up,
            state: AccountState::Closed,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccountClosureReceipt {
    pub(crate) state: AccountState,
    pub(crate) secret_deletion_attempted: bool,
}

impl AccountClosureReceipt {
    #[must_use]
    pub const fn account_state(&self) -> AccountState {
        self.state
    }

    #[must_use]
    pub const fn secret_deletion_attempted(&self) -> bool {
        self.secret_deletion_attempted
    }
}
