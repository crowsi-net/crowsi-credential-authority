use crate::{DeviceId, OpaqueOwnerRef, RevocationCause, StepUpProof};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoelaDeviceRevocationRequest {
    pub(crate) owner: OpaqueOwnerRef,
    pub(crate) target_device: DeviceId,
    pub(crate) expected_device_epoch: u64,
    pub(crate) cause: RevocationCause,
    pub(crate) step_up: StepUpProof,
}

impl CoelaDeviceRevocationRequest {
    #[must_use]
    pub const fn new(
        owner: OpaqueOwnerRef,
        target_device: DeviceId,
        expected_device_epoch: u64,
        cause: RevocationCause,
        step_up: StepUpProof,
    ) -> Self {
        Self {
            owner,
            target_device,
            expected_device_epoch,
            cause,
            step_up,
        }
    }

    #[must_use]
    pub fn owner(&self) -> &OpaqueOwnerRef {
        &self.owner
    }

    #[must_use]
    pub fn target_device(&self) -> &DeviceId {
        &self.target_device
    }

    #[must_use]
    pub const fn expected_device_epoch(&self) -> u64 {
        self.expected_device_epoch
    }

    #[must_use]
    pub const fn cause(&self) -> RevocationCause {
        self.cause
    }

    #[must_use]
    pub const fn step_up(&self) -> &StepUpProof {
        &self.step_up
    }
}
