use crate::{DeviceId, GrantAction, GrantAudience, GrantId, OpaqueOwnerRef};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GrantUse {
    pub(crate) grant_id: GrantId,
    pub(crate) owner: OpaqueOwnerRef,
    pub(crate) device: DeviceId,
    pub(crate) audience: GrantAudience,
    pub(crate) action: GrantAction,
    pub(crate) epoch: u64,
}

impl GrantUse {
    #[must_use]
    pub const fn new(
        grant_id: GrantId,
        owner: OpaqueOwnerRef,
        device: DeviceId,
        audience: GrantAudience,
        action: GrantAction,
        epoch: u64,
    ) -> Self {
        Self {
            grant_id,
            owner,
            device,
            audience,
            action,
            epoch,
        }
    }

    pub fn with_owner(mut self, value: OpaqueOwnerRef) -> Self {
        self.owner = value;
        self
    }
    pub fn with_device(mut self, value: DeviceId) -> Self {
        self.device = value;
        self
    }
    pub fn with_audience(mut self, value: GrantAudience) -> Self {
        self.audience = value;
        self
    }
    pub fn with_action(mut self, value: GrantAction) -> Self {
        self.action = value;
        self
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RevisionReceipt {
    pub(crate) previous: u64,
    pub(crate) current: u64,
}

impl RevisionReceipt {
    pub const fn previous_revision(&self) -> u64 {
        self.previous
    }
    pub const fn current_revision(&self) -> u64 {
        self.current
    }
}
