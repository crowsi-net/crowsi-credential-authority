use std::path::{Path, PathBuf};

use crate::{HostError, management_v2_record::ManagementRecordV2};

#[derive(Clone)]
pub(crate) struct ManagementJournalV2 {
    pub(crate) root: PathBuf,
    pub(crate) anchor_root: PathBuf,
    pub(super) root_pin: crate::gateway_directory::PinnedDirectory,
    pub(super) anchor_pin: crate::gateway_directory::PinnedDirectory,
    authority_epoch: u64,
    reservation: ReservationRootBinding,
}

#[derive(Clone)]
pub(crate) struct ReservationRootBinding {
    pub(crate) key_id: String,
    pub(crate) public_key_hex: String,
    pub(crate) config_generation: u64,
}

impl ReservationRootBinding {
    pub(crate) fn from_config(value: &crate::host_config_types::HostConfigDocument) -> Self {
        Self {
            key_id: value.revocation_execution_reservation_key_id.clone(),
            public_key_hex: value
                .revocation_execution_reservation_public_key_hex
                .clone(),
            config_generation: value.revocation_execution_reservation_config_generation,
        }
    }

    #[cfg(all(test, feature = "test-support"))]
    pub(crate) fn test() -> Self {
        Self {
            key_id: "reservation-key".into(),
            public_key_hex: crate::gateway_peer_response_identity::public(12),
            config_generation: 1,
        }
    }
}

impl ManagementJournalV2 {
    pub(crate) fn initialize(
        root: &Path,
        anchor_root: &Path,
        authority_epoch: u64,
        reservation: ReservationRootBinding,
    ) -> Result<(), HostError> {
        let value = Self::value(root, anchor_root, authority_epoch, reservation)?;
        let state = crate::management_v2_marker::present(&value.root, "state")?;
        let anchor = crate::management_v2_marker::present(&value.anchor_root, "anchor")?;
        match (state, anchor) {
            (false, false) => {
                pristine(&value.root, None)?;
                pristine(&value.anchor_root, None)?;
                crate::management_v2_marker::initialize(
                    &value.anchor_root,
                    "anchor",
                    authority_epoch,
                    &value.reservation,
                )?;
                crate::management_v2_marker::initialize(
                    &value.root,
                    "state",
                    authority_epoch,
                    &value.reservation,
                )?;
            }
            (false, true) => {
                pristine(&value.root, None)?;
                pristine(
                    &value.anchor_root,
                    Some(&crate::management_v2_marker::filename("anchor")),
                )?;
                crate::management_v2_marker::verify(
                    &value.anchor_root,
                    "anchor",
                    authority_epoch,
                    &value.reservation,
                )?;
                crate::management_v2_marker::initialize(
                    &value.root,
                    "state",
                    authority_epoch,
                    &value.reservation,
                )?;
            }
            (true, false) => return Err(HostError::StateInvalid),
            (true, true) => {}
        }
        value.verify_markers()
    }

    pub(crate) fn open(
        root: &Path,
        anchor_root: &Path,
        authority_epoch: u64,
        reservation: ReservationRootBinding,
    ) -> Result<Self, HostError> {
        let value = Self::value(root, anchor_root, authority_epoch, reservation)?;
        value.verify_markers()?;
        Ok(value)
    }

    fn value(
        root: &Path,
        anchor_root: &Path,
        authority_epoch: u64,
        reservation: ReservationRootBinding,
    ) -> Result<Self, HostError> {
        if root == anchor_root {
            return Err(HostError::ConfigInvalid);
        }
        if authority_epoch == 0 {
            return Err(HostError::ConfigInvalid);
        }
        let root_pin = crate::gateway_directory::PinnedDirectory::open(root)?;
        let anchor_pin = crate::gateway_directory::PinnedDirectory::open(anchor_root)?;
        Ok(Self {
            root: root_pin.path(),
            anchor_root: anchor_pin.path(),
            root_pin,
            anchor_pin,
            authority_epoch,
            reservation,
        })
    }

    pub(super) fn verify_markers(&self) -> Result<(), HostError> {
        crate::management_v2_marker::verify(
            &self.root,
            "state",
            self.authority_epoch,
            &self.reservation,
        )?;
        crate::management_v2_marker::verify(
            &self.anchor_root,
            "anchor",
            self.authority_epoch,
            &self.reservation,
        )
    }
}

include!("management_v2_journal_modules.rs");
