use crate::state::DeviceRecord;
use crate::{DeviceGrant, DeviceId};

pub(crate) fn promote_to_target_identity(
    grant: &mut DeviceGrant,
    target_device: &DeviceId,
    identity: &DeviceRecord,
) {
    grant.source_device = target_device.clone();
    grant.target_device = target_device.clone();
    grant.source_epoch = identity.epoch;
    grant.target_epoch = identity.epoch;
    grant
        .pairwise_subject_ref
        .clone_from(&identity.pairwise_subject_ref);
    grant.identity_issuer.clone_from(&identity.issuer);
    grant.identity_service_id = identity.service_id.clone();
    grant
        .source_key_thumbprint
        .clone_from(&identity.key_thumbprint);
    grant
        .target_key_thumbprint
        .clone_from(&identity.key_thumbprint);
    grant.source_posture_revision = identity.posture_revision;
    grant.target_posture_revision = identity.posture_revision;
    grant
        .source_posture_state
        .clone_from(&identity.posture_state);
    grant.subject_revocation_epoch = identity.subject_revocation_epoch;
    grant.service_revocation_epoch = identity.service_revocation_epoch;
    grant.session_revocation_epoch = identity.session_revocation_epoch;
    grant.identity_key_id.clone_from(&identity.key_id);
}
