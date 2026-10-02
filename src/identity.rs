use crate::{AuthorityError, DeviceId, GrantAudience, OpaqueOwnerRef, ServiceId};
use ihat_identity_assertion_contracts::{
    AssertionVerifier, decode_assertion_strict, verify_assertion_at,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeviceIdentityBinding {
    pub issuer: String,
    pub audience: GrantAudience,
    pub service_id: ServiceId,
    pub pairwise_subject: String,
    pub device_id: DeviceId,
    pub device_proof_key_ref: String,
    pub session_ref: String,
    pub posture_state: String,
    pub posture_revision: u64,
    pub subject_revocation_epoch: u64,
    pub service_revocation_epoch: u64,
    pub device_revocation_epoch: u64,
    pub session_revocation_epoch: u64,
    pub issued_at_epoch_s: u64,
    pub expires_at_epoch_s: u64,
    pub nonce: String,
    pub key_id: String,
}

impl DeviceIdentityBinding {
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub(crate) fn from_verified_assertion(
        issuer: impl Into<String>,
        audience: GrantAudience,
        service_id: ServiceId,
        pairwise_subject: impl Into<String>,
        device_id: DeviceId,
        device_proof_key_ref: impl Into<String>,
        session_ref: impl Into<String>,
        posture_state: impl Into<String>,
        posture_revision: u64,
        subject_revocation_epoch: u64,
        service_revocation_epoch: u64,
        device_revocation_epoch: u64,
        session_revocation_epoch: u64,
        issued_at_epoch_s: u64,
        expires_at_epoch_s: u64,
        nonce: impl Into<String>,
        key_id: impl Into<String>,
    ) -> Self {
        Self {
            issuer: issuer.into(),
            audience,
            service_id,
            pairwise_subject: pairwise_subject.into(),
            device_id,
            device_proof_key_ref: device_proof_key_ref.into(),
            session_ref: session_ref.into(),
            posture_state: posture_state.into(),
            posture_revision,
            subject_revocation_epoch,
            service_revocation_epoch,
            device_revocation_epoch,
            session_revocation_epoch,
            issued_at_epoch_s,
            expires_at_epoch_s,
            nonce: nonce.into(),
            key_id: key_id.into(),
        }
    }
}

pub trait IdentityAssertionVerifier: AssertionVerifier {
    fn expected_issuer(&self) -> &str;

    fn revocation_epochs_are_current(&self, binding: &DeviceIdentityBinding) -> bool;
}

pub trait ServiceAccountOwnerMapper {
    fn map_owner(
        &self,
        issuer: &str,
        service_id: &ServiceId,
        pairwise_subject: &str,
    ) -> Result<OpaqueOwnerRef, AuthorityError>;
}

pub fn verify_device_identity_assertion<V: IdentityAssertionVerifier>(
    assertion_wire: &[u8],
    expected_audience: &GrantAudience,
    verifier: &V,
    now_epoch_s: u64,
) -> Result<DeviceIdentityBinding, AuthorityError> {
    let assertion = decode_assertion_strict(assertion_wire)
        .map_err(|_| AuthorityError::IdentityAssertionInvalid)?;
    verify_assertion_at(
        &assertion,
        verifier,
        verifier.expected_issuer(),
        expected_audience.as_str(),
        now_epoch_s,
    )
    .map_err(|_| AuthorityError::IdentityAssertionInvalid)?;
    let epochs = assertion.revocation_epochs;
    let binding = DeviceIdentityBinding::from_verified_assertion(
        assertion.issuer,
        GrantAudience::parse(assertion.audience)?,
        ServiceId::parse(assertion.service_id)?,
        assertion.pairwise_subject,
        DeviceId::parse(assertion.device_id)?,
        assertion.device_proof_key_ref,
        assertion.session_ref,
        assertion.device_posture.state,
        assertion.device_posture.revision,
        epochs.subject,
        epochs.service,
        epochs.device,
        epochs.session,
        assertion.issued_at_epoch_s,
        assertion.expires_at_epoch_s,
        assertion.nonce,
        assertion.key_id,
    );
    if !verifier.revocation_epochs_are_current(&binding) {
        return Err(AuthorityError::StaleRevocationEpoch);
    }
    Ok(binding)
}
