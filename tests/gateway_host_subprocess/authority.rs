use crowsi_credential_authority::{
    AssertionVerifier, AuthorityError, DeviceIdentityBinding, GrantAudience, OpaqueOwnerRef,
    ServiceId,
    test_support::{
        CredentialAuthority, IdentityAssertionVerifier, ServiceAccountOwnerMapper,
        initialize_file_authority_store,
    },
};
use ed25519_dalek::{Signature, Verifier as _};

use crate::{
    fixture::{Fixture, key},
    identity::{
        DEVICE_A, DEVICE_B, ISSUER, OWNER, PAIRWISE, REGISTRATION_AUDIENCE, SERVICE, assertion,
    },
};

pub(crate) fn provision(fixture: &Fixture) {
    let store = initialize_file_authority_store(
        &fixture.store,
        &fixture.authority_anchor,
        (fixture.now - 1) * 1_000,
    )
    .expect("store");
    let mut authority = CredentialAuthority::with_store(store, fixture.now * 1_000);
    let audience = GrantAudience::parse(REGISTRATION_AUDIENCE).expect("audience");
    for device in [DEVICE_A, DEVICE_B] {
        let wire = serde_json::to_vec(&assertion(fixture, device, REGISTRATION_AUDIENCE))
            .expect("assertion");
        authority
            .register_device_from_assertion(&wire, &audience, &IdentityVerifier, &OwnerMapper)
            .expect("register device");
    }
}

struct IdentityVerifier;

impl AssertionVerifier for IdentityVerifier {
    fn verify(&self, key_id: &str, payload: &[u8], signature: &str) -> bool {
        let Ok(bytes) = hex::decode(signature) else {
            return false;
        };
        let Ok(signature) = Signature::try_from(bytes.as_slice()) else {
            return false;
        };
        key_id == "identity-key" && key(2).verifying_key().verify(payload, &signature).is_ok()
    }
}

impl IdentityAssertionVerifier for IdentityVerifier {
    fn expected_issuer(&self) -> &'static str {
        ISSUER
    }

    fn revocation_epochs_are_current(&self, _: &DeviceIdentityBinding) -> bool {
        true
    }
}

struct OwnerMapper;

impl ServiceAccountOwnerMapper for OwnerMapper {
    fn map_owner(
        &self,
        issuer: &str,
        service: &ServiceId,
        subject: &str,
    ) -> Result<OpaqueOwnerRef, AuthorityError> {
        if issuer == ISSUER && service.as_str() == SERVICE && subject == PAIRWISE {
            OpaqueOwnerRef::parse(OWNER)
        } else {
            Err(AuthorityError::WrongOwner)
        }
    }
}
