use super::*;

pub(super) struct FixedIdentityVerifier;
pub(super) struct StaleEpochVerifier;
pub(super) struct FixedOwnerMapper;

impl AssertionVerifier for FixedIdentityVerifier {
    fn verify(&self, key_id: &str, canonical_payload: &[u8], signature: &str) -> bool {
        key_id == "ihat-key-01" && !canonical_payload.is_empty() && signature == "opaque-signature"
    }
}

impl IdentityAssertionVerifier for FixedIdentityVerifier {
    fn expected_issuer(&self) -> &'static str {
        "ihat://identity-authority"
    }

    fn revocation_epochs_are_current(
        &self,
        _binding: &crowsi_credential_authority::DeviceIdentityBinding,
    ) -> bool {
        true
    }
}

impl AssertionVerifier for StaleEpochVerifier {
    fn verify(&self, key_id: &str, canonical_payload: &[u8], signature: &str) -> bool {
        FixedIdentityVerifier.verify(key_id, canonical_payload, signature)
    }
}

impl IdentityAssertionVerifier for StaleEpochVerifier {
    fn expected_issuer(&self) -> &'static str {
        "ihat://identity-authority"
    }

    fn revocation_epochs_are_current(
        &self,
        _binding: &crowsi_credential_authority::DeviceIdentityBinding,
    ) -> bool {
        false
    }
}

impl ServiceAccountOwnerMapper for FixedOwnerMapper {
    fn map_owner(
        &self,
        _issuer: &str,
        _service_id: &crowsi_credential_authority::ServiceId,
        pairwise_subject: &str,
    ) -> Result<OpaqueOwnerRef, AuthorityError> {
        if pairwise_subject == "psu_service-a_01JSUBJECT000000000000001" {
            Ok(owner_a())
        } else {
            Err(AuthorityError::WrongOwner)
        }
    }
}

pub(super) fn signed_identity_assertion(
    device: &crowsi_credential_authority::DeviceId,
    assertion_audience: &GrantAudience,
    nonce: &str,
) -> Vec<u8> {
    let document = serde_json::json!({
        "schema": DEVICE_IDENTITY_ASSERTION_SCHEMA,
        "issuer": "ihat://identity-authority",
        "audience": assertion_audience.as_str(),
        "service_id": "github-api",
        "pairwise_subject": "psu_service-a_01JSUBJECT000000000000001",
        "device_id": device.as_str(),
        "device_proof_key_ref": format!("key-thumbprint:{device}"),
        "session_ref": format!("sref_{}", "b".repeat(64)),
        "device_posture": { "state": "compliant", "revision": 11 },
        "revocation_epochs": { "subject": 5, "service": 3, "device": 7, "session": 9 },
        "issued_at_epoch_s": NOW_MS / 1_000 - 1,
        "expires_at_epoch_s": NOW_MS / 1_000 + 120,
        "nonce": nonce,
        "key_id": "ihat-key-01",
        "signature": "opaque-signature"
    });
    serde_json::to_vec(&document).expect("closed assertion JSON")
}
