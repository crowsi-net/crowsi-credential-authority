use super::*;

pub struct TestIdentityVerifier;
pub struct TestOwnerMapper;
pub struct TestProviderVerifier;

impl AssertionVerifier for TestIdentityVerifier {
    fn verify(&self, key_id: &str, payload: &[u8], signature: &str) -> bool {
        key_id == "ihat-key-01" && !payload.is_empty() && signature == "opaque-signature"
    }
}

impl IdentityAssertionVerifier for TestIdentityVerifier {
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

impl ServiceAccountOwnerMapper for TestOwnerMapper {
    fn map_owner(
        &self,
        _issuer: &str,
        _service_id: &ServiceId,
        subject: &str,
    ) -> Result<OpaqueOwnerRef, AuthorityError> {
        if subject == "psu_service-a_01JSUBJECT000000000000001" {
            Ok(owner_a())
        } else {
            Err(AuthorityError::WrongOwner)
        }
    }
}

impl ProviderEvidenceVerifier for TestProviderVerifier {
    fn verify(&self, kind: ProviderEvidenceKind, payload: &[u8], signature: &str) -> bool {
        let expected = match kind {
            ProviderEvidenceKind::ReissueReceipt => "valid-provider-reissue-signature",
            ProviderEvidenceKind::UnknownOutcome => "provider-signature-over-unknown-outcome",
            ProviderEvidenceKind::Reconciliation => "valid-provider-signature",
        };
        !payload.is_empty() && signature == expected
    }
}
