use super::*;

pub const NOW_MS: u64 = 1_800_000_000_000;
pub const FRESH_STEP_UP_MS: u64 = 120_000;
pub const GRANT_TTL_MS: u64 = 60_000;
pub fn authority() -> TestAuthority {
    TestAuthority::at(NOW_MS)
}

pub fn owner_a() -> OpaqueOwnerRef {
    OpaqueOwnerRef::parse("psa_service-a_01JOWNER000000000000000001")
        .expect("opaque pairwise service-account reference")
}

pub fn owner_b() -> OpaqueOwnerRef {
    OpaqueOwnerRef::parse("psa_service-a_01JOWNER000000000000000002")
        .expect("different opaque pairwise service-account reference")
}

pub fn source_device() -> DeviceId {
    DeviceId::parse("dev_01JSOURCE000000000000000001").expect("source device id")
}

pub fn target_device() -> DeviceId {
    DeviceId::parse("dev_01JTARGET000000000000000001").expect("target device id")
}

pub fn unrelated_device() -> DeviceId {
    DeviceId::parse("dev_01JOTHER0000000000000000001").expect("unrelated device id")
}

pub fn credential_id() -> CredentialId {
    CredentialId::parse("cred_01JCREDENTIAL00000000000001").expect("credential id")
}

pub fn service() -> ServiceId {
    ServiceId::parse("github-api").expect("service id")
}

pub fn provider_account() -> ProviderAccountRef {
    ProviderAccountRef::parse("github-installation:opaque-01").expect("provider account ref")
}

pub fn audience() -> GrantAudience {
    GrantAudience::parse("crowsi://github/sign").expect("closed audience")
}

pub fn action() -> GrantAction {
    GrantAction::parse("sign-github-request").expect("closed action")
}
