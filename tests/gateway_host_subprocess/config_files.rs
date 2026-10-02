use serde_json::json;
use std::{fs, os::unix::fs::PermissionsExt, path::PathBuf};

use crate::fixture::{Fixture, digest, key, public};

pub(crate) struct Files {
    pub(crate) executable: PathBuf,
    pub(crate) executable_digest: String,
    pub(crate) provider_executable: PathBuf,
    pub(crate) provider_executable_digest: String,
    pub(crate) response_key: PathBuf,
    pub(crate) projection_key: PathBuf,
    pub(crate) reservation_key: PathBuf,
    pub(crate) provider_config: PathBuf,
    pub(crate) provider_config_digest: String,
    pub(crate) gateway_response_key: PathBuf,
    pub(crate) server_private_key: PathBuf,
}

pub(crate) fn write(fixture: &Fixture) -> Files {
    fixture.write(
        "root-trust.json",
        &serde_json::to_vec(&json!({
            "schema":"crowsi://credential-authority/host-root-trust/v1",
            "configuration_key_id":"root-config-key",
            "configuration_public_key_hex":public(1)
        }))
        .expect("root trust"),
    );
    let response_key = signing_key(
        fixture,
        "host-response.json",
        6,
        "host-response-key",
        "crowsi://credential-authority/host-response-key/v1",
    );
    let projection_key = signing_key(
        fixture,
        "projection.json",
        7,
        "projection-key",
        "crowsi://credential-authority/management-projection-key/v2",
    );
    let reservation_key = signing_key(
        fixture,
        "reservation.json",
        14,
        "reservation-key",
        "crowsi://credential-authority/revocation-execution-reservation-key/v1",
    );
    let gateway_response_key = signing_key(
        fixture,
        "gateway-response.json",
        11,
        "gateway-response-key",
        "crowsi://credential-authority/gateway-response-key/v1",
    );
    let provider = b"{\"schema\":\"provider-fixture/v1\"}";
    let provider_config = fixture.write("provider.json", provider);
    let server_private_key = fixture.write("gateway-server-key.der", b"fixture-key");
    let source = PathBuf::from(env!("CARGO_BIN_EXE_crowsi-credential-authority-host"));
    let executable = fixture.path("crowsi-credential-authority-host");
    fs::copy(&source, &executable).expect("materialize finite host");
    fs::set_permissions(&executable, fs::Permissions::from_mode(0o500)).expect("host mode");
    let executable_digest = digest(&fs::read(&executable).expect("host binary"));
    let provider_executable = fixture.path("provider-executable");
    fs::copy(source, &provider_executable).expect("materialize provider executable");
    fs::set_permissions(&provider_executable, fs::Permissions::from_mode(0o500))
        .expect("provider mode");
    let provider_executable_digest =
        digest(&fs::read(&provider_executable).expect("provider binary"));
    Files {
        executable,
        executable_digest,
        provider_executable,
        provider_executable_digest,
        response_key,
        projection_key,
        reservation_key,
        provider_config,
        provider_config_digest: digest(provider),
        gateway_response_key,
        server_private_key,
    }
}

fn signing_key(fixture: &Fixture, name: &str, byte: u8, key_id: &str, schema: &str) -> PathBuf {
    fixture.write(
        name,
        &serde_json::to_vec(&json!({
            "schema":schema,"key_id":key_id,
            "private_key_hex":hex::encode(key(byte).to_bytes())
        }))
        .expect("signing key"),
    )
}
