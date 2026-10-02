#[path = "gateway_host_subprocess/authority.rs"]
mod authority;
#[path = "gateway_host_subprocess/config.rs"]
mod config;
#[path = "gateway_host_subprocess/config_files.rs"]
mod config_files;
#[path = "gateway_host_subprocess/config_gateway.rs"]
mod config_gateway;
#[path = "gateway_host_subprocess/config_host.rs"]
mod config_host;
#[path = "gateway_host_subprocess/fixture.rs"]
mod fixture;
#[path = "gateway_host_subprocess/identity.rs"]
mod identity;
#[path = "gateway_host_subprocess/process.rs"]
mod process;
#[path = "gateway_host_subprocess/process_run.rs"]
mod process_run;

use crowsi_credential_authority_contracts::{
    ManagementProjectionBodyV2, decode_management_projection_strict,
};
use ed25519_dalek::Verifier as _;

// ID-53: a real finite host child, not the gateway, opens the authority store and signs output.
#[test]
fn gateway_request_crosses_the_real_finite_host_process() {
    let fixture = fixture::Fixture::new();
    authority::provision(&fixture);
    let documents = config::write(&fixture);
    let output = process::snapshot(&fixture, &documents);
    let projection = decode_management_projection_strict(&output).expect("signed projection");
    assert_eq!(projection.current_device_ref, identity::DEVICE_A);
    assert!(matches!(
        projection.body,
        ManagementProjectionBodyV2::Snapshot { .. }
    ));
}

#[test]
fn finite_host_signs_the_current_authority_peer_head() {
    let fixture = fixture::Fixture::new();
    authority::provision(&fixture);
    let documents = config::write(&fixture);
    let (request, output) = process::peer_head(&fixture, &documents);
    let value: serde_json::Value = serde_json::from_slice(&output).expect("head response");
    assert_eq!(value["request_id"], request["request_id"]);
    assert_eq!(value["authority_epoch"], 1);
    assert_eq!(value["entries"].as_array().expect("entries").len(), 2);
    let canonical = canonical_head(&value);
    let signature = hex::decode(value["signature"].as_str().expect("signature")).expect("hex");
    fixture::key(6)
        .verifying_key()
        .verify(
            &canonical,
            &ed25519_dalek::Signature::try_from(signature.as_slice()).expect("signature bytes"),
        )
        .expect("signed head");
}

fn canonical_head(value: &serde_json::Value) -> Vec<u8> {
    let mut unsigned = value.clone();
    unsigned
        .as_object_mut()
        .expect("object")
        .remove("signature");
    let body = serde_json::to_vec(&unsigned).expect("body");
    [
        b"CROWSI-CREDENTIAL-AUTHORITY-PEER-STATUS-HEAD-V1\n".as_slice(),
        body.len().to_string().as_bytes(),
        b"\n",
        &body,
    ]
    .concat()
}
