#[test]
fn host_config_v4_requires_reservation_root_provider_state_and_distinct_roles() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let schema: serde_json::Value = serde_json::from_slice(
        &fs::read(root.join("schemas/host-config-v4.schema.json")).expect("host schema"),
    )
    .expect("valid host schema JSON");
    assert_eq!(
        schema["$id"],
        "crowsi://credential-authority/host-config/v4"
    );
    let required = schema["required"].as_array().expect("required fields");
    for field in [
        "authority_store_directory",
        "authority_anchor_directory",
        "operation_state_directory",
        "management_state_directory",
        "management_anchor_directory",
        "revocation_execution_reservation_signing_key_path",
        "revocation_execution_reservation_key_id",
        "revocation_execution_reservation_public_key_hex",
        "revocation_execution_reservation_config_generation",
    ] {
        assert!(required.iter().any(|item| item == field), "missing {field}");
    }
    let provider = &schema["$defs"]["provider"];
    assert!(
        provider["required"]
            .as_array()
            .expect("provider required")
            .iter()
            .any(|item| item == "state_directory")
    );
    let config = fs::read_to_string(root.join("src/host_config.rs")).expect("host config");
    let validation =
        fs::read_to_string(root.join("src/host_config_validation.rs")).expect("validation");
    assert!(config.contains("CROWSI-CREDENTIAL-AUTHORITY-HOST-CONFIG-V4"));
    assert!(!config.contains("HOST-CONFIG-V1"));
    assert!(!config.contains("HOST-CONFIG-V2"));
    assert!(validation.contains("host-config/v4"));
    assert!(!validation.contains("host-config/v1"));
    assert!(!validation.contains("host-config/v2"));
}
